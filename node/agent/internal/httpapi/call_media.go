package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/internal/voicemedia"
	"github.com/human-agent65535/nassimhub-node/proto"
)

// getCallMedia speaks the same MDM2 PCM boundary as the NAS host media
// endpoint. It remains unavailable until a validated hardware opener is
// explicitly wired into the Agent.
func (h *handler) getCallMedia(w http.ResponseWriter, r *http.Request) {
	const operation = "open_call_media"
	if r.TLS == nil {
		h.writeAPIError(w, proto.ErrorFailedPrecondition, operation, "", "call media requires TLS")
		return
	}
	if h.callMedia == nil {
		h.writeAPIError(w, proto.ErrorNotSupported, operation, "", "call media is not configured")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	calls, err := h.modem.ListCalls(r.Context())
	if err != nil {
		h.writeError(w, err)
		return
	}
	active := false
	for _, call := range calls {
		if call.ID == id && call.State == proto.CallActive {
			active = true
			break
		}
	}
	if !active {
		h.writeAPIError(w, proto.ErrorFailedPrecondition, operation, "", "call is not active")
		return
	}
	if r.ProtoMajor != 1 ||
		!strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "modemdeck-media-v2") ||
		!headerHasToken(r.Header.Get("Connection"), "upgrade") {
		h.writeAPIError(w, proto.ErrorInvalidArgument, operation, "", "MDM2 upgrade is required")
		return
	}
	h.mediaMu.Lock()
	if h.mediaActive {
		h.mediaMu.Unlock()
		h.writeAPIError(w, proto.ErrorConflict, operation, "", "call media is already in use")
		return
	}
	h.mediaActive = true
	h.mediaMu.Unlock()
	defer func() {
		h.mediaMu.Lock()
		h.mediaActive = false
		h.mediaMu.Unlock()
	}()

	connection, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		h.writeAPIError(w, proto.ErrorNotSupported, operation, "", "HTTP upgrade is unavailable")
		return
	}
	defer connection.Close()
	_, err = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: modemdeck-media-v2\r\n" +
		"ModemDeck-Media-Version: 2\r\n" +
		"ModemDeck-Media-Encoding: pcm\r\n" +
		"ModemDeck-Media-Resolution: s16le\r\n" +
		"ModemDeck-Media-Rate: 16000\r\n" +
		"ModemDeck-Media-Channels: 1\r\n" +
		"ModemDeck-Media-Frame-Duration-Ms: 20\r\n" +
		"ModemDeck-Media-Frame-Bytes: 640\r\n\r\n")
	if err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	h.logs.Infof("voice_media", "authenticated media stream opened for %s", id)
	mediaContext, stopMedia := context.WithCancel(r.Context())
	defer stopMedia()
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		keepCallMediaActive(mediaContext, id, time.Second, h.modem.ListCalls, func() {
			stopMedia()
			_ = connection.Close()
		})
	}()
	if err := voicemedia.Serve(mediaContext, connection, buffered.Reader, id, h.callMedia); err != nil {
		h.logs.Warnf("voice_media", "media stream ended for %s: %v", id, err)
	} else {
		h.logs.Infof("voice_media", "media stream closed for %s", id)
	}
	stopMedia()
	<-watchDone
	// Experimental hardware media owns the call until its connection closes.
	// Cleanup must survive a cancelled request or unplugged USB link.
	cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, _ = h.modem.Hangup(cleanup, id)
}

func headerHasToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

package nodeserver

import (
	"github.com/human-agent65535/nassimhub-node/agent/internal/transportkey"
	"github.com/human-agent65535/nassimhub-node/proto"
	"github.com/human-agent65535/nassimhub-node/xport/kcp"
)

// The adapter between the key store and the protocol.
//
// It exists so the store knows nothing about HTTP and the handler knows nothing
// about files. The conversion is the only place a secret becomes a wire value,
// which is a useful property when the question "where can this secret possibly
// go" has to be answered - the answer is: here, and then into one TLS response.

type transportKeyIssuer struct {
	store *transportkey.Store
}

func (i transportKeyIssuer) response(secret kcp.TransportSecret) proto.TransportKeyResponse {
	encoded := secret.Encode()
	return proto.TransportKeyResponse{
		KeyID:    encoded.KeyID,
		Epoch:    encoded.Epoch,
		Secret:   encoded.Secret,
		IssuedAt: encoded.IssuedAt,
		// The grace window is reported rather than assumed by the Core. A Core
		// that guessed would either rotate too eagerly - dropping packets in
		// flight - or hold an old key longer than the Node accepts it, which
		// looks like an authentication failure with no cause.
		GraceSeconds: int(kcp.DefaultGrace.Seconds()),
	}
}

func (i transportKeyIssuer) Current() (proto.TransportKeyResponse, error) {
	secret, err := i.store.Current()
	if err != nil {
		return proto.TransportKeyResponse{}, err
	}
	return i.response(secret), nil
}

func (i transportKeyIssuer) Rotate() (proto.TransportKeyResponse, error) {
	secret, err := i.store.Rotate()
	if err != nil {
		return proto.TransportKeyResponse{}, err
	}
	return i.response(secret), nil
}

func (i transportKeyIssuer) Destroy() error { return i.store.Destroy() }

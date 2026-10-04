package provisioning

import (
	_ "embed"
	"net/http"
)

// The setup page.
//
// It is one file, embedded in the binary, with no build step, no package
// manager, no framework and no external request of any kind. That is not
// minimalism for its own sake - it follows from where this page runs.
//
// The device serving it is an access point with no internet connection: the
// whole reason the user is looking at this page is that the device does not yet
// know how to reach the network. A page that loaded a font, a stylesheet or a
// script from anywhere would hang on that request and present a blank screen at
// the exact moment the user most needs it to work. So everything the page needs
// is inside it, and the only requests it makes are to the three endpoints on
// this same device.
//
// The second constraint is the hardware. The agent's whole job is to be small
// on a device with 256 MB of RAM and a filesystem that has been full before;
// shipping a front-end toolchain's output next to it would be a poor trade for
// a page with three controls.
//
// The page is served only where the rest of the provisioning API is served -
// behind the same guard, on the same listener, which closes as soon as the
// device joins a network. It exposes nothing the API does not: scan, connect,
// and the state machine's current state.
//
//go:embed ui.html
var setupPage []byte

// serveUI returns the setup page.
//
// It is registered behind the same guard as everything else here, so a request
// from outside the access point's subnet gets the same 403 that an API call
// would, and a request after the device has joined a network gets the same 404.
// A user who reaches this page has therefore already been established to be
// standing next to the device.
func (h *Handler) serveUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// No caching. A page cached from a previous provisioning session would
	// show a stale state, and the device is about to stop serving it anyway.
	w.Header().Set("Cache-Control", "no-store")
	// The page loads nothing from anywhere, and this says so in a form a
	// browser enforces: if a future edit adds an external script or font, it
	// will not load, and the failure will be immediate and visible rather than
	// appearing only on a device with no internet.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(setupPage)
}

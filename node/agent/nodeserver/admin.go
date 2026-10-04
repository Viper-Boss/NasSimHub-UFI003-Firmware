package nodeserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/human-agent65535/nassimhub-node/agent/nodetls"
)

// AdminHandler is the independent browser console. It never serves the Core
// protocol, whose original identity, certificate and listener remain separate.
func (s *Server) AdminHandler() http.Handler { return s.adminHandler }
func (s *Server) AdminAddress() string       { return s.adminAddress }
func (s *Server) startAdmin() error {
	if s.adminHandler == nil {
		return nil
	}
	config, err := nodetls.SecureServerConfig(*s.adminCertificate, s.options.PQProfile, s.options.PQPolicy)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", s.options.AdminListen)
	if err != nil {
		return fmt.Errorf("listen for administration: %w", err)
	}
	s.adminAddress = listener.Addr().String()
	server := &http.Server{Handler: s.adminHandler, TLSConfig: config, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	s.servers = append(s.servers, server)
	go func() {
		if err := server.Serve(tls.NewListener(listener, config)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.Logs.Errorf("admin", "management listener stopped: %v", err)
		}
	}()
	s.Logs.Infof("admin", "local management ready on %s", s.adminAddress)
	return nil
}

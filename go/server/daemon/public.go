// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/publictls"
)

// The plain HTTP listener of public HTTPS answers ACME challenges and
// redirects; it needs none of the API's allowances.
const (
	redirectReadHeaderTimeout = 5 * time.Second
	redirectIdleTimeout       = 30 * time.Second
)

// servePublic opens public HTTPS's listeners and serves them: the HTTPS
// listener (listen_https) serves the same handler as the plain listener,
// with the certificate public manages, and nothing before it has one; the
// plain HTTP listener (listen_http_redirect), when on, answers ACME
// HTTP-01 challenges and redirects everything else to the public URL. A
// listener that stops reports on served, as the plain listener's does.
func servePublic(cfg *config.Config, public *publictls.Manager, handler http.Handler, log *slog.Logger, served chan<- error, h *hooks) ([]*http.Server, error) {
	p := cfg.PublicHTTPS
	tlsLn, err := net.Listen("tcp", p.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen_https %s: %w", p.Listen, err)
	}
	var plainLn net.Listener
	if p.RedirectListen != "" {
		if plainLn, err = net.Listen("tcp", p.RedirectListen); err != nil {
			_ = tlsLn.Close()
			return nil, fmt.Errorf("listen_http_redirect %s: %w", p.RedirectListen, err)
		}
	}
	// A refused handshake (no certificate yet, another name, a scanner) is
	// routine on a public port: debug, not a warning.
	quiet := slog.NewLogLogger(log.Handler(), slog.LevelDebug)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	httpsSrv := &http.Server{
		Handler:           handler,
		TLSConfig:         public.TLSConfig(),
		Protocols:         protocols,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          quiet,
		ConnContext:       httpserver.ConnContext,
		// A TLS-ALPN-01 handshake serves no request.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){publictls.ACMETLS1: publictls.ChallengeOnly},
	}
	servers := []*http.Server{httpsSrv}
	go func() {
		if err := httpsSrv.ServeTLS(tlsLn, "", ""); !errors.Is(err, http.ErrServerClosed) {
			served <- fmt.Errorf("listen_https: %w", err)
		}
	}()
	var plainAddr net.Addr
	if plainLn != nil {
		plainSrv := &http.Server{
			Handler:           public.RedirectHandler(cfg.PublicURL),
			ReadHeaderTimeout: redirectReadHeaderTimeout,
			ReadTimeout:       redirectReadHeaderTimeout,
			IdleTimeout:       redirectIdleTimeout,
			MaxHeaderBytes:    16 << 10,
			ErrorLog:          quiet,
		}
		servers = append(servers, plainSrv)
		plainAddr = plainLn.Addr()
		go func() {
			if err := plainSrv.Serve(plainLn); !errors.Is(err, http.ErrServerClosed) {
				served <- fmt.Errorf("listen_http_redirect: %w", err)
			}
		}()
	}
	log.Info("public HTTPS is listening", "host", p.Host, "https", tlsLn.Addr().String(), "http", addrString(plainAddr), "ca", p.CA)
	if h.publicReady != nil {
		h.publicReady(tlsLn.Addr(), plainAddr)
	}
	return servers, nil
}

func addrString(a net.Addr) string {
	if a == nil {
		return "off"
	}
	return a.String()
}

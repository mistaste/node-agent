// Package controlhttp contains the small outbound controller transport. It is
// never used by the VPN data plane or by public relay forwarding.
package controlhttp

import (
	"crypto/tls"
	"net/http"
	"time"
)

func NewClient(timeout, headerTimeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	// Some provider paths black-hole reused H2 control connections. Keep ALPN
	// consistent with the H1 transport, retaining verified TLS and keep-alives.
	transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	transport.ResponseHeaderTimeout = headerTimeout
	transport.IdleConnTimeout = 45 * time.Second
	return &http.Client{Timeout: timeout, Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

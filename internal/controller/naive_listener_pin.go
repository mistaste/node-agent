package controller

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"time"
)

// Naive's public listener uses Caddy-managed TLS, not the decoy certificate.
// Read only the verified leaf certificate from the loopback listener after
// apply. Never accept an untrusted chain, wrong hostname, or expired leaf.
func naiveListenerPin(ctx context.Context, hostname string, port int) (string, error) {
	return verifiedNaiveListenerPin(ctx, hostname, port, nil)
}

func verifiedNaiveListenerPin(ctx context.Context, hostname string, port int, roots *x509.CertPool) (string, error) {
	if hostname == "" || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid Naive TLS listener")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	dialer := tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{
		ServerName: hostname, RootCAs: roots, MinVersion: tls.VersionTLS12,
	}}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer connection.Close()
	state := connection.(*tls.Conn).ConnectionState()
	if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("Naive TLS certificate is not verified")
	}
	digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(digest[:]), nil
}

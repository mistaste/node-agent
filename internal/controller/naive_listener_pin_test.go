package controller

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestNaiveListenerPinVerifiesActualCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	_, textPort, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(textPort)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	pin, err := verifiedNaiveListenerPin(context.Background(), "example.com", port, roots)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	if pin != base64.StdEncoding.EncodeToString(digest[:]) {
		t.Fatal("wrong leaf SPKI")
	}
	if pin, err := verifiedNaiveListenerPin(context.Background(), "wrong.example", port, roots); err == nil || pin != "" {
		t.Fatal("wrong hostname accepted")
	}
	if pin, err := verifiedNaiveListenerPin(context.Background(), "example.com", port, x509.NewCertPool()); err == nil || pin != "" {
		t.Fatal("untrusted certificate accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifiedNaiveListenerPin(ctx, "example.com", port, roots); err == nil {
		t.Fatal("cancelled probe succeeded")
	}
	if _, err := naiveListenerPin(context.Background(), "example.com", 0); err == nil {
		t.Fatal("invalid listener accepted")
	}
}

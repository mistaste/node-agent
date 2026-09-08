package api

import (
	"github.com/guardex/node-agent/internal/config"
	"testing"
)

func TestManagementListenerRefusesPlaintextExposure(t *testing.T) {
	for _, address := range []string{"0.0.0.0:0", "[::]:0", "192.0.2.1:8099", "10.0.0.1:8099"} {
		server := NewMetricsOnlyServer(&config.Config{ListenAddr: address}, nil)
		if err := server.Run(); err == nil || err.Error() != "management listener requires TLS outside loopback" {
			t.Fatalf("address %s: %v", address, err)
		}
	}
	server := NewMetricsOnlyServer(&config.Config{ListenAddr: "127.0.0.1:0", TLSCertFile: "missing-cert"}, nil)
	if err := server.Run(); err == nil || err.Error() != "both management TLS certificate and key are required" {
		t.Fatalf("partial TLS configuration: %v", err)
	}
}

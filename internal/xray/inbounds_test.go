package xray

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestInjectRealityKeyFillsOnlyKeylessReality(t *testing.T) {
	raw := []byte(`{"tag":"dynamic","port":443,"protocol":"vless","settings":{"decryption":"none"},"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"dest":"www.example.com:443","serverNames":["www.example.com"],"privateKey":"","shortIds":[]}}}`)
	patched, publicKey, shortID, err := InjectRealityKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if publicKey == "" || shortID == "" {
		t.Fatalf("public material missing: public=%q shortID=%q", publicKey, shortID)
	}
	if strings.Contains(string(patched), publicKey) {
		t.Fatal("server config should contain the private key, not public key")
	}
	var root map[string]any
	if err := json.Unmarshal(patched, &root); err != nil {
		t.Fatal(err)
	}
	reality := root["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	if reality["privateKey"] == "" {
		t.Fatal("private key was not injected")
	}
	shortIDs := reality["shortIds"].([]any)
	if len(shortIDs) != 1 || shortIDs[0] != shortID {
		t.Fatalf("shortIds = %#v, want %q", shortIDs, shortID)
	}
}

func TestLinkedCoreBuildsAdvertisedRealityTransports(t *testing.T) {
	for _, network := range []string{"tcp", "raw", "xhttp", "grpc"} {
		t.Run(network, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{
				"tag":"build-%s","port":%d,"protocol":"vless",
				"settings":{"clients":[],"decryption":"none"},
				"streamSettings":{"network":%q,"security":"reality","realitySettings":{
					"dest":"www.example.com:443","serverNames":["www.example.com"],
					"privateKey":"","shortIds":[]
				}}
			}`, network, 443, network))
			prepared, _, _, err := EnsureRealityKey(raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateInboundForCore(prepared); err != nil {
				t.Fatalf("linked xray-core cannot build advertised %s+reality: %v", network, err)
			}
		})
	}
}

func TestLinkedCoreBuildsAdvertisedTLSTransports(t *testing.T) {
	for index, network := range []string{"tcp", "raw", "xhttp", "grpc", "websocket", "ws", "httpupgrade"} {
		t.Run(network, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{
				"tag":"tls-%s","port":%d,"protocol":"vless",
				"settings":{"clients":[],"decryption":"none"},
				"streamSettings":{"network":%q,"security":"tls","tlsSettings":{}}
			}`, network, 11443+index, network))
			if err := ValidateInboundForCore(raw); err != nil {
				t.Fatalf("linked xray-core cannot build advertised %s+tls: %v", network, err)
			}
		})
	}
}

func TestInjectRealityKeyDoesNotReplaceExistingKey(t *testing.T) {
	privateKey, expectedPublic, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"privateKey":"` + privateKey + `","shortIds":["0123456789abcdef"]}}}`)
	patched, publicKey, shortID, err := InjectRealityKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if publicKey != expectedPublic || shortID != "0123456789abcdef" || !strings.Contains(string(patched), privateKey) {
		t.Fatalf("existing key changed: public=%q short=%q config=%s", publicKey, shortID, patched)
	}
}

func TestEnsureRealityKeyReusesManagedCredentials(t *testing.T) {
	template := []byte(`{"tag":"same","streamSettings":{"network":"tcp","security":"reality","realitySettings":{"privateKey":"","shortIds":[]}}}`)
	first, firstPublic, firstShort, err := EnsureRealityKey(template, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, secondPublic, secondShort, err := EnsureRealityKey(template, first)
	if err != nil {
		t.Fatal(err)
	}
	if firstPublic != secondPublic || firstShort != secondShort || string(first) != string(second) {
		t.Fatalf("credentials rotated on retry: first=%q/%q second=%q/%q", firstPublic, firstShort, secondPublic, secondShort)
	}
}

func TestControlPlaneVersionIsDiscoverable(t *testing.T) {
	if version := ControlPlaneVersion(); version == "" || version == "unknown" {
		t.Fatalf("ControlPlaneVersion=%q", version)
	}
}

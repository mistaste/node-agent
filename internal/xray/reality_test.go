package xray

import (
	"encoding/base64"
	"testing"
)

func TestGenerateRealityKeypair(t *testing.T) {
	priv, pub, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	for name, k := range map[string]string{"priv": priv, "pub": pub} {
		raw, err := base64.RawURLEncoding.DecodeString(k)
		if err != nil {
			t.Fatalf("%s not raw-url base64: %v", name, err)
		}
		if len(raw) != 32 {
			t.Fatalf("%s len = %d, want 32", name, len(raw))
		}
	}
	if priv == pub {
		t.Fatal("priv == pub")
	}
}

func TestGenerateShortID(t *testing.T) {
	id, err := GenerateShortID()
	if err != nil {
		t.Fatalf("shortid: %v", err)
	}
	if len(id) != 16 {
		t.Fatalf("shortid len = %d, want 16 hex chars", len(id))
	}
}

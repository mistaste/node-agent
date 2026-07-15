package xray

import (
	"errors"
	"testing"
)

func TestInboundErrorCompatibility(t *testing.T) {
	for _, message := range []string{
		"rpc error: code = Unknown desc = already exists",
		"existing tag found: vless-adaptive-xhttp",
	} {
		if !IsInboundAlreadyExists(errors.New(message)) {
			t.Fatalf("IsInboundAlreadyExists(%q) = false", message)
		}
	}
	if IsInboundAlreadyExists(errors.New("permission denied")) {
		t.Fatal("permission error classified as existing inbound")
	}

	if !IsNotFound(errors.New("not enough information for making a decision")) {
		t.Fatal("current Xray absent-handler wording was not classified as not found")
	}
}

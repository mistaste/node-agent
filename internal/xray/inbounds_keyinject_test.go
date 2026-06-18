package xray

import (
	"encoding/json"
	"testing"
)

func TestInjectRealityKey_FillsEmptyPrivateKey(t *testing.T) {
	in := []byte(`{"tag":"t","port":8443,"protocol":"vless",
		"streamSettings":{"network":"xhttp","security":"reality",
			"realitySettings":{"dest":"www.cloudflare.com:443","serverNames":["www.cloudflare.com"],"privateKey":"","shortIds":[]}}}`)
	out, pub, sid, err := InjectRealityKey(in)
	if err != nil {
		t.Fatal(err)
	}
	if pub == "" || sid == "" {
		t.Fatalf("expected pub+sid, got pub=%q sid=%q", pub, sid)
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	rs := m["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	if rs["privateKey"] == "" {
		t.Fatal("privateKey not injected")
	}
}

func TestInjectRealityKey_LeavesNonRealityAlone(t *testing.T) {
	in := []byte(`{"tag":"t","port":8388,"protocol":"shadowsocks","settings":{}}`)
	out, pub, sid, err := InjectRealityKey(in)
	if err != nil || pub != "" || sid != "" || string(out) != string(in) {
		t.Fatalf("non-reality should pass through: pub=%q sid=%q err=%v", pub, sid, err)
	}
}

package inbound

import (
	"strings"
	"testing"
)

const validReality = `{
  "tag":"reality-xhttp-01",
  "port":443,
  "protocol":"vless",
  "settings":{"clients":[],"decryption":"none"},
  "streamSettings":{
    "network":"xhttp",
    "security":"reality",
    "realitySettings":{
      "dest":"www.example.com:443",
      "serverNames":["www.example.com"],
      "privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "shortIds":["0123456789abcdef"]
    },
    "xhttpSettings":{"path":"/guardex"}
  }
}`

func TestParseValidRealityXHTTP(t *testing.T) {
	cfg, err := Parse([]byte(validReality))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tag != "reality-xhttp-01" || cfg.Port != 443 || cfg.Network != "xhttp" || cfg.Security != "reality" {
		t.Fatalf("unexpected config: %+v", cfg.Public())
	}
	if cfg.Digest == "" || len(cfg.Raw) == 0 {
		t.Fatal("expected canonical config and digest")
	}
	public := cfg.Public()
	if strings.Contains(public.Digest, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") {
		t.Fatal("public metadata leaked secret")
	}
}

func TestParseRejectsUnsafeShapes(t *testing.T) {
	tests := []struct {
		name    string
		replace string
		with    string
	}{
		{"empty tag", `"reality-xhttp-01"`, `""`},
		{"unsafe tag", `"reality-xhttp-01"`, `"../../xray"`},
		{"zero port", `"port":443`, `"port":0`},
		{"large port", `"port":443`, `"port":65536`},
		{"protocol", `"protocol":"vless"`, `"protocol":"shadowsocks"`},
		{"network", `"network":"xhttp"`, `"network":"quic"`},
		{"security", `"security":"reality"`, `"security":"none"`},
		{"bad combination", `"network":"xhttp"`, `"network":"ws"`},
		{"unknown top field", `"tag":"reality-xhttp-01",`, `"tag":"reality-xhttp-01","command":"rm",`},
		{"unknown stream field", `"network":"xhttp",`, `"network":"xhttp","quicSettings":{},`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := strings.Replace(validReality, tt.replace, tt.with, 1)
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatalf("Parse accepted unsafe config: %s", raw)
			}
		})
	}
}

func TestParseAcceptsDocumentedTransportAliases(t *testing.T) {
	for _, network := range []string{"tcp", "raw", "xhttp", "grpc"} {
		t.Run(network+"-reality", func(t *testing.T) {
			raw := strings.Replace(validReality, `"network":"xhttp"`, `"network":"`+network+`"`, 1)
			if _, err := Parse([]byte(raw)); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, network := range []string{"tcp", "raw", "xhttp", "grpc", "websocket", "ws", "httpupgrade"} {
		t.Run(network+"-tls", func(t *testing.T) {
			raw := strings.Replace(validReality, `"network":"xhttp"`, `"network":"`+network+`"`, 1)
			raw = strings.Replace(raw, `"security":"reality"`, `"security":"tls"`, 1)
			if _, err := Parse([]byte(raw)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParseCanonicalDigestIsStableAcrossWhitespace(t *testing.T) {
	a, err := Parse([]byte(validReality))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(strings.ReplaceAll(validReality, "\n", "")))
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != b.Digest {
		t.Fatalf("digest changed with whitespace: %s != %s", a.Digest, b.Digest)
	}
}

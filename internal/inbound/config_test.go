package inbound

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func validHysteriaConfig(t *testing.T, password string, hop string) string {
	t.Helper()
	t.Setenv("HYSTERIA_TLS_DIR", filepath.Join(t.TempDir(), "tls"))
	cert, key := ManagedTLSPaths("gx-hysteria-01")
	return fmt.Sprintf(`{
		"tag":"gx-hysteria-01","port":24443,"protocol":"hysteria",
		"settings":{"version":2,"clients":[]},
		"streamSettings":{"network":"hysteria","security":"tls",
			"tlsSettings":{"serverName":"203.0.113.10","alpn":["h3"],"minVersion":"1.3","maxVersion":"1.3","certificates":[{"certificateFile":%q,"keyFile":%q}]},
			"hysteriaSettings":{"version":2,"auth":"","udpIdleTimeout":60,"masquerade":{}},
			"finalmask":{"udp":[{"type":"salamander","settings":{"password":%q}}]%s}
		}
	}`, cert, key, password, hop)
}

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

const validGRPCReality = `{
  "tag":"reality-grpc-01",
  "port":8443,
  "protocol":"vless",
  "settings":{"clients":[],"decryption":"none"},
  "streamSettings":{
    "network":"grpc",
    "security":"reality",
    "realitySettings":{
      "dest":"www.example.com:443",
      "serverNames":["www.example.com"],
      "privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "shortIds":["0123456789abcdef"]
    },
    "grpcSettings":{
      "authority":"www.example.com",
      "serviceName":"guardex.sync-v1",
      "multiMode":false,
      "idle_timeout":60,
      "health_check_timeout":20,
      "permit_without_stream":false,
      "initial_windows_size":0,
      "user_agent":"Guardex"
    }
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

func TestParseValidRealityGRPC(t *testing.T) {
	cfg, err := Parse([]byte(validGRPCReality))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tag != "reality-grpc-01" || cfg.Port != 8443 || cfg.Network != "grpc" || cfg.Security != "reality" {
		t.Fatalf("unexpected config: %+v", cfg.Public())
	}
}

func TestParseValidManagedHysteriaTLSAndSalamander(t *testing.T) {
	raw := validHysteriaConfig(t, "", `,"quicParams":{"congestion":"bbr","udpHop":{"ports":"24443-24445","interval":30}}`)
	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocol != "hysteria" || cfg.Network != "hysteria" || cfg.Security != "tls" || cfg.Port != 24443 {
		t.Fatalf("unexpected Hysteria config: %+v", cfg.Public())
	}
}

func TestParseRejectsUnsafeManagedHysteriaShapes(t *testing.T) {
	valid := validHysteriaConfig(t, "", "")
	tests := []struct {
		name, replace, with string
	}{
		{"wrong protocol version", `"settings":{"version":2`, `"settings":{"version":1`},
		{"wrong transport", `"network":"hysteria"`, `"network":"raw"`},
		{"without TLS", `"security":"tls"`, `"security":"reality"`},
		{"wrong ALPN", `"alpn":["h3"]`, `"alpn":["h2"]`},
		{"server name contains port", `"serverName":"203.0.113.10"`, `"serverName":"example.com:443"`},
		{"invalid dns label", `"serverName":"203.0.113.10"`, `"serverName":"-example.com"`},
		{"old TLS", `"minVersion":"1.3"`, `"minVersion":"1.2"`},
		{"automatic chain building", `"certificates":[{`, `"certificates":[{"buildChain":true,`},
		{"literal certificate", `"certificates":[{`, `"certificates":[{"certificate":["PEM"],`},
		{"path escape", `/fullchain.pem`, `/../fullchain.pem`},
		{"shared auth", `"auth":""`, `"auth":"shared"`},
		{"without Salamander", `"type":"salamander"`, `"type":"noise"`},
		{"short Salamander secret", `"password":""`, `"password":"short"`},
		{"non-base64 Salamander secret", `"password":""`, `"password":"*******************************************"`},
		{"unknown FinalMask field", `"finalmask":{`, `"finalmask":{"tcp":[],`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := strings.Replace(valid, tt.replace, tt.with, 1)
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatalf("Parse accepted unsafe Hysteria config: %s", raw)
			}
		})
	}
}

func TestParseRejectsUDPHopWithoutListenerAndOversizedRange(t *testing.T) {
	withoutListener := validHysteriaConfig(t, "", `,"quicParams":{"udpHop":{"ports":"25000-25010","interval":30}}`)
	if _, err := Parse([]byte(withoutListener)); err == nil {
		t.Fatal("udpHop without the listener port was accepted")
	}
	oversized := validHysteriaConfig(t, "", `,"quicParams":{"udpHop":{"ports":"24443-25000","interval":30}}`)
	if _, err := Parse([]byte(oversized)); err == nil {
		t.Fatal("udpHop range over the safety limit was accepted")
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
	for _, network := range []string{"tcp", "raw", "xhttp"} {
		t.Run(network+"-reality", func(t *testing.T) {
			raw := strings.Replace(validReality, `"network":"xhttp"`, `"network":"`+network+`"`, 1)
			if _, err := Parse([]byte(raw)); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := Parse([]byte(validGRPCReality)); err != nil {
		t.Fatalf("grpc-reality: %v", err)
	}
	for _, network := range []string{"tcp", "raw", "xhttp", "websocket", "ws", "httpupgrade"} {
		t.Run(network+"-tls", func(t *testing.T) {
			raw := strings.Replace(validReality, `"network":"xhttp"`, `"network":"`+network+`"`, 1)
			raw = strings.Replace(raw, `"security":"reality"`, `"security":"tls"`, 1)
			if _, err := Parse([]byte(raw)); err != nil {
				t.Fatal(err)
			}
		})
	}
	grpcTLS := strings.Replace(validGRPCReality, `"security":"reality"`, `"security":"tls"`, 1)
	if _, err := Parse([]byte(grpcTLS)); err != nil {
		t.Fatalf("grpc-tls: %v", err)
	}
}

func TestParseRejectsUnsafeGRPCSettings(t *testing.T) {
	tests := []struct {
		name    string
		replace string
		with    string
	}{
		{"missing settings", `"grpcSettings":{`, `"xhttpSettings":{`},
		{"non-object settings", `"grpcSettings":{`, `"grpcSettings":null,"xhttpSettings":{`},
		{"empty service name", `"serviceName":"guardex.sync-v1"`, `"serviceName":""`},
		{"unsafe service name", `"serviceName":"guardex.sync-v1"`, `"serviceName":"bad path?"`},
		{"unknown field", `"authority":"www.example.com",`, `"authority":"www.example.com","command":"ignored",`},
		{"wrong multi mode type", `"multiMode":false`, `"multiMode":"false"`},
		{"negative idle timeout", `"idle_timeout":60`, `"idle_timeout":-1`},
		{"negative health timeout", `"health_check_timeout":20`, `"health_check_timeout":-1`},
		{"negative window size", `"initial_windows_size":0`, `"initial_windows_size":-1`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := strings.Replace(validGRPCReality, tt.replace, tt.with, 1)
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatalf("Parse accepted unsafe grpcSettings: %s", raw)
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

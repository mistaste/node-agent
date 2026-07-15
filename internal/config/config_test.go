package config

import "testing"

func TestLoadUsesSeparateDurableInboundStore(t *testing.T) {
	t.Setenv("INBOUNDS_FILE", "")
	t.Setenv("USERS_FILE", "")
	cfg := Load()
	if cfg.InboundsFile != "/data/inbounds.json" {
		t.Fatalf("InboundsFile=%q", cfg.InboundsFile)
	}
	if cfg.UsersFile != "/data/users.json" {
		t.Fatalf("UsersFile=%q", cfg.UsersFile)
	}
}

func TestControllerPollingRequiresCompleteVerifiedHTTPSConfig(t *testing.T) {
	valid := &Config{ControllerURL: "https://api.guardex-vpn.com", InternalServiceToken: "service", Secret: "node"}
	if !valid.ControllerPollingEnabled() {
		t.Fatal("complete HTTPS controller configuration was not enabled")
	}
	for _, cfg := range []*Config{
		{ControllerURL: "http://api.guardex-vpn.com", InternalServiceToken: "service", Secret: "node"},
		{ControllerURL: "https://user@api.guardex-vpn.com", InternalServiceToken: "service", Secret: "node"},
		{ControllerURL: "https://api.guardex-vpn.com", InternalServiceToken: "", Secret: "node"},
		{ControllerURL: "https://api.guardex-vpn.com", InternalServiceToken: "service", Secret: "change-me-secret"},
	} {
		if cfg.ControllerPollingEnabled() {
			t.Fatalf("unsafe/incomplete controller configuration enabled: %+v", cfg)
		}
	}
}

func TestLoadCanonicalizesOnlyOfficialLegacyControllerPort(t *testing.T) {
	t.Setenv("CONTROLLER_URL", "https://api.guardex-vpn.com:2096/")
	if got := Load().ControllerURL; got != "https://api.guardex-vpn.com" {
		t.Fatalf("legacy official controller URL = %q", got)
	}
	t.Setenv("CONTROLLER_URL", "https://staging.example.com:2096")
	if got := Load().ControllerURL; got != "https://staging.example.com:2096" {
		t.Fatalf("unrelated controller URL was rewritten: %q", got)
	}
}

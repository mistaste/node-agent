package xray

import (
	"testing"

	hysteriaAccount "github.com/xtls/xray-core/proxy/hysteria/account"
	vlessAccount "github.com/xtls/xray-core/proxy/vless"
)

func TestBuildManagedHysteriaUserUsesUUIDAuthAndSharedStatsIdentity(t *testing.T) {
	const uuid = "6f8d0c5b-6c62-4b35-9231-b2af180b5284"
	user, err := buildManagedUser(AddUserParams{UUID: uuid, Protocol: "hysteria", Level: 3})
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != uuid+"@guardex" || user.Level != 3 {
		t.Fatalf("unexpected Hysteria stats identity: %+v", user)
	}
	memory, err := user.ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	account, ok := memory.Account.(*hysteriaAccount.MemoryAccount)
	if !ok || account.Auth != uuid {
		t.Fatalf("Hysteria auth account = %#v", memory.Account)
	}
}

func TestBuildManagedUserPreservesVLESSCompatibility(t *testing.T) {
	const uuid = "6f8d0c5b-6c62-4b35-9231-b2af180b5284"
	user, err := buildManagedUser(AddUserParams{UUID: uuid, Flow: "xtls-rprx-vision"})
	if err != nil {
		t.Fatal(err)
	}
	memory, err := user.ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := memory.Account.(*vlessAccount.MemoryAccount); !ok {
		t.Fatalf("VLESS account = %#v", memory.Account)
	}
}

func TestBuildManagedHysteriaUserRejectsVLESSFlow(t *testing.T) {
	if _, err := buildManagedUser(AddUserParams{UUID: "6f8d0c5b-6c62-4b35-9231-b2af180b5284", Protocol: "hysteria", Flow: "xtls-rprx-vision"}); err == nil {
		t.Fatal("Hysteria user accepted a VLESS flow")
	}
}

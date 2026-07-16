package xray

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardex/node-agent/internal/inbound"
)

func managedHysteriaTestConfig(t *testing.T, tag string, port int, password string, hop bool) []byte {
	t.Helper()
	certificateFile, keyFile := inbound.ManagedTLSPaths(tag)
	hopJSON := ""
	if hop {
		hopJSON = fmt.Sprintf(`,"quicParams":{"congestion":"bbr","udpHop":{"ports":%q,"interval":30}}`, fmt.Sprintf("%d-%d", port, port+2))
	}
	return []byte(fmt.Sprintf(`{
		"tag":%q,"port":%d,"protocol":"hysteria",
		"settings":{"version":2,"clients":[]},
		"streamSettings":{
			"network":"hysteria","security":"tls",
			"tlsSettings":{"serverName":"203.0.113.10","alpn":["h3"],"minVersion":"1.3","maxVersion":"1.3","fingerprint":"chrome","certificates":[{"certificateFile":%q,"keyFile":%q}]},
			"hysteriaSettings":{"version":2,"auth":"","udpIdleTimeout":60,"masquerade":{}},
			"finalmask":{"udp":[{"type":"salamander","settings":{"password":%q}}]%s}
		}
	}`, tag, port, certificateFile, keyFile, password, hopJSON))
}

func TestEnsureManagedHysteriaMaterialGeneratesAndReusesNodeSecrets(t *testing.T) {
	t.Setenv("HYSTERIA_TLS_DIR", filepath.Join(t.TempDir(), "tls"))
	template := managedHysteriaTestConfig(t, "gx-hysteria-test", 24443, "", false)
	if _, err := inbound.Parse(template); err != nil {
		t.Fatalf("keyless template rejected: %v", err)
	}
	first, firstMaterial, err := EnsureManagedHysteriaMaterial(template, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstMaterial.SalamanderPassword) < 32 || len(firstMaterial.PinSHA256) != 64 {
		t.Fatalf("invalid client material: %+v", firstMaterial)
	}
	if !strings.Contains(string(first), firstMaterial.SalamanderPassword) {
		t.Fatal("runtime config does not contain generated Salamander material")
	}
	if _, err := inbound.Parse(first); err != nil {
		t.Fatalf("realized config rejected: %v", err)
	}
	if err := ValidateInboundForCore(first); err != nil {
		t.Fatalf("linked Xray core cannot build managed Hysteria2: %v", err)
	}

	second, secondMaterial, err := EnsureManagedHysteriaMaterial(template, first)
	if err != nil {
		t.Fatal(err)
	}
	if secondMaterial.SalamanderPassword != firstMaterial.SalamanderPassword || secondMaterial.PinSHA256 != firstMaterial.PinSHA256 || secondMaterial.CertificateRotated {
		t.Fatalf("retry rotated Hysteria material: first=%+v second=%+v", firstMaterial, secondMaterial)
	}
	var firstJSON, secondJSON any
	_ = json.Unmarshal(first, &firstJSON)
	_ = json.Unmarshal(second, &secondJSON)
	if fmt.Sprint(firstJSON) != fmt.Sprint(secondJSON) {
		t.Fatal("retry changed realized Hysteria config")
	}
	// The dedicated node-local secret survives a targeted loss of inbounds.json
	// (represented here by no previous runtime config).
	third, thirdMaterial, err := EnsureManagedHysteriaMaterial(template, nil)
	if err != nil {
		t.Fatal(err)
	}
	if thirdMaterial.SalamanderPassword != firstMaterial.SalamanderPassword || thirdMaterial.PinSHA256 != firstMaterial.PinSHA256 || thirdMaterial.CertificateRotated || string(third) != string(first) {
		t.Fatal("node-local recovery rotated Hysteria material")
	}

	certificateFile, keyFile := inbound.ManagedTLSPaths("gx-hysteria-test")
	if keyInfo, err := os.Stat(keyFile); err != nil || keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private-key permissions = %v, err=%v", keyInfo, err)
	}
	if certInfo, err := os.Stat(certificateFile); err != nil || certInfo.Mode().Perm() != 0o600 {
		t.Fatalf("certificate permissions = %v, err=%v", certInfo, err)
	}
	for _, link := range []string{certificateFile, keyFile} {
		if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("managed TLS view %q is not a symlink: info=%v err=%v", link, info, err)
		}
		if target, err := os.Readlink(link); err != nil || target != managedTLSBundleFilename {
			t.Fatalf("managed TLS view %q target=%q err=%v", link, target, err)
		}
	}
	bundleFile := filepath.Join(filepath.Dir(keyFile), managedTLSBundleFilename)
	if bundleInfo, err := os.Stat(bundleFile); err != nil || bundleInfo.Mode().Perm() != 0o600 {
		t.Fatalf("TLS-bundle permissions = %v, err=%v", bundleInfo, err)
	}
	secretFile := filepath.Join(filepath.Dir(keyFile), "salamander.key")
	if secretInfo, err := os.Stat(secretFile); err != nil || secretInfo.Mode().Perm() != 0o600 {
		t.Fatalf("Salamander-secret permissions = %v, err=%v", secretInfo, err)
	}
}

func TestEnsureManagedHysteriaMaterialFailsClosedOnPartialTLSState(t *testing.T) {
	t.Setenv("HYSTERIA_TLS_DIR", filepath.Join(t.TempDir(), "tls"))
	template := managedHysteriaTestConfig(t, "gx-hysteria-partial", 24444, "", false)
	certificateFile, _ := inbound.ManagedTLSPaths("gx-hysteria-partial")
	if err := os.MkdirAll(filepath.Dir(certificateFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certificateFile, []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}
	realized, material, err := EnsureManagedHysteriaMaterial(template, nil)
	if err != nil {
		t.Fatalf("partial pre-bundle TLS state was not recovered: %v", err)
	}
	if !material.CertificateRotated || len(material.PinSHA256) != 64 {
		t.Fatalf("partial-state recovery did not report rotation: %+v", material)
	}
	if err := ValidateInboundForCore(realized); err != nil {
		t.Fatalf("recovered TLS state cannot build in linked Xray: %v", err)
	}
}

func TestEnsureManagedHysteriaMaterialRepairsDerivedViewsFromBundle(t *testing.T) {
	t.Setenv("HYSTERIA_TLS_DIR", filepath.Join(t.TempDir(), "tls"))
	template := managedHysteriaTestConfig(t, "gx-hysteria-view-recovery", 24446, "", false)
	first, firstMaterial, err := EnsureManagedHysteriaMaterial(template, nil)
	if err != nil {
		t.Fatal(err)
	}
	certificateFile, keyFile := inbound.ManagedTLSPaths("gx-hysteria-view-recovery")
	if err := os.Remove(certificateFile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certificateFile, []byte("crash-partial-view"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	recovered, recoveredMaterial, err := EnsureManagedHysteriaMaterial(template, first)
	if err != nil {
		t.Fatal(err)
	}
	if recoveredMaterial.PinSHA256 != firstMaterial.PinSHA256 || recoveredMaterial.CertificateRotated || string(recovered) != string(first) {
		t.Fatalf("derived-view recovery changed source material: first=%+v recovered=%+v", firstMaterial, recoveredMaterial)
	}
	certificate, _ := os.ReadFile(certificateFile)
	privateKey, _ := os.ReadFile(keyFile)
	if _, err := tls.X509KeyPair(certificate, privateKey); err != nil {
		t.Fatalf("repaired views are not a valid pair: %v", err)
	}
}

func TestEnsureManagedHysteriaMaterialRenewsBeforeExpiryWithStablePrivateKey(t *testing.T) {
	t.Setenv("HYSTERIA_TLS_DIR", filepath.Join(t.TempDir(), "tls"))
	const tag = "gx-hysteria-renewal"
	const serverName = "203.0.113.10"
	template := managedHysteriaTestConfig(t, tag, 24447, "", false)
	first, firstMaterial, err := EnsureManagedHysteriaMaterial(template, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, keyFile := inbound.ManagedTLSPaths(tag)
	bundleFile := filepath.Join(filepath.Dir(keyFile), managedTLSBundleFilename)
	current, exists, err := loadManagedTLSBundle(bundleFile)
	if err != nil || !exists {
		t.Fatalf("load initial TLS bundle: exists=%v err=%v", exists, err)
	}
	privateScalar := new(big.Int).Set(current.privateKey.D)
	issuedAt := time.Now().UTC().Add(-managedTLSLifetime + 24*time.Hour)
	expiring, err := newManagedTLSBundle(serverName, current.privateKey, issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeTLSBundleAtomically(bundleFile, expiring.raw); err != nil {
		t.Fatal(err)
	}
	expiringDigest := sha256.Sum256(expiring.leaf.Raw)
	renewed, renewedMaterial, err := EnsureManagedHysteriaMaterial(template, first)
	if err != nil {
		t.Fatal(err)
	}
	if !renewedMaterial.CertificateRotated || renewedMaterial.PinSHA256 == firstMaterial.PinSHA256 || renewedMaterial.PinSHA256 == hex.EncodeToString(expiringDigest[:]) {
		t.Fatalf("renewal did not publish a fresh pin: first=%+v renewed=%+v", firstMaterial, renewedMaterial)
	}
	if string(renewed) != string(first) {
		t.Fatal("certificate renewal changed structural/client-secret JSON")
	}
	after, exists, err := loadManagedTLSBundle(bundleFile)
	if err != nil || !exists || after.privateKey.D.Cmp(privateScalar) != 0 {
		t.Fatalf("certificate renewal rotated the private key: exists=%v err=%v", exists, err)
	}
	if time.Until(after.leaf.NotAfter) < managedTLSLifetime-managedTLSRenewBefore {
		t.Fatalf("renewed leaf lifetime is unexpectedly short: %v", after.leaf.NotAfter)
	}
}

func TestEnsureManagedHysteriaMaterialFailsClosedOnSecretConflict(t *testing.T) {
	t.Setenv("HYSTERIA_TLS_DIR", filepath.Join(t.TempDir(), "tls"))
	template := managedHysteriaTestConfig(t, "gx-hysteria-secret-conflict", 24445, "", false)
	_, first, err := EnsureManagedHysteriaMaterial(template, nil)
	if err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("A", 43)
	if other == first.SalamanderPassword {
		t.Fatal("test secret unexpectedly matches generated material")
	}
	conflicting := managedHysteriaTestConfig(t, "gx-hysteria-secret-conflict", 24445, other, false)
	if _, _, err := EnsureManagedHysteriaMaterial(conflicting, nil); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("conflicting durable Salamander state was not rejected: %v", err)
	}
}

func TestManagedHysteriaUDPHopBuildsInLinkedCore(t *testing.T) {
	t.Setenv("HYSTERIA_TLS_DIR", filepath.Join(t.TempDir(), "tls"))
	template := managedHysteriaTestConfig(t, "gx-hysteria-hop", 24500, "", true)
	realized, _, err := EnsureManagedHysteriaMaterial(template, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateInboundForCore(realized); err != nil {
		t.Fatalf("linked Xray core cannot build udpHop config: %v", err)
	}
}

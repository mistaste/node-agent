package xray

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/guardex/node-agent/internal/inbound"
)

// A node runs one agent process, but direct API requests and controller pulls
// may realize the same tag concurrently. Serialize keypair creation so the two
// atomic file renames can never leave a certificate from one generation paired
// with the private key from another.
var managedHysteriaMaterialMu sync.Mutex

const (
	managedTLSBundleFilename = "bundle.pem"
	managedTLSLifetime       = 397 * 24 * time.Hour
	managedTLSRenewBefore    = 30 * 24 * time.Hour
	maxManagedTLSBundleBytes = 128 * 1024
)

// HysteriaMaterial contains only material required to construct a client
// profile. Certificate private keys never leave the node. SalamanderPassword
// is still a client secret and must only be carried in client_secret_json.
type HysteriaMaterial struct {
	SalamanderPassword string
	PinSHA256          string
	CertificateRotated bool
}

// EnsureManagedHysteriaMaterial realizes a keyless controller template. The
// TLS keypair and Salamander password are durable and node-local: retries and
// unrelated profile edits reuse the previous values instead of silently
// invalidating issued client profiles.
func EnsureManagedHysteriaMaterial(configJSON, previousConfig []byte) ([]byte, HysteriaMaterial, error) {
	managedHysteriaMaterialMu.Lock()
	defer managedHysteriaMaterialMu.Unlock()

	var root struct {
		Tag            string `json:"tag"`
		Protocol       string `json:"protocol"`
		StreamSettings struct {
			TLSSettings struct {
				ServerName   string `json:"serverName"`
				Certificates []struct {
					CertificateFile string `json:"certificateFile"`
					KeyFile         string `json:"keyFile"`
				} `json:"certificates"`
			} `json:"tlsSettings"`
			FinalMask struct {
				UDP []struct {
					Type     string `json:"type"`
					Settings struct {
						Password string `json:"password"`
					} `json:"settings"`
				} `json:"udp"`
			} `json:"finalmask"`
		} `json:"streamSettings"`
	}
	if err := json.Unmarshal(configJSON, &root); err != nil {
		return nil, HysteriaMaterial{}, fmt.Errorf("parse managed hysteria config: %w", err)
	}
	if root.Protocol != "hysteria" {
		return append([]byte(nil), configJSON...), HysteriaMaterial{}, nil
	}
	if len(root.StreamSettings.TLSSettings.Certificates) != 1 || len(root.StreamSettings.FinalMask.UDP) != 1 || root.StreamSettings.FinalMask.UDP[0].Type != "salamander" {
		return nil, HysteriaMaterial{}, errors.New("managed hysteria material contract is incomplete")
	}

	certificate := root.StreamSettings.TLSSettings.Certificates[0]
	expectedCert, expectedKey := inbound.ManagedTLSPaths(root.Tag)
	if filepath.Clean(certificate.CertificateFile) != expectedCert || filepath.Clean(certificate.KeyFile) != expectedKey {
		return nil, HysteriaMaterial{}, errors.New("managed hysteria TLS paths violate the node-local contract")
	}
	if err := ensureSecureTLSDirectory(filepath.Dir(expectedCert)); err != nil {
		return nil, HysteriaMaterial{}, err
	}
	password := root.StreamSettings.FinalMask.UDP[0].Settings.Password
	if password == "" && len(previousConfig) > 0 {
		password = hysteriaSalamanderPassword(previousConfig)
	}
	password, err := ensureManagedSalamanderPassword(root.Tag, password)
	if err != nil {
		return nil, HysteriaMaterial{}, err
	}
	pin, certificateRotated, err := ensureManagedTLSCertificate(root.Tag, root.StreamSettings.TLSSettings.ServerName, certificate.CertificateFile, certificate.KeyFile)
	if err != nil {
		return nil, HysteriaMaterial{}, err
	}

	var document map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(configJSON)))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, HysteriaMaterial{}, fmt.Errorf("normalize managed hysteria config: %w", err)
	}
	stream, _ := document["streamSettings"].(map[string]any)
	finalMask, _ := stream["finalmask"].(map[string]any)
	udp, _ := finalMask["udp"].([]any)
	mask, _ := udp[0].(map[string]any)
	settings, _ := mask["settings"].(map[string]any)
	settings["password"] = password
	runtimeJSON, err := json.Marshal(document)
	if err != nil {
		return nil, HysteriaMaterial{}, fmt.Errorf("encode managed hysteria config: %w", err)
	}
	return runtimeJSON, HysteriaMaterial{SalamanderPassword: password, PinSHA256: pin, CertificateRotated: certificateRotated}, nil
}

func hysteriaSalamanderPassword(configJSON []byte) string {
	var root struct {
		Protocol       string `json:"protocol"`
		StreamSettings struct {
			FinalMask struct {
				UDP []struct {
					Type     string `json:"type"`
					Settings struct {
						Password string `json:"password"`
					} `json:"settings"`
				} `json:"udp"`
			} `json:"finalmask"`
		} `json:"streamSettings"`
	}
	if json.Unmarshal(configJSON, &root) != nil || root.Protocol != "hysteria" || len(root.StreamSettings.FinalMask.UDP) != 1 || root.StreamSettings.FinalMask.UDP[0].Type != "salamander" {
		return ""
	}
	return root.StreamSettings.FinalMask.UDP[0].Settings.Password
}

func ensureManagedSalamanderPassword(tag, candidate string) (string, error) {
	_, keyFile := inbound.ManagedTLSPaths(tag)
	secretFile := filepath.Join(filepath.Dir(keyFile), "salamander.key")
	info, err := os.Lstat(secretFile)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return "", errors.New("managed hysteria Salamander secret must be a regular mode-0600 file")
		}
		if info.Size() < 1 || info.Size() > 256 {
			return "", errors.New("managed hysteria Salamander secret file has an invalid size")
		}
		stored, readErr := os.ReadFile(secretFile)
		if readErr != nil {
			return "", fmt.Errorf("read managed hysteria Salamander secret: %w", readErr)
		}
		password := string(stored)
		if !validManagedSalamanderPassword(password) {
			return "", errors.New("managed hysteria Salamander secret file is invalid")
		}
		if candidate != "" && candidate != password {
			return "", errors.New("managed hysteria Salamander state conflicts with the durable node-local secret")
		}
		return password, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect managed hysteria Salamander secret: %w", err)
	}
	if candidate == "" {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return "", fmt.Errorf("generate Salamander password: %w", err)
		}
		candidate = base64.RawURLEncoding.EncodeToString(secret)
	}
	if !validManagedSalamanderPassword(candidate) {
		return "", errors.New("managed hysteria Salamander candidate is invalid")
	}
	if err := writeSecretAtomically(secretFile, []byte(candidate)); err != nil {
		return "", err
	}
	return candidate, nil
}

func validManagedSalamanderPassword(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func writeSecretAtomically(filename string, value []byte) error {
	dir := filepath.Dir(filename)
	temporary, err := os.CreateTemp(dir, ".salamander-*.tmp")
	if err != nil {
		return fmt.Errorf("create managed hysteria Salamander temp file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	fail := func(err error) error {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := temporary.Write(value); err != nil {
		return fail(err)
	}
	if err := temporary.Sync(); err != nil {
		return fail(err)
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return fmt.Errorf("persist managed hysteria Salamander secret: %w", err)
	}
	directory, err := os.Open(dir)
	if err == nil {
		err = directory.Sync()
		_ = directory.Close()
	}
	return err
}

type managedTLSBundle struct {
	raw        []byte
	leaf       *x509.Certificate
	privateKey *ecdsa.PrivateKey
}

func ensureManagedTLSCertificate(tag, serverName, certificateFile, keyFile string) (string, bool, error) {
	expectedCert, expectedKey := inbound.ManagedTLSPaths(tag)
	if filepath.Clean(certificateFile) != expectedCert || filepath.Clean(keyFile) != expectedKey {
		return "", false, errors.New("managed hysteria TLS paths violate the node-local contract")
	}
	dir := filepath.Dir(expectedCert)
	if err := ensureSecureTLSDirectory(dir); err != nil {
		return "", false, err
	}
	bundleFile := filepath.Join(dir, managedTLSBundleFilename)
	bundle, exists, err := loadManagedTLSBundle(bundleFile)
	if err != nil {
		return "", false, err
	}
	rotated := false
	now := time.Now().UTC()
	if !exists {
		bundle, exists, err = migrateLegacyManagedTLSPair(expectedCert, expectedKey)
		if err != nil {
			return "", false, err
		}
		if !exists {
			bundle, err = newManagedTLSBundle(serverName, nil, now)
			rotated = true
		}
		if err != nil {
			return "", false, err
		}
		if err := writeTLSBundleAtomically(bundleFile, bundle.raw); err != nil {
			return "", false, err
		}
	}
	// Install and validate stable views before any renewal. Once both paths are
	// links to the same bundle name, a single atomic rename changes the leaf and
	// key source together and there is no fallible two-file commit afterwards.
	if err := ensureManagedTLSBundleLinks(expectedCert, expectedKey); err != nil {
		return "", false, err
	}
	if err := validateManagedTLSBundleLinks(expectedCert, expectedKey, bundle.raw); err != nil {
		return "", false, err
	}
	if managedTLSNeedsRenewal(bundle.leaf, serverName, now) {
		// Keep the ECDSA key stable across routine certificate renewal. Xray reads
		// certificate/key paths independently; a stable key makes even a read
		// concurrent with the atomic bundle swap a valid pair.
		bundle, err = newManagedTLSBundle(serverName, bundle.privateKey, now)
		if err != nil {
			return "", false, err
		}
		if err := writeTLSBundleAtomically(bundleFile, bundle.raw); err != nil {
			return "", false, err
		}
		rotated = true
	}
	digest := sha256.Sum256(bundle.leaf.Raw)
	return hex.EncodeToString(digest[:]), rotated, nil
}

func loadManagedTLSBundle(filename string) (managedTLSBundle, bool, error) {
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return managedTLSBundle{}, false, nil
	}
	if err != nil {
		return managedTLSBundle{}, false, fmt.Errorf("inspect managed hysteria TLS bundle: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maxManagedTLSBundleBytes {
		return managedTLSBundle{}, false, errors.New("managed hysteria TLS bundle must be a regular mode-0600 file of bounded size")
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		return managedTLSBundle{}, false, fmt.Errorf("read managed hysteria TLS bundle: %w", err)
	}
	bundle, err := parseManagedTLSBundle(raw)
	if err != nil {
		return managedTLSBundle{}, false, fmt.Errorf("validate managed hysteria TLS bundle: %w", err)
	}
	return bundle, true, nil
}

func migrateLegacyManagedTLSPair(certificateFile, keyFile string) (managedTLSBundle, bool, error) {
	certInfo, certErr := os.Lstat(certificateFile)
	keyInfo, keyErr := os.Lstat(keyFile)
	certMissing := errors.Is(certErr, os.ErrNotExist)
	keyMissing := errors.Is(keyErr, os.ErrNotExist)
	if certErr != nil && !certMissing {
		return managedTLSBundle{}, false, fmt.Errorf("inspect legacy managed certificate: %w", certErr)
	}
	if keyErr != nil && !keyMissing {
		return managedTLSBundle{}, false, fmt.Errorf("inspect legacy managed private key: %w", keyErr)
	}
	if certMissing || keyMissing {
		return managedTLSBundle{}, false, nil
	}
	if certInfo.Mode()&os.ModeSymlink != 0 || keyInfo.Mode()&os.ModeSymlink != 0 {
		// Managed links can only point at the bundle. If the bundle itself was
		// lost, no private source of truth remains and a controlled rotation is
		// safer than following an arbitrary link.
		certTarget, certLinkErr := os.Readlink(certificateFile)
		keyTarget, keyLinkErr := os.Readlink(keyFile)
		if certLinkErr == nil && keyLinkErr == nil && certTarget == managedTLSBundleFilename && keyTarget == managedTLSBundleFilename {
			return managedTLSBundle{}, false, nil
		}
		return managedTLSBundle{}, false, errors.New("managed hysteria legacy TLS paths contain unexpected symlinks")
	}
	if !certInfo.Mode().IsRegular() || !keyInfo.Mode().IsRegular() {
		return managedTLSBundle{}, false, errors.New("managed hysteria legacy TLS paths must be regular files")
	}
	if keyInfo.Mode().Perm()&0o077 != 0 {
		return managedTLSBundle{}, false, errors.New("managed hysteria legacy private key permissions are unsafe")
	}
	certPEM, certReadErr := os.ReadFile(certificateFile)
	keyPEM, keyReadErr := os.ReadFile(keyFile)
	if certReadErr != nil || keyReadErr != nil {
		return managedTLSBundle{}, false, errors.New("managed hysteria legacy TLS pair could not be read")
	}
	raw := make([]byte, 0, len(certPEM)+len(keyPEM)+1)
	raw = append(raw, bytes.TrimSpace(certPEM)...)
	raw = append(raw, '\n')
	raw = append(raw, bytes.TrimSpace(keyPEM)...)
	raw = append(raw, '\n')
	bundle, err := parseManagedTLSBundle(raw)
	if err != nil {
		// A pre-bundle crash could leave mismatched regular files. They are only
		// derived views, so replace them from a newly generated source of truth.
		return managedTLSBundle{}, false, nil
	}
	return bundle, true, nil
}

func parseManagedTLSBundle(raw []byte) (managedTLSBundle, error) {
	if len(raw) == 0 || len(raw) > maxManagedTLSBundleBytes {
		return managedTLSBundle{}, errors.New("TLS bundle size is invalid")
	}
	pair, err := tls.X509KeyPair(raw, raw)
	if err != nil {
		return managedTLSBundle{}, err
	}
	if len(pair.Certificate) == 0 {
		return managedTLSBundle{}, errors.New("TLS bundle has no leaf certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return managedTLSBundle{}, err
	}
	privateKey, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve != elliptic.P256() {
		return managedTLSBundle{}, errors.New("TLS bundle private key must be ECDSA P-256")
	}
	return managedTLSBundle{raw: append([]byte(nil), raw...), leaf: leaf, privateKey: privateKey}, nil
}

func managedTLSNeedsRenewal(leaf *x509.Certificate, serverName string, now time.Time) bool {
	if leaf == nil || now.Before(leaf.NotBefore) || !now.Add(managedTLSRenewBefore).Before(leaf.NotAfter) {
		return true
	}
	return leaf.VerifyHostname(serverName) != nil
}

func ensureSecureTLSDirectory(dir string) error {
	root := inbound.ManagedTLSRoot()
	if filepath.Dir(dir) != root {
		return errors.New("managed hysteria TLS directory is outside the configured root")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create managed TLS root: %w", err)
	}
	if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("managed TLS root must be a real directory")
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create managed TLS profile directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("managed TLS profile path must be a real directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("managed TLS profile directory must not be group/world writable")
	}
	return nil
}

func newManagedTLSBundle(serverName string, privateKey *ecdsa.PrivateKey, now time.Time) (managedTLSBundle, error) {
	var err error
	if privateKey == nil {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return managedTLSBundle{}, fmt.Errorf("generate managed hysteria TLS key: %w", err)
		}
	}
	if privateKey.Curve != elliptic.P256() {
		return managedTLSBundle{}, errors.New("managed hysteria TLS key must be ECDSA P-256")
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return managedTLSBundle{}, fmt.Errorf("generate managed hysteria certificate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverName, Organization: []string{"Guardex node-local transport"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(managedTLSLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(serverName); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{serverName}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return managedTLSBundle{}, fmt.Errorf("create managed hysteria certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return managedTLSBundle{}, fmt.Errorf("encode managed hysteria private key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	raw := append(append([]byte(nil), certPEM...), keyPEM...)
	bundle, err := parseManagedTLSBundle(raw)
	if err != nil {
		return managedTLSBundle{}, fmt.Errorf("validate generated managed hysteria TLS bundle: %w", err)
	}
	return bundle, nil
}

func writeTLSBundleAtomically(filename string, raw []byte) error {
	dir := filepath.Dir(filename)
	temporary, err := os.CreateTemp(dir, ".tls-bundle-*.tmp")
	if err != nil {
		return fmt.Errorf("create managed hysteria TLS-bundle temp file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	fail := func(err error) error {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := temporary.Write(raw); err != nil {
		return fail(err)
	}
	if err := temporary.Sync(); err != nil {
		return fail(err)
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return fmt.Errorf("persist managed hysteria TLS bundle: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		// Rename has already committed in the live filesystem. If the exact
		// parsed bundle is readable, report success/new pin rather than returning
		// an error that would make observed material lie about the active target.
		current, readErr := os.ReadFile(filename)
		if readErr != nil || !bytes.Equal(current, raw) {
			return fmt.Errorf("sync managed hysteria TLS bundle directory: %w", err)
		}
	}
	return nil
}

func ensureManagedTLSBundleLinks(certificateFile, keyFile string) error {
	for _, filename := range []string{certificateFile, keyFile} {
		info, err := os.Lstat(filename)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			target, readErr := os.Readlink(filename)
			if readErr != nil || target != managedTLSBundleFilename {
				return errors.New("managed hysteria TLS link has an unexpected target")
			}
			continue
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect managed hysteria TLS view: %w", err)
		}
		if err == nil && !info.Mode().IsRegular() {
			return errors.New("managed hysteria TLS view must be a regular migration file or managed symlink")
		}
		if err := replaceWithManagedBundleLink(filename); err != nil {
			return err
		}
	}
	return syncDirectory(filepath.Dir(certificateFile))
}

func replaceWithManagedBundleLink(filename string) error {
	dir := filepath.Dir(filename)
	temporary, err := os.CreateTemp(dir, ".tls-link-*.tmp")
	if err != nil {
		return fmt.Errorf("reserve managed hysteria TLS-link path: %w", err)
	}
	temporaryName := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryName)
		return err
	}
	if err := os.Remove(temporaryName); err != nil {
		return err
	}
	defer os.Remove(temporaryName)
	if err := os.Symlink(managedTLSBundleFilename, temporaryName); err != nil {
		return fmt.Errorf("create managed hysteria TLS link: %w", err)
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return fmt.Errorf("install managed hysteria TLS link: %w", err)
	}
	return nil
}

func validateManagedTLSBundleLinks(certificateFile, keyFile string, expected []byte) error {
	certificate, err := os.ReadFile(certificateFile)
	if err != nil {
		return fmt.Errorf("read managed hysteria certificate view: %w", err)
	}
	privateKey, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("read managed hysteria private-key view: %w", err)
	}
	if !bytes.Equal(certificate, expected) || !bytes.Equal(privateKey, expected) {
		return errors.New("managed hysteria TLS views do not resolve to the durable bundle")
	}
	if _, err := tls.X509KeyPair(certificate, privateKey); err != nil {
		return fmt.Errorf("validate managed hysteria TLS views: %w", err)
	}
	return nil
}

func syncDirectory(dir string) error {
	directory, err := os.Open(dir)
	if err == nil {
		err = directory.Sync()
		_ = directory.Close()
	}
	return err
}

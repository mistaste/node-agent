package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAgentUpdatePartsValidatesRefAndSeparatesFullRollout(t *testing.T) {
	agentOnly, err := agentUpdateParts("git", "feature/controller-pull")
	if err != nil {
		t.Fatal(err)
	}
	if command := strings.Join(agentOnly, " "); strings.Contains(command, "pull xray") || !strings.Contains(command, "--build node-agent") {
		t.Fatalf("agent-only command = %q", command)
	}
	full, err := agentUpdateParts("git-full", "master")
	if err != nil {
		t.Fatal(err)
	}
	command := strings.Join(full, " ")
	if !strings.Contains(command, "docker compose pull xray") || !strings.Contains(command, "--build xray node-agent") {
		t.Fatalf("full command = %q", command)
	}

	for _, ref := range []string{"--upload-pack=evil", "master;reboot", "../master", "feature//bad", "feature/bad ", "feature/"} {
		if _, err := agentUpdateParts("git-full", ref); err == nil {
			t.Fatalf("unsafe ref %q accepted", ref)
		}
	}
	if _, err := agentUpdateParts("other", "master"); err == nil {
		t.Fatal("unsupported mode accepted")
	}
}

func TestValidateBinaryUpdateRequiresHTTPSAndSHA256(t *testing.T) {
	payloadDigest := sha256.Sum256([]byte("binary"))
	checksum := hex.EncodeToString(payloadDigest[:])
	validURL, normalizedChecksum, err := validateBinaryUpdate(" https://downloads.example/agent?release=1 ", strings.ToUpper(checksum))
	if err != nil {
		t.Fatal(err)
	}
	if validURL != "https://downloads.example/agent?release=1" || normalizedChecksum != checksum {
		t.Fatalf("normalized update = %q %q", validURL, normalizedChecksum)
	}
	for _, testCase := range []struct {
		url      string
		checksum string
	}{
		{url: "http://downloads.example/agent", checksum: checksum},
		{url: "https://user:password@downloads.example/agent", checksum: checksum},
		{url: "https://downloads.example/agent#fragment", checksum: checksum},
		{url: "https://downloads.example/agent", checksum: ""},
		{url: "https://downloads.example/agent", checksum: "abcd"},
	} {
		if _, _, err := validateBinaryUpdate(testCase.url, testCase.checksum); err == nil {
			t.Fatalf("unsafe binary update accepted: url=%q checksum=%q", testCase.url, testCase.checksum)
		}
	}
}

func TestDownloadVerifiedBinaryChecksStatusSizeDigestAndCleansTemp(t *testing.T) {
	payload := []byte("verified node-agent binary")
	digest := sha256.Sum256(payload)
	checksum := hex.EncodeToString(digest[:])
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/binary":
			_, _ = w.Write(payload)
		case "/error":
			http.Error(w, "do not install", http.StatusBadGateway)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = binaryUpdateHTTPClient.CheckRedirect

	dir := t.TempDir()
	target := filepath.Join(dir, "agent")
	if err := downloadVerifiedBinary(context.Background(), client, server.URL+"/binary", target, checksum, 1024); err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(installed) != string(payload) {
		t.Fatalf("installed payload = %q", installed)
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("installed mode info=%v err=%v", info, err)
	}

	for _, testCase := range []struct {
		name     string
		url      string
		checksum string
		limit    int64
	}{
		{name: "http status", url: server.URL + "/error", checksum: checksum, limit: 1024},
		{name: "checksum", url: server.URL + "/binary", checksum: strings.Repeat("0", 64), limit: 1024},
		{name: "size", url: server.URL + "/binary", checksum: checksum, limit: int64(len(payload) - 1)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if err := os.WriteFile(target, []byte("last-known-good"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := downloadVerifiedBinary(context.Background(), client, testCase.url, target, testCase.checksum, testCase.limit); err == nil {
				t.Fatal("unsafe binary download unexpectedly succeeded")
			}
			current, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(current) != "last-known-good" {
				t.Fatalf("failed download replaced target: %q", current)
			}
			temps, err := filepath.Glob(filepath.Join(dir, ".agent-*.new"))
			if err != nil {
				t.Fatal(err)
			}
			if len(temps) != 0 {
				t.Fatalf("partial downloads were not cleaned: %v", temps)
			}
		})
	}
}

func TestDownloadVerifiedBinaryForbidsRedirectAndDoesNotLeakSignedURLInError(t *testing.T) {
	payload := []byte("binary")
	digest := sha256.Sum256(payload)
	checksum := hex.EncodeToString(digest[:])
	var reached atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			reached.Store(true)
			_, _ = w.Write(payload)
			return
		}
		http.Redirect(w, r, "/target", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = binaryUpdateHTTPClient.CheckRedirect
	if err := downloadVerifiedBinary(context.Background(), client, server.URL+"/redirect", filepath.Join(t.TempDir(), "agent"), checksum, 1024); err == nil {
		t.Fatal("redirected binary download unexpectedly succeeded")
	}
	if reached.Load() {
		t.Fatal("binary updater followed a redirect")
	}

	secretURL := "https://downloads.example/agent?signature=top-secret"
	failingClient := &http.Client{Transport: updateRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network unavailable")
	})}
	err := downloadVerifiedBinary(context.Background(), failingClient, secretURL, filepath.Join(t.TempDir(), "agent"), checksum, 1024)
	if err == nil {
		t.Fatal("failed transport unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "top-secret") || strings.Contains(err.Error(), secretURL) {
		t.Fatalf("signed update URL leaked through error: %v", err)
	}
}

func TestBinaryUpdaterRejectsUntrustedTLSCertificate(t *testing.T) {
	payload := []byte("binary")
	digest := sha256.Sum256(payload)
	checksum := hex.EncodeToString(digest[:])
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	if err := downloadVerifiedBinary(context.Background(), binaryUpdateHTTPClient, server.URL, filepath.Join(t.TempDir(), "agent"), checksum, 1024); err == nil {
		t.Fatal("binary updater trusted a self-signed download certificate")
	}
}

type updateRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f updateRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

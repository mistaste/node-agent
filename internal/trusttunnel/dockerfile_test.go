package trusttunnel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerfileUsesBuildKitTargetArchitecture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	dockerfile := string(raw)
	if !strings.Contains(dockerfile, "ARG TARGETARCH\n") {
		t.Fatal("Dockerfile must consume BuildKit's TARGETARCH")
	}
	if strings.Contains(dockerfile, "ARG TARGETARCH=") {
		t.Fatal("Dockerfile must not override BuildKit's TARGETARCH")
	}
	raw, err = os.ReadFile(filepath.Join("..", "..", "ops", "build-trusttunnel-live-credentials.sh"))
	if err != nil {
		t.Fatal(err)
	}
	builder := string(raw)
	for _, mapping := range []string{"amd64) arch=x86_64", "arm64) arch=aarch64"} {
		if !strings.Contains(builder, mapping) {
			t.Fatalf("endpoint cross build missing %s", mapping)
		}
	}
	for _, pin := range []string{
		"adguard/core-libs@sha256:79273e6cfee10546af7edbb0122660b9e53e3380742181f5afbe068b212810c4",
		"fab5b8353a19332f935fa30869307d37d4a898d1",
		"git apply /patches/udp-rejection.patch /patches/live-credentials.patch",
	} {
		if !strings.Contains(dockerfile, pin) {
			t.Fatalf("missing reviewed endpoint build pin: %s", pin)
		}
	}
}

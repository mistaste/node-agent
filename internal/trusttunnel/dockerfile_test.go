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
	for _, architecture := range []string{"amd64", "arm64"} {
		if !strings.Contains(dockerfile, architecture+") tt_arch=") {
			t.Fatalf("Dockerfile does not pin the %s endpoint", architecture)
		}
	}
}

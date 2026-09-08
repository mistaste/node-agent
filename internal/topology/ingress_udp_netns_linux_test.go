//go:build linux

package topology

import (
	"context"
	_ "embed"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

//go:embed testdata/ingress_udp_netns.py
var ingressUDPNetNSTest string

// This opt-in packet test ALWAYS creates fresh anonymous network namespaces
// before touching networking. It does not attach to the host's network, install
// packages, write host network configuration, or contact any external address.
func TestIngressUDPReturnNetNS(t *testing.T) {
	if os.Getenv("GUARDEX_NFT_NETNS_TEST") != "1" {
		t.Skip("set GUARDEX_NFT_NETNS_TEST=1 on an isolated Linux test runner")
	}
	if os.Geteuid() != 0 {
		t.Fatal("network namespace integration test requires root/CAP_SYS_ADMIN")
	}
	for _, tool := range []string{"python3", "unshare", "nsenter", "ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required test tool %s is unavailable: %v", tool, err)
		}
	}
	rules, err := RenderNFTables(backboneState(RoleIngress))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-c", ingressUDPNetNSTest)
	input, err := json.Marshal(map[string]any{"rules": rules, "source_policy_args": ingressUDPSourceArgs("add", 65532, 18443)})
	if err != nil {
		t.Fatal(err)
	}
	command.Stdin = strings.NewReader(string(input))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated UDP return-path test failed: %v\n%s", err, output)
	}
	t.Log(string(output))
}

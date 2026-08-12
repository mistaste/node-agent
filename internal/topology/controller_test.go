package topology

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testServiceToken = "service-token-for-topology-tests"
const testNodeSecret = "0123456789abcdef0123456789abcdef"

func testController(t *testing.T, handler http.Handler) (*Controller, *recordingRunner) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	runner := &recordingRunner{}
	applier, err := NewApplier(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	applier.runner = runner
	controller, err := NewController(server.URL, testServiceToken, testNodeSecret, time.Minute, applier)
	if err != nil {
		t.Fatal(err)
	}
	controller.http = server.Client()
	return controller, runner
}

func requireNodeAuth(t *testing.T, request *http.Request) {
	t.Helper()
	if request.Header.Get("X-Service-Token") != testServiceToken ||
		request.Header.Get("X-Node-Secret") != testNodeSecret {
		t.Fatal("node topology request omitted controller credentials")
	}
}

func TestControllerCleansUnassignedNodeWithoutInvalidReport(t *testing.T) {
	var reports atomic.Int32
	controller, _ := testController(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requireNodeAuth(t, request)
		if request.Method == http.MethodPost {
			reports.Add(1)
		}
		_ = json.NewEncoder(response).Encode(DesiredState{SchemaVersion: 1, Revision: 1})
	}))
	if err := controller.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reports.Load() != 0 {
		t.Fatal("unassigned node emitted a role-less observed report")
	}
}

func TestControllerCleansUnassignedNodeAfterHigherStoredRevision(t *testing.T) {
	var reports atomic.Int32
	controller, runner := testController(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requireNodeAuth(t, request)
		if request.Method == http.MethodPost {
			reports.Add(1)
		}
		_ = json.NewEncoder(response).Encode(DesiredState{SchemaVersion: 1, Revision: 1})
	}))
	state := backboneState(RoleIngress)
	state.Revision = 8
	if err := controller.applier.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	runner.commands = nil
	if err := controller.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reports.Load() != 0 {
		t.Fatal("unassigned node emitted a role-less observed report")
	}
	removed := false
	for _, command := range runner.commands {
		if command.name == "ip" && strings.Join(command.args, " ") == "link del dev gxwg0" {
			removed = true
		}
	}
	if !removed {
		t.Fatalf("higher-revision live topology survived unassignment: %#v", runner.commands)
	}
}

func TestControllerReportsAppliedRelayRevision(t *testing.T) {
	state := DesiredState{SchemaVersion: 1, Revision: 7, Role: RoleRelay, Enabled: true, Relay: &Relay{IngressAddress: netip.MustParseAddr("93.184.216.34"), IngressPort: 443, TCPEnabled: true}}
	var reported NodeReport
	controller, _ := testController(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requireNodeAuth(t, request)
		if request.Method == http.MethodGet {
			_ = json.NewEncoder(response).Encode(state)
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&reported); err != nil {
			t.Fatal(err)
		}
		response.WriteHeader(http.StatusOK)
	}))
	if err := controller.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reported.Role != string(RoleRelay) || reported.ObservedRevision != 7 || reported.Status != "applied" {
		t.Fatalf("unexpected observed report: %+v", reported)
	}
}

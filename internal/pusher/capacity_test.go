package pusher

import "testing"

func TestDetectedLinkCapacityPrefersExplicitOverride(t *testing.T) {
	if got := detectedLinkCapacity(1000, 10000); got != 1000 {
		t.Fatalf("got %d", got)
	}
	if got := detectedLinkCapacity(0, 2500); got != 2500 {
		t.Fatalf("got %d", got)
	}
	if got := detectedLinkCapacity(0, 0); got != 0 {
		t.Fatalf("got %d", got)
	}
}

package xray

import "runtime/debug"

const linkedControlPlaneFallback = "v1.260327.0"

// ControlPlaneVersion is the xray-core module linked into the agent's dynamic
// HandlerService config builder. Runtime core version is separately configured
// because Xray's HandlerService does not expose a version RPC.
func ControlPlaneVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return linkedControlPlaneFallback
	}
	for _, dependency := range info.Deps {
		if dependency.Path == "github.com/xtls/xray-core" {
			return dependency.Version
		}
	}
	// Go 1.26 may omit dependency metadata from stripped/static binaries. Keep
	// this fallback in lockstep with go.mod so health remains operationally useful.
	return linkedControlPlaneFallback
}

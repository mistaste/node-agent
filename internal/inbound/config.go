package inbound

import (
	"errors"

	"regexp"
	"strings"
)

var clientIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const MaxConfigBytes = 1 << 20

var tagPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func ValidateIdentity(tag string, port int) error {
	if !tagPattern.MatchString(tag) {
		return errors.New("tag must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")
	}
	if port < 1 || port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

func ValidateClientID(value string) error {
	if !clientIDPattern.MatchString(strings.ToLower(strings.TrimSpace(value))) {
		return errors.New("client id must be a canonical UUID")
	}
	return nil
}

// IsControllerManagedTag confines the pull control-plane to a namespace which
// can never overlap the static baseline or an operator-created legacy handler.
// The backend enforces the same prefixes, but the node remains the final trust
// boundary before a native runtime mutation.
func IsControllerManagedTag(tag string) bool {
	tag = strings.TrimSpace(tag)
	return strings.HasPrefix(tag, "gx-")
}

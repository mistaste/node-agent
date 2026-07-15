// Package inbound defines the only dynamic Xray inbound shape accepted by the
// node agent. Keeping validation here makes both the HTTP API and a future
// desired-manifest pull reconciler use the same, deliberately small surface.
package inbound

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

const MaxConfigBytes = 1 << 20

var tagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

var allowedNetworks = map[string]struct{}{
	"tcp":         {},
	"raw":         {},
	"xhttp":       {},
	"grpc":        {},
	"websocket":   {},
	"ws":          {},
	"httpupgrade": {},
}

var allowedSecurities = map[string]struct{}{
	"reality": {},
	"tls":     {},
}

// Config is a validated, canonical dynamic inbound. Raw contains the complete
// server-side Xray config, including credentials required to restore it after a
// restart. Raw must therefore only be persisted in a mode-0600 store and must
// never be returned by an API response.
type Config struct {
	Tag      string
	Port     int
	Protocol string
	Network  string
	Security string
	Raw      json.RawMessage
	Digest   string
}

// PublicConfig is safe to expose to the controller. It intentionally contains
// no Xray settings or key material.
type PublicConfig struct {
	Tag      string `json:"tag"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Network  string `json:"network"`
	Security string `json:"security"`
	Digest   string `json:"runtime_digest"`
}

func (c Config) Public() PublicConfig {
	return PublicConfig{
		Tag:      c.Tag,
		Port:     c.Port,
		Protocol: c.Protocol,
		Network:  c.Network,
		Security: c.Security,
		Digest:   c.Digest,
	}
}

func (c Config) Clone() Config {
	c.Raw = append(json.RawMessage(nil), c.Raw...)
	return c
}

// ValidateIdentity applies the same listener identity policy used by Parse.
// Controller tombstones do not contain a full Xray document, so they use this
// helper before attempting a managed deletion.
func ValidateIdentity(tag string, port int) error {
	if !tagPattern.MatchString(tag) {
		return errors.New("tag must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")
	}
	if port < 1 || port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

// IsControllerManagedTag confines the pull control-plane to a namespace which
// can never overlap the static baseline or an operator-created legacy handler.
// The backend enforces the same prefixes, but the node remains the final trust
// boundary before an Xray runtime mutation.
func IsControllerManagedTag(tag string) bool {
	tag = strings.TrimSpace(tag)
	return strings.HasPrefix(tag, "gx-")
}

type inboundDocument struct {
	Tag            string          `json:"tag"`
	Port           int             `json:"port"`
	Listen         json.RawMessage `json:"listen,omitempty"`
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings json.RawMessage `json:"streamSettings"`
	Sniffing       json.RawMessage `json:"sniffing,omitempty"`
}

type streamDocument struct {
	Address             json.RawMessage `json:"address,omitempty"`
	Port                json.RawMessage `json:"port,omitempty"`
	Network             string          `json:"network"`
	Security            string          `json:"security"`
	FinalMask           json.RawMessage `json:"finalmask,omitempty"`
	TLSSettings         json.RawMessage `json:"tlsSettings,omitempty"`
	RealitySettings     json.RawMessage `json:"realitySettings,omitempty"`
	RawSettings         json.RawMessage `json:"rawSettings,omitempty"`
	TCPSettings         json.RawMessage `json:"tcpSettings,omitempty"`
	XHTTPSettings       json.RawMessage `json:"xhttpSettings,omitempty"`
	SplitHTTPSettings   json.RawMessage `json:"splithttpSettings,omitempty"`
	GRPCSettings        json.RawMessage `json:"grpcSettings,omitempty"`
	WebSocketSettings   json.RawMessage `json:"wsSettings,omitempty"`
	HTTPUpgradeSettings json.RawMessage `json:"httpupgradeSettings,omitempty"`
	SocketSettings      json.RawMessage `json:"sockopt,omitempty"`
}

type vlessSettings struct {
	Decryption string `json:"decryption"`
}

type realitySettings struct {
	PrivateKey string   `json:"privateKey"`
	ShortIDs   []string `json:"shortIds"`
}

// Parse validates an inbound and returns a deterministic JSON representation.
// Unknown top-level/stream fields are rejected so an authenticated controller
// still cannot smuggle an unreviewed transport into Xray.
func Parse(raw []byte) (Config, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return Config{}, errors.New("empty inbound config")
	}
	if len(raw) > MaxConfigBytes {
		return Config{}, fmt.Errorf("inbound config exceeds %d bytes", MaxConfigBytes)
	}

	var doc inboundDocument
	if err := decodeStrict(raw, &doc); err != nil {
		return Config{}, fmt.Errorf("invalid inbound config: %w", err)
	}
	if err := ValidateIdentity(doc.Tag, doc.Port); err != nil {
		return Config{}, err
	}
	if doc.Protocol != "vless" {
		return Config{}, errors.New("only the vless protocol is supported")
	}
	if len(doc.Settings) == 0 || bytes.Equal(bytes.TrimSpace(doc.Settings), []byte("null")) {
		return Config{}, errors.New("vless settings are required")
	}
	var settings vlessSettings
	if err := json.Unmarshal(doc.Settings, &settings); err != nil {
		return Config{}, fmt.Errorf("invalid vless settings: %w", err)
	}
	if settings.Decryption != "" && settings.Decryption != "none" {
		return Config{}, errors.New("vless decryption must be none")
	}

	if len(doc.StreamSettings) == 0 || bytes.Equal(bytes.TrimSpace(doc.StreamSettings), []byte("null")) {
		return Config{}, errors.New("streamSettings are required")
	}
	var stream streamDocument
	if err := decodeStrict(doc.StreamSettings, &stream); err != nil {
		return Config{}, fmt.Errorf("invalid streamSettings: %w", err)
	}
	network := strings.ToLower(strings.TrimSpace(stream.Network))
	security := strings.ToLower(strings.TrimSpace(stream.Security))
	if network != stream.Network || security != stream.Security {
		return Config{}, errors.New("stream network and security must use lowercase canonical names")
	}
	stream.Network = network
	stream.Security = security
	if _, ok := allowedNetworks[stream.Network]; !ok {
		return Config{}, fmt.Errorf("unsupported stream network %q", stream.Network)
	}
	if _, ok := allowedSecurities[stream.Security]; !ok {
		return Config{}, fmt.Errorf("unsupported stream security %q", stream.Security)
	}
	if stream.Security == "reality" {
		switch stream.Network {
		case "tcp", "raw", "xhttp", "grpc":
		default:
			return Config{}, fmt.Errorf("reality is not supported with %s", stream.Network)
		}
		if len(stream.RealitySettings) == 0 || bytes.Equal(bytes.TrimSpace(stream.RealitySettings), []byte("null")) {
			return Config{}, errors.New("realitySettings are required for reality security")
		}
		if !isJSONObject(stream.RealitySettings) {
			return Config{}, errors.New("realitySettings must be an object")
		}
		var credentials realitySettings
		if err := json.Unmarshal(stream.RealitySettings, &credentials); err != nil {
			return Config{}, fmt.Errorf("invalid reality credentials: %w", err)
		}
		if credentials.PrivateKey != "" {
			decoded, err := base64.RawURLEncoding.DecodeString(credentials.PrivateKey)
			if err != nil || len(decoded) != 32 {
				return Config{}, errors.New("reality privateKey must be a base64url-encoded X25519 key")
			}
		}
		for _, shortID := range credentials.ShortIDs {
			if len(shortID) > 16 || len(shortID)%2 != 0 || !isHex(shortID) {
				return Config{}, errors.New("reality shortIds must contain even-length hexadecimal values up to 16 characters")
			}
		}
	}
	if stream.Security == "tls" && len(stream.TLSSettings) > 0 && !isJSONObject(stream.TLSSettings) {
		return Config{}, errors.New("tlsSettings must be an object")
	}

	canonical, err := canonicalJSON(raw)
	if err != nil {
		return Config{}, fmt.Errorf("canonicalize inbound config: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return Config{
		Tag:      doc.Tag,
		Port:     doc.Port,
		Protocol: doc.Protocol,
		Network:  stream.Network,
		Security: stream.Security,
		Raw:      canonical,
		Digest:   hex.EncodeToString(sum[:]),
	}, nil
}

func isHex(value string) bool {
	for _, character := range value {
		if !((character >= '0' && character <= '9') ||
			(character >= 'a' && character <= 'f') ||
			(character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

func decodeStrict(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func isJSONObject(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

func canonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func SupportedNetworks() []string {
	out := make([]string, 0, len(allowedNetworks))
	for value := range allowedNetworks {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func SupportedSecurities() []string {
	out := make([]string, 0, len(allowedSecurities))
	for value := range allowedSecurities {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

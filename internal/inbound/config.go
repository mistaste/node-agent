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
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	MaxConfigBytes        = 1 << 20
	DefaultManagedTLSRoot = "/etc/guardex/tls"
)

var tagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var clientIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Keep this in sync with the backend catalogue validator. Xray supports a
// broader custom-path syntax, but managed profiles deliberately use a simple
// service identifier so it is safe to carry through URI/query parameters and
// every supported client implementation.
var grpcServiceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`)
var hysteriaDNSLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

var allowedNetworks = map[string]struct{}{
	"tcp":         {},
	"raw":         {},
	"xhttp":       {},
	"grpc":        {},
	"hysteria":    {},
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

func ValidateClientID(value string) error {
	if !clientIDPattern.MatchString(strings.ToLower(strings.TrimSpace(value))) {
		return errors.New("client id must be a canonical UUID")
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
	HysteriaSettings    json.RawMessage `json:"hysteriaSettings,omitempty"`
	WebSocketSettings   json.RawMessage `json:"wsSettings,omitempty"`
	HTTPUpgradeSettings json.RawMessage `json:"httpupgradeSettings,omitempty"`
	SocketSettings      json.RawMessage `json:"sockopt,omitempty"`
}

type vlessSettings struct {
	Decryption string `json:"decryption"`
}

type hysteriaServerSettings struct {
	Version int32                `json:"version"`
	Clients []hysteriaServerUser `json:"clients"`
}

type hysteriaServerUser struct {
	Auth  string `json:"auth"`
	Level uint32 `json:"level"`
	Email string `json:"email"`
}

type realitySettings struct {
	PrivateKey string   `json:"privateKey"`
	ShortIDs   []string `json:"shortIds"`
}

// grpcSettings mirrors the JSON fields understood by the linked Xray config
// builder. decodeStrict below prevents controller manifests from smuggling
// unknown transport options past the node trust boundary.
type grpcSettings struct {
	Authority           string `json:"authority"`
	ServiceName         string `json:"serviceName"`
	MultiMode           bool   `json:"multiMode"`
	IdleTimeout         int32  `json:"idle_timeout"`
	HealthCheckTimeout  int32  `json:"health_check_timeout"`
	PermitWithoutStream bool   `json:"permit_without_stream"`
	InitialWindowsSize  int32  `json:"initial_windows_size"`
	UserAgent           string `json:"user_agent"`
}

type managedTLSSettings struct {
	ServerName       string                  `json:"serverName"`
	RejectUnknownSNI bool                    `json:"rejectUnknownSni"`
	ALPN             []string                `json:"alpn"`
	MinVersion       string                  `json:"minVersion"`
	MaxVersion       string                  `json:"maxVersion"`
	Fingerprint      string                  `json:"fingerprint"`
	Certificates     []managedTLSCertificate `json:"certificates"`
}

type managedTLSCertificate struct {
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
	Usage           string `json:"usage"`
	OneTimeLoading  bool   `json:"oneTimeLoading"`
	BuildChain      bool   `json:"buildChain"`
}

type hysteriaTransportSettings struct {
	Version        int32              `json:"version"`
	Auth           string             `json:"auth"`
	UDPIdleTimeout int64              `json:"udpIdleTimeout"`
	Masquerade     hysteriaMasquerade `json:"masquerade"`
}

type hysteriaMasquerade struct {
	Type        string            `json:"type"`
	Dir         string            `json:"dir"`
	URL         string            `json:"url"`
	RewriteHost bool              `json:"rewriteHost"`
	Insecure    bool              `json:"insecure"`
	Content     string            `json:"content"`
	Headers     map[string]string `json:"headers"`
	StatusCode  int32             `json:"statusCode"`
}

type managedFinalMask struct {
	UDP        []managedMask      `json:"udp"`
	QuicParams *managedQuicParams `json:"quicParams"`
}

type managedMask struct {
	Type     string                  `json:"type"`
	Settings managedSalamanderConfig `json:"settings"`
}

type managedSalamanderConfig struct {
	Password string `json:"password"`
}

type managedQuicParams struct {
	Congestion string         `json:"congestion"`
	UDPHop     *managedUDPHop `json:"udpHop"`
}

type managedUDPHop struct {
	Ports    json.RawMessage `json:"ports"`
	Interval json.RawMessage `json:"interval"`
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
	if doc.Protocol != "vless" && doc.Protocol != "hysteria" {
		return Config{}, errors.New("only the vless and hysteria protocols are supported")
	}
	if len(doc.Settings) == 0 || bytes.Equal(bytes.TrimSpace(doc.Settings), []byte("null")) {
		return Config{}, errors.New("protocol settings are required")
	}
	if doc.Protocol == "vless" {
		var settings vlessSettings
		if err := json.Unmarshal(doc.Settings, &settings); err != nil {
			return Config{}, fmt.Errorf("invalid vless settings: %w", err)
		}
		if settings.Decryption != "" && settings.Decryption != "none" {
			return Config{}, errors.New("vless decryption must be none")
		}
	} else {
		var settings hysteriaServerSettings
		if err := decodeStrict(doc.Settings, &settings); err != nil {
			return Config{}, fmt.Errorf("invalid hysteria settings: %w", err)
		}
		if settings.Version != 2 {
			return Config{}, errors.New("hysteria protocol version must be 2")
		}
		for _, user := range settings.Clients {
			if strings.TrimSpace(user.Auth) == "" || len(user.Auth) > 256 {
				return Config{}, errors.New("hysteria client auth must be 1-256 characters")
			}
			if len(user.Email) > 320 || strings.ContainsAny(user.Email, "\r\n\x00") {
				return Config{}, errors.New("hysteria client email is invalid")
			}
		}
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
	if doc.Protocol == "hysteria" && (stream.Network != "hysteria" || stream.Security != "tls") {
		return Config{}, errors.New("hysteria protocol requires hysteria transport with tls")
	}
	if doc.Protocol == "vless" && stream.Network == "hysteria" {
		return Config{}, errors.New("managed hysteria transport requires the hysteria protocol")
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
	if doc.Protocol == "hysteria" {
		if err := validateManagedHysteria(doc.Tag, doc.Port, stream); err != nil {
			return Config{}, err
		}
	}
	if stream.Network == "grpc" {
		if len(stream.GRPCSettings) == 0 || bytes.Equal(bytes.TrimSpace(stream.GRPCSettings), []byte("null")) {
			return Config{}, errors.New("grpcSettings are required for grpc transport")
		}
		if !isJSONObject(stream.GRPCSettings) {
			return Config{}, errors.New("grpcSettings must be an object")
		}
		var settings grpcSettings
		if err := decodeStrict(stream.GRPCSettings, &settings); err != nil {
			return Config{}, fmt.Errorf("invalid grpcSettings: %w", err)
		}
		if !grpcServiceNamePattern.MatchString(settings.ServiceName) {
			return Config{}, errors.New("grpc serviceName must be 1-128 letters, digits, dots, underscores, tildes or hyphens")
		}
		if settings.IdleTimeout < 0 || settings.HealthCheckTimeout < 0 || settings.InitialWindowsSize < 0 {
			return Config{}, errors.New("grpc timeout and window settings must not be negative")
		}
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

func validateManagedHysteria(tag string, listenerPort int, stream streamDocument) error {
	if len(stream.TLSSettings) == 0 || bytes.Equal(bytes.TrimSpace(stream.TLSSettings), []byte("null")) {
		return errors.New("tlsSettings are required for managed hysteria")
	}
	var tlsSettings managedTLSSettings
	if err := decodeStrict(stream.TLSSettings, &tlsSettings); err != nil {
		return fmt.Errorf("invalid managed hysteria tlsSettings: %w", err)
	}
	if !validHysteriaServerName(tlsSettings.ServerName) {
		return errors.New("hysteria tls serverName is invalid")
	}
	if len(tlsSettings.ALPN) != 1 || tlsSettings.ALPN[0] != "h3" {
		return errors.New("hysteria tls ALPN must be exactly h3")
	}
	if tlsSettings.MinVersion != "1.3" || tlsSettings.MaxVersion != "1.3" {
		return errors.New("managed hysteria requires TLS 1.3 only")
	}
	if tlsSettings.Fingerprint != "" && tlsSettings.Fingerprint != "chrome" {
		return errors.New("managed hysteria tls fingerprint must be chrome when specified")
	}
	if len(tlsSettings.Certificates) != 1 {
		return errors.New("managed hysteria requires exactly one node-local certificate reference")
	}
	expectedCert, expectedKey := ManagedTLSPaths(tag)
	certificate := tlsSettings.Certificates[0]
	if filepath.Clean(certificate.CertificateFile) != expectedCert || filepath.Clean(certificate.KeyFile) != expectedKey {
		return errors.New("managed hysteria certificate paths do not match the node-local tag contract")
	}
	if certificate.Usage != "" && certificate.Usage != "encipherment" {
		return errors.New("managed hysteria certificate usage must be encipherment")
	}
	if certificate.OneTimeLoading {
		return errors.New("managed hysteria certificates must support file renewal reloads")
	}
	if certificate.BuildChain {
		return errors.New("managed hysteria uses the exact node-local leaf certificate without automatic chain building")
	}

	if len(stream.HysteriaSettings) == 0 || !isJSONObject(stream.HysteriaSettings) {
		return errors.New("hysteriaSettings are required for hysteria transport")
	}
	var hysteriaSettings hysteriaTransportSettings
	if err := decodeStrict(stream.HysteriaSettings, &hysteriaSettings); err != nil {
		return fmt.Errorf("invalid hysteriaSettings: %w", err)
	}
	if hysteriaSettings.Version != 2 {
		return errors.New("hysteria transport version must be 2")
	}
	if hysteriaSettings.Auth != "" {
		return errors.New("managed hysteria uses per-user auth, not a shared transport auth")
	}
	if hysteriaSettings.UDPIdleTimeout != 0 && (hysteriaSettings.UDPIdleTimeout < 2 || hysteriaSettings.UDPIdleTimeout > 600) {
		return errors.New("hysteria udpIdleTimeout must be between 2 and 600 seconds")
	}
	if err := validateMasquerade(hysteriaSettings.Masquerade); err != nil {
		return err
	}

	if len(stream.FinalMask) == 0 || !isJSONObject(stream.FinalMask) {
		return errors.New("managed hysteria requires a salamander finalmask")
	}
	var finalMask managedFinalMask
	if err := decodeStrict(stream.FinalMask, &finalMask); err != nil {
		return fmt.Errorf("invalid managed hysteria finalmask: %w", err)
	}
	if len(finalMask.UDP) != 1 || finalMask.UDP[0].Type != "salamander" {
		return errors.New("managed hysteria finalmask must contain exactly one UDP salamander mask")
	}
	password := finalMask.UDP[0].Settings.Password
	if password != "" && !validSalamanderPassword(password) {
		return errors.New("managed hysteria salamander password is invalid")
	}
	if finalMask.QuicParams != nil {
		switch finalMask.QuicParams.Congestion {
		case "", "bbr", "brutal", "reno":
		default:
			return errors.New("managed hysteria congestion must be bbr, brutal or reno")
		}
		if finalMask.QuicParams.UDPHop != nil {
			ports, expanded, err := parsePortList(finalMask.QuicParams.UDPHop.Ports)
			if err != nil {
				return fmt.Errorf("invalid hysteria udpHop ports: %w", err)
			}
			if _, _, err := parseRange(finalMask.QuicParams.UDPHop.Interval, 5, 3600); err != nil {
				return fmt.Errorf("invalid hysteria udpHop interval: %w", err)
			}
			if ports == "" || !containsInt(expanded, listenerPort) {
				return errors.New("hysteria udpHop ports must include the effective listener port")
			}
		}
	}
	return nil
}

func validSalamanderPassword(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validHysteriaServerName(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 253 || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	for _, label := range strings.Split(value, ".") {
		if !hysteriaDNSLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func validateMasquerade(value hysteriaMasquerade) error {
	switch value.Type {
	case "":
		if value.Dir != "" || value.URL != "" || value.Content != "" || value.StatusCode != 0 || len(value.Headers) != 0 || value.RewriteHost || value.Insecure {
			return errors.New("empty hysteria masquerade type must not include settings")
		}
	case "string":
		if value.Dir != "" || value.URL != "" || value.RewriteHost || value.Insecure || len(value.Content) > 16*1024 {
			return errors.New("managed hysteria string masquerade is invalid")
		}
		if value.StatusCode < 200 || value.StatusCode > 599 {
			return errors.New("managed hysteria masquerade statusCode must be 200-599")
		}
		for key, headerValue := range value.Headers {
			if key == "" || len(key) > 128 || len(headerValue) > 1024 || strings.ContainsAny(key+headerValue, "\r\n\x00") {
				return errors.New("managed hysteria masquerade headers are invalid")
			}
		}
	default:
		return errors.New("managed hysteria masquerade supports only the default 404 or an inline string")
	}
	return nil
}

// ManagedTLSPaths is the only filesystem contract accepted from the
// controller. Private key bytes never appear in a desired manifest.
func ManagedTLSPaths(tag string) (certificateFile, keyFile string) {
	dir := filepath.Join(ManagedTLSRoot(), tag)
	return filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
}

// ManagedTLSRoot is configurable only by the node operator. The controller can
// reference files under this root but cannot choose an arbitrary filesystem
// location. Tests use the override to avoid host-level writes.
func ManagedTLSRoot() string {
	root := strings.TrimSpace(os.Getenv("HYSTERIA_TLS_DIR"))
	if root == "" || !filepath.IsAbs(root) {
		return DefaultManagedTLSRoot
	}
	return filepath.Clean(root)
}

func parsePortList(raw json.RawMessage) (string, []int, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", nil, errors.New("ports are required")
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		var number int
		if err := json.Unmarshal(raw, &number); err != nil {
			return "", nil, errors.New("ports must be an integer or comma-separated ranges")
		}
		text = strconv.Itoa(number)
	}
	parts := strings.Split(text, ",")
	canonical := make([]string, 0, len(parts))
	expanded := make([]int, 0)
	seen := make(map[int]struct{})
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || strings.Contains(part, "env:") {
			return "", nil, errors.New("empty and environment-derived port ranges are not allowed")
		}
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return "", nil, errors.New("invalid port range")
		}
		from, err := strconv.Atoi(bounds[0])
		if err != nil || from < 1 || from > 65535 {
			return "", nil, errors.New("port must be between 1 and 65535")
		}
		to := from
		if len(bounds) == 2 {
			to, err = strconv.Atoi(bounds[1])
			if err != nil || to < from || to > 65535 {
				return "", nil, errors.New("invalid ascending port range")
			}
		}
		if len(expanded)+(to-from+1) > 512 {
			return "", nil, errors.New("udpHop expands to more than 512 ports")
		}
		if from == to {
			canonical = append(canonical, strconv.Itoa(from))
		} else {
			canonical = append(canonical, fmt.Sprintf("%d-%d", from, to))
		}
		for port := from; port <= to; port++ {
			if _, ok := seen[port]; !ok {
				seen[port] = struct{}{}
				expanded = append(expanded, port)
			}
		}
	}
	return strings.Join(canonical, ","), expanded, nil
}

func parseRange(raw json.RawMessage, minimum, maximum int) (int, int, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return 0, 0, errors.New("range is required")
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		var number int
		if err := json.Unmarshal(raw, &number); err != nil {
			return 0, 0, errors.New("range must be an integer or from-to string")
		}
		text = strconv.Itoa(number)
	}
	bounds := strings.Split(strings.TrimSpace(text), "-")
	if len(bounds) < 1 || len(bounds) > 2 {
		return 0, 0, errors.New("invalid range")
	}
	from, err := strconv.Atoi(bounds[0])
	if err != nil {
		return 0, 0, errors.New("invalid range start")
	}
	to := from
	if len(bounds) == 2 {
		to, err = strconv.Atoi(bounds[1])
		if err != nil {
			return 0, 0, errors.New("invalid range end")
		}
	}
	if from > to || from < minimum || to > maximum {
		return 0, 0, fmt.Errorf("range must be ascending between %d and %d", minimum, maximum)
	}
	return from, to, nil
}

func containsInt(values []int, wanted int) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
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

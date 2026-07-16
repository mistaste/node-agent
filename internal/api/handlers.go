package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/inbound"
	"github.com/guardex/node-agent/internal/inboundsync"
	"github.com/guardex/node-agent/internal/metrics"
	"github.com/guardex/node-agent/internal/store"
	"github.com/guardex/node-agent/internal/userops"
	"github.com/guardex/node-agent/internal/xray"
)

type handlers struct {
	cfg       *config.Config
	xray      *xray.Client
	collector *metrics.Collector
	store     *store.Store
	inbounds  *inboundsync.Manager
	userOps   *userops.Coordinator
	userCore  userRuntime
}

type userRuntime interface {
	AddUser(context.Context, xray.AddUserParams) error
	RemoveUser(context.Context, string, string) error
}

func (h *handlers) health(w http.ResponseWriter, r *http.Request) {
	items := h.inbounds.Inventory()
	applied := 0
	for _, item := range items {
		if item.Applied {
			applied++
		}
	}
	status := "ok"
	if applied != len(items) {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  status,
		"version": h.cfg.AgentVersion(),
		"xray": map[string]string{
			"configured_core_version": h.cfg.XrayCoreVersion,
			"control_plane_version":   xray.ControlPlaneVersion(),
		},
		"dynamic_inbounds": map[string]int{
			"desired":  len(items),
			"applied":  applied,
			"degraded": len(items) - applied,
		},
		"capabilities": inboundCapabilities(h.cfg),
	})
}

func (h *handlers) getMetrics(w http.ResponseWriter, r *http.Request) {
	snap := h.collector.Latest()
	if snap == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "not ready yet"})
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

type addUserRequest struct {
	UUID       string `json:"uuid"`
	Flow       string `json:"flow"`
	Level      uint32 `json:"level"`
	InboundTag string `json:"inbound_tag"`
}

func (h *handlers) addUser(w http.ResponseWriter, r *http.Request) {
	var req addUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if req.UUID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "uuid required"})
		return
	}
	if req.InboundTag == "" {
		req.InboundTag = h.cfg.DefaultInboundTag
	}
	h.userOps.Lock()
	defer h.userOps.Unlock()
	if h.inbounds != nil {
		if managed, ok := h.inbounds.ManagedConfig(req.InboundTag); ok &&
			(managed.Network == "xhttp" || managed.Network == "grpc") && strings.TrimSpace(req.Flow) != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": strings.ToUpper(managed.Network) + " inbounds must not use a VLESS flow"})
			return
		}
	}

	err := h.runtimeUsers().AddUser(r.Context(), xray.AddUserParams{
		InboundTag: req.InboundTag,
		UUID:       req.UUID,
		Flow:       req.Flow,
		Level:      req.Level,
	})
	if err != nil && !xray.IsAlreadyExists(err) {
		log.Printf("[api] addUser runtime operation failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Persist so the user survives an Xray restart (re-applied by the syncer).
	if h.store != nil {
		if serr := h.store.Add(store.User{
			UUID:       req.UUID,
			InboundTag: req.InboundTag,
			Flow:       req.Flow,
			Level:      req.Level,
		}); serr != nil {
			log.Printf("[api] addUser persist error: %v", serr)
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "added", "uuid": req.UUID})
}

func (h *handlers) removeUser(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	if uuid == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "uuid required"})
		return
	}

	inboundTag := r.URL.Query().Get("inbound_tag")
	if inboundTag == "" {
		inboundTag = h.cfg.DefaultInboundTag
	}
	h.userOps.Lock()
	defer h.userOps.Unlock()

	err := h.runtimeUsers().RemoveUser(r.Context(), inboundTag, uuid)
	if err != nil && !xray.IsNotFound(err) {
		log.Printf("[api] removeUser runtime operation failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Drop from the durable store so it is not re-applied by the syncer.
	if h.store != nil {
		if serr := h.store.Remove(inboundTag, uuid); serr != nil {
			log.Printf("[api] removeUser persist error: %v", serr)
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed", "uuid": uuid})
}

func (h *handlers) runtimeUsers() userRuntime {
	if h.userCore != nil {
		return h.userCore
	}
	return h.xray
}

func (h *handlers) addInbound(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, inbound.MaxConfigBytes+1))
	if err != nil || len(body) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty body"})
		return
	}
	if len(body) > inbound.MaxConfigBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "inbound config too large"})
		return
	}
	cfg, err := inbound.Parse(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	desiredDigest := cfg.Digest
	h.userOps.Lock()
	defer h.userOps.Unlock()

	var previous []byte
	if managed, ok := h.inbounds.ManagedConfig(cfg.Tag); ok {
		previous = managed.Raw
	}
	patched, publicKey, shortID, err := xray.EnsureRealityKey(cfg.Raw, previous)
	if err != nil {
		log.Printf("[api] prepare inbound %q: %v", cfg.Tag, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid Reality settings"})
		return
	}
	cfg, err = inbound.Parse(patched)
	if err != nil {
		log.Printf("[api] validate prepared inbound %q: %v", cfg.Tag, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid prepared inbound"})
		return
	}
	if err := h.inbounds.ApplyDesired(r.Context(), cfg, desiredDigest); err != nil {
		log.Printf("[api] apply inbound %q: %v", cfg.Tag, err)
		if errors.Is(err, inboundsync.ErrTagConflict) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "inbound tag is already owned by a static or unmanaged config"})
			return
		}
		if errors.Is(err, inboundsync.ErrControllerOwned) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "inbound tag is managed by controller polling"})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "node could not apply the inbound"})
		return
	}
	log.Printf("[api] dynamic inbound %q applied", cfg.Tag)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "applied",
		"inbound":        cfg.Public(),
		"desired_digest": desiredDigest,
		"public_key":     publicKey,
		"short_id":       shortID,
	})
}

func (h *handlers) listInbounds(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"inbounds":     h.inbounds.Inventory(),
		"capabilities": inboundCapabilities(h.cfg),
	})
}

func (h *handlers) removeInbound(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	if tag == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tag required"})
		return
	}
	h.userOps.Lock()
	defer h.userOps.Unlock()
	if err := h.inbounds.Remove(r.Context(), tag); err != nil {
		log.Printf("[api] removeInbound %q: %v", tag, err)
		if errors.Is(err, inboundsync.ErrNotManaged) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "dynamic inbound not found"})
			return
		}
		if errors.Is(err, inboundsync.ErrControllerOwned) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "inbound tag is managed by controller polling"})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "node could not remove the inbound"})
		return
	}
	if h.store != nil {
		if err := h.store.RemoveByInboundTag(tag); err != nil {
			log.Printf("[api] removeInbound durable user cleanup failed")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "durable user cleanup failed"})
			return
		}
	}
	log.Printf("[api] dynamic inbound %q removed", tag)
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed", "tag": tag})
}

func inboundCapabilities(cfg *config.Config) map[string]any {
	return map[string]any{
		"protocols":                []string{"vless"},
		"stream_networks":          []string{"raw", "xhttp", "grpc"},
		"stream_securities":        []string{"reality"},
		"controller_tag_namespace": "gx-",
		"durable_inventory":        true,
		"startup_reconciliation":   true,
		"desired_manifest_store":   true,
		"controller_polling":       cfg != nil && cfg.ControllerPollingEnabled(),
		"static_inbounds_managed":  false,
	}
}

type updateRequest struct {
	Mode   string `json:"mode"`
	URL    string `json:"url"`
	Ref    string `json:"ref"`
	SHA256 string `json:"sha256"`
}

var safeGitRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)

const (
	maxBinaryUpdateBytes = int64(256 << 20)
	binaryUpdateTimeout  = 2 * time.Minute
)

var binaryUpdateHTTPClient = &http.Client{
	Timeout: binaryUpdateTimeout,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func (h *handlers) updateXray(w http.ResponseWriter, r *http.Request) {
	var req updateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	updateURL, checksum, err := validateBinaryUpdate(req.URL, req.SHA256)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	go func() {
		if err := replaceAndRestart(updateURL, "/usr/local/bin/xray", "xray", checksum); err != nil {
			log.Printf("[update] xray update error: %v", err)
		} else {
			log.Printf("[update] xray updated successfully")
		}
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "update started"})
}

func (h *handlers) updateAgent(w http.ResponseWriter, r *http.Request) {
	var req updateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}

	mode := req.Mode
	if mode == "" {
		mode = "git"
	}
	if req.Ref == "" {
		req.Ref = h.cfg.UpdateRef
	}

	if mode == "git" || mode == "git-full" {
		parts, err := agentUpdateParts(mode, req.Ref)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid update mode or ref"})
			return
		}
		go func() {
			if err := runDetachedComposeHelper(h.cfg.RepoDir, parts); err != nil {
				log.Printf("[update] agent git update error: %v", err)
			}
		}()
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "update started", "mode": mode})
		return
	}

	if mode != "binary" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported update mode"})
		return
	}
	updateURL, checksum, validateErr := validateBinaryUpdate(req.URL, req.SHA256)
	if validateErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": validateErr.Error()})
		return
	}
	self, err := os.Executable()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot resolve self path"})
		return
	}

	go func() {
		if err := replaceAndRestart(updateURL, self, "agent", checksum); err != nil {
			log.Printf("[update] agent update error: %v", err)
		}
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "update started"})
}

func validateBinaryUpdate(rawURL, rawChecksum string) (string, string, error) {
	rawURL = strings.TrimSpace(rawURL)
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", "", errors.New("binary update URL must use HTTPS without credentials or a fragment")
	}
	checksum := strings.ToLower(strings.TrimSpace(rawChecksum))
	decoded, err := hex.DecodeString(checksum)
	if err != nil || len(decoded) != sha256.Size {
		return "", "", errors.New("binary update requires a valid SHA-256 checksum")
	}
	return parsed.String(), checksum, nil
}

func agentUpdateParts(mode, ref string) ([]string, error) {
	if mode != "git" && mode != "git-full" {
		return nil, errors.New("unsupported git update mode")
	}
	if !safeGitRef.MatchString(ref) || strings.Contains(ref, "..") || strings.Contains(ref, "//") || strings.HasSuffix(ref, "/") {
		return nil, errors.New("unsafe git ref")
	}
	parts := []string{
		"git", "fetch", "origin", ref, "&&",
		"git", "checkout", ref, "&&",
		"git", "pull", "--ff-only", "origin", ref, "&&",
	}
	if mode == "git-full" {
		parts = append(parts,
			"docker", "compose", "pull", "xray", "&&",
			"docker", "compose", "up", "-d", "--build", "xray", "node-agent",
		)
	} else {
		// Agent-only rollout must never recreate or stop the data-plane. Xray is
		// intentionally updated only by the explicit git-full mode above.
		parts = append(parts, "docker", "compose", "up", "-d", "--no-deps", "--build", "node-agent")
	}
	return parts, nil
}

func (h *handlers) restartNode(w http.ResponseWriter, r *http.Request) {
	if err := runDetachedComposeHelper(h.cfg.RepoDir, []string{
		"docker", "compose", "restart", "xray", "node-agent",
	}); err != nil {
		log.Printf("[restart] node restart error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "restart failed"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "restart started"})
}

func runDetachedComposeHelper(repoDir string, parts []string) error {
	args, err := detachedComposeHelperArgs(repoDir, parts)
	if err != nil {
		return err
	}
	return exec.Command("docker", args...).Run()
}

func detachedComposeHelperArgs(repoDir string, parts []string) ([]string, error) {
	if repoDir == "" {
		repoDir = "/opt/guardex-node"
	}
	if repoDir != strings.TrimSpace(repoDir) || strings.Contains(repoDir, ":") || containsControlCharacter(repoDir) {
		return nil, errors.New("agent repository path contains unsafe characters")
	}
	repoDir = filepath.Clean(repoDir)
	if !filepath.IsAbs(repoDir) || repoDir == string(filepath.Separator) {
		return nil, errors.New("agent repository path must be an absolute non-root path")
	}
	script, err := shellJoinCommand(parts)
	if err != nil {
		return nil, err
	}
	return []string{
		"run", "-d", "--rm",
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		// Docker Compose resolves relative bind mounts on the host daemon. Keep
		// the repository at the same absolute path inside this helper; mounting
		// it as /work would make ./xray-config.json resolve to host /work and
		// Docker would silently create a directory in place of the config file.
		"-v", repoDir + ":" + repoDir,
		"-w", repoDir,
		"docker:27-cli",
		"sh", "-lc",
		"apk add --no-cache docker-cli-compose git >/dev/null && " + script,
	}, nil
}

// shellJoinCommand preserves the explicit && separators used by the fixed
// update plans and quotes every executable/argument token. agentUpdateParts
// already validates the user-controlled ref, but quoting here keeps this
// privileged Docker-socket helper safe if another internal caller is added.
func shellJoinCommand(parts []string) (string, error) {
	if len(parts) == 0 {
		return "", errors.New("detached compose command is empty")
	}
	quoted := make([]string, 0, len(parts))
	operatorPending := true
	for _, part := range parts {
		if part == "&&" {
			if operatorPending {
				return "", errors.New("detached compose command has an invalid separator")
			}
			quoted = append(quoted, part)
			operatorPending = true
			continue
		}
		if part == "" || containsControlCharacter(part) {
			return "", errors.New("detached compose command contains an unsafe argument")
		}
		quoted = append(quoted, "'"+strings.ReplaceAll(part, "'", `'"'"'`)+"'")
		operatorPending = false
	}
	if operatorPending {
		return "", errors.New("detached compose command ends with a separator")
	}
	return strings.Join(quoted, " "), nil
}

func containsControlCharacter(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

// replaceAndRestart installs only a bounded, checksum-verified HTTPS response.
// The temporary file is created beside the target so the final rename is
// atomic, and every failure before that rename removes the partial download.
func replaceAndRestart(downloadURL, targetPath, serviceName, expectedSHA256 string) error {
	ctx, cancel := context.WithTimeout(context.Background(), binaryUpdateTimeout)
	defer cancel()
	if err := downloadVerifiedBinary(ctx, binaryUpdateHTTPClient, downloadURL, targetPath, expectedSHA256, maxBinaryUpdateBytes); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "restart", serviceName).Run(); err != nil {
		return fmt.Errorf("restart updated service: %w", err)
	}
	return nil
}

func downloadVerifiedBinary(ctx context.Context, client *http.Client, downloadURL, targetPath, expectedSHA256 string, maxBytes int64) error {
	if client == nil || maxBytes < 1 {
		return errors.New("binary download configuration is invalid")
	}
	if normalizedURL, checksum, err := validateBinaryUpdate(downloadURL, expectedSHA256); err != nil {
		return err
	} else {
		downloadURL = normalizedURL
		expectedSHA256 = checksum
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return errors.New("binary download request is invalid")
	}
	requestClient := *client
	requestClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := requestClient.Do(req)
	if err != nil {
		// Do not wrap the net/http error: signed download URLs commonly contain
		// secret query parameters and net/http includes the full URL in errors.
		return errors.New("binary download request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("binary download returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return errors.New("binary download exceeds the size limit")
	}

	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return errors.New("binary target directory is unavailable")
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(targetPath)+"-*.new")
	if err != nil {
		return errors.New("binary temporary file could not be created")
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		_ = tmp.Close()
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(resp.Body, maxBytes+1))
	if copyErr != nil {
		return errors.New("binary download could not be written")
	}
	if written == 0 {
		return errors.New("binary download is empty")
	}
	if written > maxBytes {
		return errors.New("binary download exceeds the size limit")
	}
	if hex.EncodeToString(hasher.Sum(nil)) != expectedSHA256 {
		return errors.New("binary download checksum mismatch")
	}
	if err := tmp.Chmod(0o755); err != nil {
		return errors.New("binary temporary file permissions could not be set")
	}
	if err := tmp.Sync(); err != nil {
		return errors.New("binary temporary file could not be synced")
	}
	if err := tmp.Close(); err != nil {
		return errors.New("binary temporary file could not be closed")
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return errors.New("binary target could not be replaced")
	}
	removeTemp = false
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

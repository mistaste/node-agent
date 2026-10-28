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
	"github.com/guardex/node-agent/internal/metrics"
)

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

type handlers struct {
	cfg        *config.Config
	collector  *metrics.Collector
	reconciler desiredStateReconciler
}
type desiredStateReconciler interface {
	SyncOnce(context.Context) error
	IsNaiveTag(string) bool
}

func (h *handlers) reconcileDesiredState(w http.ResponseWriter, r *http.Request) {
	if h.reconciler == nil {
		writeJSON(w, 503, map[string]string{"error": "controller unavailable"})
		return
	}
	if err := h.reconciler.SyncOnce(r.Context()); err != nil {
		writeJSON(w, 503, map[string]string{"error": "reconcile failed"})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "reconciled"})
}
func (h *handlers) health(w http.ResponseWriter, r *http.Request) {
	if h.cfg.MetricsOnly {
		writeJSON(w, 200, map[string]any{"status": "ok", "version": h.cfg.AgentVersion(), "mode": "metrics-only", "capabilities": map[string]bool{"host_metrics": true, "agent_update": true, "inbound_management": false, "topology_management": false}})
		return
	}
	writeJSON(w, 200, map[string]any{"status": "ok", "version": h.cfg.AgentVersion(), "capabilities": map[string]any{"engines": []string{"trusttunnel", "naiveproxy"}, "host_metrics": true}})
}
func (h *handlers) getMetrics(w http.ResponseWriter, r *http.Request) {
	snapshot := h.collector.Latest()
	if snapshot == nil {
		writeJSON(w, 503, map[string]string{"error": "not ready"})
		return
	}
	writeJSON(w, 200, snapshot)
}
func (h *handlers) nativeUserChange(w http.ResponseWriter, r *http.Request) {
	h.reconcileDesiredState(w, r)
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
	if h.cfg.MetricsOnly {
		if mode != "git" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "metrics-only hosts support agent-only git updates"})
			return
		}
		parts, err := metricsOnlyAgentUpdateParts(req.Ref)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid update mode or ref"})
			return
		}
		go func() {
			if err := runDetachedComposeHelper(h.cfg.RepoDir, parts); err != nil {
				log.Printf("[update] metrics-only agent git update error: %v", err)
			}
		}()
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "update started", "mode": mode})
		return
	}

	if mode == "git" || mode == "git-runners" || mode == "git-full" {
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
	if mode != "git" && mode != "git-runners" && mode != "git-full" {
		return nil, errors.New("unsupported git update mode")
	}
	parts, err := gitUpdatePrefix(ref)
	if err != nil {
		return nil, err
	}
	if mode == "git-full" {
		parts = append(parts,

			"docker", "compose", "up", "-d", "--build", "node-agent", "topology-agent", "trusttunnel-runner", "transport-bundle-runner",
		)
	} else if mode == "git-runners" {
		// Runner-only rollout updates the session-preserving supervisors without
		// recreating node-agent or topology-agent.
		parts = append(parts, "docker", "compose", "up", "-d", "--no-deps", "--build", "trusttunnel-runner", "transport-bundle-runner")
	} else {
		// Agent-only rollout must never recreate the topology controller or any
		// data-plane process. Restarting topology-agent can turn a harmless API
		// observability release into a policy reconciliation event.
		parts = append(parts, "docker", "compose", "up", "-d", "--no-deps", "--build", "node-agent")
	}
	return parts, nil
}

func metricsOnlyAgentUpdateParts(ref string) ([]string, error) {
	parts, err := gitUpdatePrefix(ref)
	if err != nil {
		return nil, err
	}
	// topology-agent owns the relay/exit forwarding data plane. Recreating it
	// from this control endpoint would turn a harmless agent update into a live
	// traffic interruption.
	return append(parts, "docker", "compose", "up", "-d", "--no-deps", "--build", "node-agent"), nil
}

func gitUpdatePrefix(ref string) ([]string, error) {
	if !safeGitRef.MatchString(ref) || strings.Contains(ref, "..") || strings.Contains(ref, "//") || strings.HasSuffix(ref, "/") {
		return nil, errors.New("unsafe git ref")
	}
	return []string{
		"git", "fetch", "origin", ref, "&&",
		"git", "checkout", ref, "&&",
		"git", "pull", "--ff-only", "origin", ref, "&&",
	}, nil
}

func (h *handlers) restartNode(w http.ResponseWriter, r *http.Request) {
	if err := runDetachedComposeHelper(h.cfg.RepoDir, []string{"docker", "compose", "restart", "trusttunnel-runner", "transport-bundle-runner", "node-agent"}); err != nil {
		writeJSON(w, 500, map[string]string{"error": "restart failed"})
		return
	}
	writeJSON(w, 202, map[string]string{"status": "restart started"})
}

func runDetachedComposeHelper(repoDir string, parts []string) error {
	args, err := detachedComposeHelperArgs(repoDir, parts)
	if err != nil {
		return err
	}
	output, err := exec.Command("docker", args...).CombinedOutput()
	if err == nil {
		return nil
	}
	detail := summarizeUpdateOutput(output)
	if detail == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, detail)
}

func summarizeUpdateOutput(output []byte) string {
	const maxBytes = 2048
	detail := strings.TrimSpace(string(output))
	detail = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 0x20 {
			return r
		}
		return ' '
	}, detail)
	if len(detail) > maxBytes {
		detail = detail[len(detail)-maxBytes:]
		detail = "..." + detail
	}
	return detail
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
		// it as /work would make ./data resolve to host /work and
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

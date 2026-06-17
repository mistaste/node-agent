package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/metrics"
	"github.com/guardex/node-agent/internal/xray"
)

type handlers struct {
	cfg       *config.Config
	xray      *xray.Client
	collector *metrics.Collector
}

func (h *handlers) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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

	err := h.xray.AddUser(r.Context(), xray.AddUserParams{
		InboundTag: req.InboundTag,
		UUID:       req.UUID,
		Flow:       req.Flow,
		Level:      req.Level,
	})
	if err != nil {
		log.Printf("[api] addUser error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
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

	err := h.xray.RemoveUser(r.Context(), inboundTag, uuid)
	if err != nil {
		log.Printf("[api] removeUser error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed", "uuid": uuid})
}

func (h *handlers) addInbound(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty body"})
		return
	}
	var meta struct {
		Tag string `json:"tag"`
	}
	_ = json.Unmarshal(body, &meta)

	if err := h.xray.AddInboundFromJSON(r.Context(), body); err != nil {
		log.Printf("[api] addInbound %q: %v", meta.Tag, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	log.Printf("[api] inbound %q added", meta.Tag)
	writeJSON(w, http.StatusOK, map[string]string{"status": "added", "tag": meta.Tag})
}

func (h *handlers) removeInbound(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	if tag == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tag required"})
		return
	}
	if err := h.xray.RemoveInbound(r.Context(), tag); err != nil {
		log.Printf("[api] removeInbound %q: %v", tag, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	log.Printf("[api] inbound %q removed", tag)
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed", "tag": tag})
}

type updateRequest struct {
	URL string `json:"url"`
}

func (h *handlers) updateXray(w http.ResponseWriter, r *http.Request) {
	var req updateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url required"})
		return
	}

	go func() {
		if err := replaceAndRestart(req.URL, "/usr/local/bin/xray", "xray"); err != nil {
			log.Printf("[update] xray update error: %v", err)
		} else {
			log.Printf("[update] xray updated successfully")
		}
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "update started"})
}

func (h *handlers) updateAgent(w http.ResponseWriter, r *http.Request) {
	var req updateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url required"})
		return
	}

	self, err := os.Executable()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot resolve self path"})
		return
	}

	go func() {
		if err := replaceAndRestart(req.URL, self, "agent"); err != nil {
			log.Printf("[update] agent update error: %v", err)
		}
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "update started"})
}

// replaceAndRestart downloads a binary to a temp file, replaces target, restarts via systemctl.
func replaceAndRestart(url, targetPath, serviceName string) error {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	tmp := targetPath + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	f.Close()

	if err := os.Rename(tmp, targetPath); err != nil {
		return err
	}

	return exec.Command("systemctl", "restart", serviceName).Run()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

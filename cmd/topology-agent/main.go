package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/guardex/node-agent/internal/topology"
)

func main() {
	root := env("TOPOLOGY_ROOT", "/data/topology")
	interval := duration(env("TOPOLOGY_RESYNC_INTERVAL", "30s"), 30*time.Second)
	applier, err := topology.NewApplier(root)
	if err != nil {
		log.Fatal("[topology] invalid local state directory")
	}
	controller, err := topology.NewController(
		strings.TrimSpace(os.Getenv("CONTROLLER_URL")),
		strings.TrimSpace(os.Getenv("INTERNAL_SERVICE_TOKEN")),
		strings.TrimSpace(os.Getenv("AGENT_SECRET")),
		interval,
		applier,
	)
	if err != nil {
		log.Fatal("[topology] controller configuration is incomplete")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	controller.Run(ctx)
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func duration(value string, fallback time.Duration) time.Duration {
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

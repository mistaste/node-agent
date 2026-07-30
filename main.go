package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/guardex/node-agent/internal/api"
	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/controller"
	"github.com/guardex/node-agent/internal/inboundsync"
	"github.com/guardex/node-agent/internal/metrics"
	"github.com/guardex/node-agent/internal/pusher"
	"github.com/guardex/node-agent/internal/store"
	"github.com/guardex/node-agent/internal/trusttunnel"
	"github.com/guardex/node-agent/internal/userops"
	"github.com/guardex/node-agent/internal/usersync"
	"github.com/guardex/node-agent/internal/xray"
)

func main() {
	cfg := config.Load()
	if !cfg.AgentAPISecretValid() {
		log.Fatal("[agent] AGENT_SECRET must be a non-placeholder secret of at least 32 characters")
	}
	if len(os.Args) == 2 && os.Args[1] == "check-rollback-v0.2.3" {
		if err := store.CheckLegacyV3Rollback(cfg.InboundsFile); err != nil {
			log.Fatalf("[rollback-check] unsafe: %v", err)
		}
		log.Printf("[rollback-check] safe: v3 store contains no active Hysteria records")
		return
	}

	xrayClient, err := xray.NewClient(cfg.XrayGRPCAddr)
	if err != nil {
		log.Fatalf("[agent] failed to connect to xray gRPC: %v", err)
	}
	defer xrayClient.Close()
	log.Printf("[agent] connected to xray at %s", cfg.XrayGRPCAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Dynamic inbounds are desired state, not ephemeral API calls. Restore them
	// before users so every stored user's inbound tag exists after a core restart.
	inboundStore := store.NewInboundStore(cfg.InboundsFile)
	if err := inboundStore.Load(); err != nil {
		log.Fatalf("[agent] failed to load inbound store: %v", err)
	}
	inboundManager := inboundsync.New(xrayClient, inboundStore, cfg.ResyncInterval, cfg.DefaultInboundTag, "api")
	appliedInbounds, failedInbounds := inboundManager.Bootstrap(ctx)
	log.Printf("[inboundsync] bootstrap: applied=%d failed=%d desired=%d", appliedInbounds, failedInbounds, len(inboundManager.Inventory()))
	go inboundManager.Run(ctx)

	// Load the durable user inventory before controller tombstones can run so a
	// deleted tag is cleaned atomically and cannot be resurrected by usersync.
	userStore := store.New(cfg.UsersFile)
	if err := userStore.Load(); err != nil {
		log.Printf("[agent] failed to load user store: %v", err)
	}
	userOperations := userops.New()
	var trustTunnelRuntime *trusttunnel.Runtime
	var controllerReconciler *controller.Reconciler
	var controllerErr error

	// Restore durable users before the first controller pull. Both loops share
	// userOperations afterwards, so an old usersync snapshot can never race an
	// exact controller membership update or tombstone cleanup.
	syncer := usersync.New(xrayClient, userStore, cfg.ResyncInterval, userOperations)
	syncer.Bootstrap(ctx)
	if cfg.ControllerPollingEnabled() {
		controllerReconciler, controllerErr = controller.New(cfg, inboundManager, userStore, xrayClient, userOperations)
		if controllerErr != nil {
			log.Printf("[controller-inbounds] disabled: invalid controller configuration")
		} else {
			runtime, runtimeErr := trusttunnel.NewRuntime(cfg.TrustTunnelRoot, cfg.TrustTunnelBinary, cfg.TrustTunnelService, cfg.Secret)
			if runtimeErr != nil {
				log.Printf("[trusttunnel] disabled: runtime configuration is invalid")
			} else {
				trustTunnelRuntime = runtime
				if cfg.TrustTunnelEnabled {
					controllerReconciler.EnableTrustTunnel(runtime)
					log.Printf("[trusttunnel] runtime enabled; availability will be reported after binary verification")
				} else {
					controllerReconciler.EnableTrustTunnelCleanup(runtime)
					log.Printf("[trusttunnel] endpoint apply disabled; tombstone cleanup remains enabled")
				}
			}
			// Run performs the first pull immediately after the durable inbound
			// bootstrap, then retries at RESYNC_INTERVAL while offline.
			go controllerReconciler.Run(ctx)
		}
	} else {
		log.Printf("[controller-inbounds] disabled: verified controller credentials are incomplete")
	}

	// Durable user store: Xray keeps users only in memory, so re-apply after any
	// Xray restart while honoring the shared exact-set operation lock.
	go syncer.Run(ctx)

	collector := metrics.NewCollector(xrayClient, cfg.MetricsInterval)
	go collector.Run(ctx)

	p := pusher.NewPusher(cfg, collector, userStore)
	go p.Run(ctx)

	serverOptions := []any{userOperations}
	if controllerReconciler != nil {
		serverOptions = append(serverOptions, controllerReconciler)
	}
	srv := api.NewServer(cfg, xrayClient, collector, userStore, inboundManager, serverOptions...)
	go func() {
		if err := srv.Run(); err != nil {
			log.Printf("[agent] HTTP server error: %v", err)
		}
	}()
	log.Printf("[agent] HTTP server listening on %s", cfg.ListenAddr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("[agent] shutting down")
	cancel()
	if trustTunnelRuntime != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 6*time.Second)
		if err := trustTunnelRuntime.Close(shutdownCtx); err != nil {
			log.Printf("[trusttunnel] shutdown cleanup failed: %v", err)
		}
		shutdownCancel()
	}
}

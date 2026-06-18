package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/guardex/node-agent/internal/api"
	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/metrics"
	"github.com/guardex/node-agent/internal/pusher"
	"github.com/guardex/node-agent/internal/store"
	"github.com/guardex/node-agent/internal/usersync"
	"github.com/guardex/node-agent/internal/xray"
)

func main() {
	cfg := config.Load()

	xrayClient, err := xray.NewClient(cfg.XrayGRPCAddr)
	if err != nil {
		log.Fatalf("[agent] failed to connect to xray gRPC: %v", err)
	}
	defer xrayClient.Close()
	log.Printf("[agent] connected to xray at %s", cfg.XrayGRPCAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Durable user store: Xray keeps users only in memory, so persist them and
	// re-apply on startup / after any Xray restart.
	userStore := store.New(cfg.UsersFile)
	if err := userStore.Load(); err != nil {
		log.Printf("[agent] failed to load user store: %v", err)
	}
	syncer := usersync.New(xrayClient, userStore, cfg.ResyncInterval)
	syncer.Bootstrap(ctx)
	go syncer.Run(ctx)

	collector := metrics.NewCollector(xrayClient, cfg.MetricsInterval)
	go collector.Run(ctx)

	p := pusher.NewPusher(cfg, collector)
	go p.Run(ctx)

	srv := api.NewServer(cfg, xrayClient, collector, userStore)
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
}

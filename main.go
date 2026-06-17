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

	collector := metrics.NewCollector(xrayClient, cfg.MetricsInterval)
	go collector.Run(ctx)

	p := pusher.NewPusher(cfg, collector)
	go p.Run(ctx)

	srv := api.NewServer(cfg, xrayClient, collector)
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

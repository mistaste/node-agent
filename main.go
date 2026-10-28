package main

import (
	"context"
	"github.com/guardex/node-agent/internal/api"
	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/controller"
	"github.com/guardex/node-agent/internal/metrics"
	"github.com/guardex/node-agent/internal/pusher"
	"github.com/guardex/node-agent/internal/transportbundle"
	"github.com/guardex/node-agent/internal/trusttunnel"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg := config.Load()
	if !cfg.AgentAPISecretValid() {
		log.Fatal("invalid management secret")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var controllerReconciler *controller.Reconciler
	var controllerErr error
	var trustTunnelRuntime *trusttunnel.Runtime
	if !cfg.MetricsOnly && cfg.ControllerPollingEnabled() {
		controllerReconciler, controllerErr = controller.New(cfg)
		if controllerErr != nil {
			log.Printf("[controller-inbounds] disabled: invalid controller configuration")
		} else {
			runtime, runtimeErr := trusttunnel.NewRuntime(cfg.TrustTunnelRoot, cfg.TrustTunnelBinary, cfg.TrustTunnelService, cfg.Secret)
			if runtimeErr != nil {
				log.Printf("[trusttunnel] disabled: runtime configuration is invalid")
			} else {
				trustTunnelRuntime = runtime
				if cfg.TrustTunnelProcessMode == "external" {
					runtime.UseExternalProcess()
					log.Printf("[trusttunnel] endpoint process delegated to external runner")
				}
				if cfg.TrustTunnelEnabled {
					controllerReconciler.EnableTrustTunnel(runtime)
					log.Printf("[trusttunnel] runtime enabled; availability will be reported after binary verification")
				} else {
					controllerReconciler.EnableTrustTunnelCleanup(runtime)
					log.Printf("[trusttunnel] endpoint apply disabled; tombstone cleanup remains enabled")
				}
			}
			if cfg.TransportBundleEnabled {
				bundleRuntime, bundleErr := transportbundle.NewRuntime(cfg.TransportBundleRoot, cfg.Secret)
				if bundleErr != nil {
					log.Printf("[transport-bundle] disabled: runtime configuration is invalid")
				} else {
					controllerReconciler.EnableTransportBundle(bundleRuntime)
					log.Printf("[transport-bundle] NaiveProxy mux runtime enabled")
				}
			}
			// Run performs the first pull immediately after the durable inbound
			// bootstrap, then retries at RESYNC_INTERVAL while offline.
			go controllerReconciler.Run(ctx)
		}
	} else {
		log.Printf("[controller-inbounds] disabled: verified controller credentials are incomplete")
	}

	collector := metrics.NewCollector(cfg.MetricsInterval, cfg.MetricsInterface)
	if cfg.MetricsOnly {
		collector.DisableNativeMetrics()
	}
	go collector.Run(ctx)
	var inventory pusher.UserInventory
	if controllerReconciler != nil {
		inventory = controllerReconciler
	}
	go pusher.NewPusher(cfg, collector, inventory).Run(ctx)
	srv := api.NewServer(cfg, collector, nil)
	if controllerReconciler != nil {
		srv = api.NewServer(cfg, collector, controllerReconciler)
	}
	go func() {
		if err := srv.Run(); err != nil {
			log.Printf("management server: %v", err)
			cancel()
		}
	}()
	<-ctx.Done()
	if trustTunnelRuntime != nil {
		shutdown, done := context.WithTimeout(context.Background(), 6*time.Second)
		defer done()
		_ = trustTunnelRuntime.Close(shutdown)
	}
}

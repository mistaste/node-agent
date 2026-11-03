package main

import (
	"context"
	"github.com/guardex/node-agent/internal/hardquota"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	broker, err := hardquota.New(os.Getenv("CONTROLLER_URL"), os.Getenv("AGENT_SECRET"), os.Getenv("INTERNAL_SERVICE_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	path := os.Getenv("GUARDEX_HARD_QUOTA_SOCKET")
	if !filepath.IsAbs(path) {
		log.Fatal("absolute private quota socket required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		log.Fatal(err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			log.Fatal("quota socket path is not a socket")
		}
		live, e := net.DialTimeout("unix", path, 100*time.Millisecond)
		if e == nil {
			live.Close()
			log.Fatal("quota broker already running")
		}
		if err := os.Remove(path); err != nil {
			log.Fatal(err)
		}
	}
	if err := os.Chown(filepath.Dir(path), os.Geteuid(), 65532); err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0750); err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(path)
	if err := os.Chown(path, os.Geteuid(), 65532); err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(path, 0660); err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := broker.Serve(ctx, listener); err != nil {
		log.Fatal(err)
	}
}

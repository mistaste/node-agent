package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/guardex/node-agent/internal/transportdiag"
	"os"
	"os/signal"
	"time"
)

func main() {
	target := flag.String("url", "", "owned HTTPS resource; no credentials/query")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	events, err := transportdiag.Probe(ctx, *target)
	if len(events) == 0 && err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	failed := err != nil
	if err = transportdiag.WriteJSON(os.Stdout, events); err != nil {
		os.Exit(1)
	}
	if failed {
		os.Exit(1)
	}
}

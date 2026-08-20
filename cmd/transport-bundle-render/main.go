package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/guardex/node-agent/internal/transportbundle"
)

func main() {
	input := flag.String("input", "", "root-only JSON bundle configuration")
	output := flag.String("output", "", "managed output directory")
	flag.Parse()
	if err := run(*input, *output, os.Getenv("AGENT_SECRET")); err != nil {
		fmt.Fprintln(os.Stderr, "transport bundle render failed")
		os.Exit(1)
	}
}

func run(input, output, secret string) error {
	if !filepath.IsAbs(input) || !filepath.IsAbs(output) {
		return errors.New("absolute paths are required")
	}
	raw, err := os.ReadFile(input)
	if err != nil || len(raw) > 1<<20 {
		return errors.New("configuration unavailable")
	}
	var cfg transportbundle.Config
	if json.Unmarshal(raw, &cfg) != nil {
		return errors.New("configuration invalid")
	}
	files, err := transportbundle.Build(secret, cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(output, 0700); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(output, "haproxy.cfg"), files.HAProxy, 0600); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(output, "Caddyfile"), files.Caddy, 0600)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".guardex-bundle-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

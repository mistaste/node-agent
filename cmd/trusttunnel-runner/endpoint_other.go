//go:build !linux

package main

import (
	"errors"
	"os/exec"
)

func configureEndpointCommand(_ *exec.Cmd, _, _ uint32) error {
	return errors.New("dedicated TrustTunnel endpoint identity requires Linux")
}

//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

const capNetBindService = 10

func configureEndpointCommand(command *exec.Cmd, uid, gid uint32) error {
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential:  &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true},
		AmbientCaps: []uintptr{capNetBindService},
	}
	return nil
}

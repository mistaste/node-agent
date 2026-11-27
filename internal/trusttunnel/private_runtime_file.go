package trusttunnel

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// samePrivateRuntimeFile accepts owner-only files and the external runner's
// read-only group access, bounded to the protected runtime directory's owner
// and group. Symlinks, public access and changed contents always require repair.
func samePrivateRuntimeFile(path string, expected []byte) bool {
	directory, err := os.Lstat(filepath.Dir(path))
	if err != nil || !directory.IsDir() || directory.Mode().Perm()&0027 != 0 {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	parent, parentOK := directory.Sys().(*syscall.Stat_t)
	if !ok || !parentOK || owner.Uid != parent.Uid {
		return false
	}
	mode := info.Mode().Perm()
	if mode != 0600 && !(mode == 0640 && owner.Gid == parent.Gid) {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(len(expected))+1))
	return err == nil && bytes.Equal(data, expected)
}

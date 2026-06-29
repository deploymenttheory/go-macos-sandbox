//go:build darwin

package procpath

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-macosplatform/opinionated/idiomatic/libraries/libproc"
)

const maxPath = 4096

const procPIDTBSDInfo = 3

// Path returns the executable path for pid using proc_pidpath(3).
func Path(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid pid %d", pid)
	}
	buf := make([]byte, maxPath)
	n := libproc.Pidpath(int32(pid), unsafe.Pointer(&buf[0]), uint32(len(buf)))
	if n <= 0 {
		return "", fmt.Errorf("empty path for pid %d", pid)
	}
	return string(buf[:n]), nil
}

// PPID returns the parent pid for pid using proc_pidinfo(PROC_PIDTBSDINFO).
func PPID(pid int) (int, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	buf := make([]byte, 256)
	n := libproc.Pidinfo(int32(pid), procPIDTBSDInfo, 0, unsafe.Pointer(&buf[0]), int32(len(buf)))
	if n < 20 {
		return 0, fmt.Errorf("proc_pidinfo failed for pid %d", pid)
	}
	return int(binary.LittleEndian.Uint32(buf[16:20])), nil
}

// Node is a lightweight process identity used for ancestry walks.
type Node struct {
	PID  int
	PPID int
	Path string
}

// Lookup returns process metadata for pid when the process is still running.
func Lookup(pid int) (Node, bool) {
	path, err := Path(pid)
	if err != nil || path == "" {
		return Node{}, false
	}
	ppid, err := PPID(pid)
	if err != nil {
		ppid = 0
	}
	return Node{PID: pid, PPID: ppid, Path: path}, true
}

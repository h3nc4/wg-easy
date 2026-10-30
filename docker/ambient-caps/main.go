// Command ambient-caps raises NET_ADMIN and NET_RAW into the ambient set when the process holds them, then runs its arguments.
// Ambient capabilities survive exec as a non-root user, and a capability the container does not grant is skipped.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	capNetAdmin       = 12
	capNetRaw         = 13
	capVersion3       = 0x20080522
	prCapAmbient      = 47
	prCapAmbientRaise = 2
)

type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective, permitted, inheritable uint32
}

// Capabilities belong to a thread, so the capset, the prctl calls and the exec must all run on this one.
func init() {
	runtime.LockOSThread()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s program [argument ...]\n", os.Args[0])
		os.Exit(2)
	}

	header := capHeader{version: capVersion3}
	var data [2]capData
	if _, _, errno := syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0); errno == 0 {
		for _, c := range []uint32{capNetAdmin, capNetRaw} {
			if data[0].permitted&(1<<c) != 0 {
				data[0].inheritable |= 1 << c
			}
		}
		if _, _, errno := syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0); errno == 0 {
			for _, c := range []uint32{capNetAdmin, capNetRaw} {
				if data[0].inheritable&(1<<c) != 0 {
					syscall.RawSyscall6(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientRaise, uintptr(c), 0, 0, 0)
				}
			}
		}
	}

	path, err := exec.LookPath(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(127)
	}
	err = syscall.Exec(path, os.Args[1:], os.Environ())
	fmt.Fprintln(os.Stderr, err)
	os.Exit(127)
}

// +build linux

package elf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/iovisor/gobpf/pkg/bpffs"
)

/*
#include <linux/unistd.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern __u64 ptr_to_u64(void *);

int bpf_pin_object(int fd, const char *pathname)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.pathname = ptr_to_u64((void *)pathname);
	attr.bpf_fd = fd;

	return syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
}
*/
import "C"

const (
	BPFDirGlobals = "globals" // as in iproute2's BPF_DIR_GLOBALS
	BPFFSPath     = "/sys/fs/bpf/"
)

func validPinPath(PinPath string) bool {
	if !strings.HasPrefix(PinPath, BPFFSPath) {
		return false
	}

	return filepath.Clean(PinPath) == PinPath
}

func pinObject(fd int, pinPath string) error {
	mounted, err := bpffs.IsMounted()
	if err != nil {
		return fmt.Errorf("error checking if %q is mounted: %v", BPFFSPath, err)
	}
	if !mounted {
		return fmt.Errorf("bpf fs not mounted at %q", BPFFSPath)
	}
	err = os.MkdirAll(filepath.Dir(pinPath), 0755)
	if err != nil {
		return fmt.Errorf("error creating directory %q: %v", filepath.Dir(pinPath), err)
	}
	_, err = os.Stat(pinPath)
	if err == nil {
		return fmt.Errorf("aborting, found file at %q", pinPath)
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat %q: %v", pinPath, err)
	}
	pinPathC := C.CString(pinPath)
	defer C.free(unsafe.Pointer(pinPathC))
	ret, err := C.bpf_pin_object(C.int(fd), pinPathC)
	if ret != 0 {
		return fmt.Errorf("error pinning object to %q: %v", pinPath, err)
	}
	return nil
}

// PinObjectGlobal pins and object to a name in a namespaces
// e.g. `/sys/fs/bpf/my-namespace/globals/my-name`
func PinObjectGlobal(fd int, namespace, name string) error {
	pinPath := filepath.Join(BPFFSPath, namespace, BPFDirGlobals, name)
	return pinObject(fd, pinPath)
}

// PinObject pins an object to a path
func PinObject(fd int, pinPath string) error {
	if !validPinPath(pinPath) {
		return fmt.Errorf("not a valid pin path: %s", pinPath)
	}
	return pinObject(fd, pinPath)
}

package procmon

import (
	"fmt"
	"testing"
)

func TestGetProcPids(t *testing.T) {
	pids := getProcPids("/proc")

	if len(pids) == 0 {
		t.Error("getProcPids() should not be 0", pids)
	}
}

func TestLookupPidDescriptors(t *testing.T) {
	pidsFd := lookupPidDescriptors(fmt.Sprint("/proc/", myPid, "/fd/"))

	if len(pidsFd) == 0 {
		t.Error("getProcPids() should not be 0", pidsFd)
	}
}

func TestLookupPidInProc(t *testing.T) {
	// we expect that the inode 1 points to /dev/null
	expect := "/dev/null"
	foundPid := lookupPidInProc("/proc/", expect, "", 1)
	if foundPid == -1 {
		t.Error("lookupPidInProc() should not return -1")
	}
}

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
	pidsFd := lookupPidDescriptors(fmt.Sprint("/proc/", myPid, "/fd/"), myPid)
	if len(pidsFd) == 0 {
		t.Error("getProcPids() should not be 0", pidsFd)
	}
}

func TestLookupPidInProc(t *testing.T) {
	// we expect that the inode 1 points to /dev/null
	expect := "/dev/null"
	foundPid := lookupPidInProc("/proc/", expect, "", myPid)
	if foundPid == -1 {
		t.Error("lookupPidInProc() should not return -1")
	}
}

func BenchmarkGetProcs(b *testing.B) {
	for i := 0; i < b.N; i++ {
		getProcPids("/proc")
	}
}

func BenchmarkLookupPidDescriptors(b *testing.B) {
	for i := 0; i < b.N; i++ {
		lookupPidDescriptors(fmt.Sprint("/proc/", myPid, "/fd/"), myPid)
	}
}

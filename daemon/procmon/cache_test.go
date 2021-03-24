package procmon

import (
	"fmt"
	"testing"
	"time"
)

func TestCacheProcs(t *testing.T) {
	fdList := []string{"0", "1", "2"}
	addProcEntry(fmt.Sprint("/proc/", myPid, "/fd/"), fdList, myPid)
	t.Log("Pids in cache: ", len(pidsCache))

	t.Run("Test addProcEntry", func(t *testing.T) {
		if len(pidsCache) != 1 {
			t.Error("pidsCache should be 1")
		}
	})

	oldPid := pidsCache[0]
	addProcEntry(fmt.Sprint("/proc/", myPid, "/fd/"), fdList, myPid)
	t.Run("Test addProcEntry update", func(t *testing.T) {
		if len(pidsCache) != 1 {
			t.Error("pidsCache should be still 1!", pidsCache)
		}
		oldTime := time.Unix(0, oldPid.LastSeen)
		newTime := time.Unix(0, pidsCache[0].LastSeen)
		if oldTime.Equal(newTime) == false {
			t.Error("pidsCache, time not updated: ", oldTime, newTime)
		}
	})

	addProcEntry("/proc/2/fd/", fdList, 2)
	deleteProcEntry(2)
	t.Run("Test deleteProcEntry", func(t *testing.T) {
		if len(pidsCache) != 1 {
			t.Error("pidsCache should be 1:", len(pidsCache))
		}
	})

	pid, _ := getPidFromCache(0, "", "/dev/null")
	t.Run("Test getPidFromCache", func(t *testing.T) {
		if pid != myPid {
			t.Error("pid not found in cache", len(pidsCache))
		}
	})

	// the key of an inodeCache entry is formed as: inodeNumer + srcIP + srcPort + dstIP + dstPort
	inodeKey := "000000000127.0.0.144444127.0.0.153"
	addInodeEntry(inodeKey, "/proc/fd/123", myPid)
	t.Run("Test addInodeEntry", func(t *testing.T) {
		if _, found := inodesCache[inodeKey]; !found {
			t.Error("inodesCache, inode not added:", len(inodesCache), inodesCache)
		}
	})

	pid = getPidByInodeFromCache(inodeKey)
	t.Run("Test getPidByInodeFromCache", func(t *testing.T) {
		if pid != myPid {
			t.Error("inode not found in cache", pid, inodeKey, len(inodesCache), inodesCache)
		}
	})

	// should delete all inodes of a pid
	deleteInodeEntry(myPid)
	t.Run("Test deleteInodeEntry", func(t *testing.T) {
		if _, found := inodesCache[inodeKey]; found {
			t.Error("inodesCache, key found in cache but it should not exist", inodeKey, len(inodesCache), inodesCache)
		}
	})
}

// Test getPidDescriptorsFromCache descriptors (inodes) reordering.
// When an inode (descriptor) is found, if it's pushed to the top of the list,
// the next time we look for it will cost -10x.
// Without reordering, the inode 0 will always be found on the 10th position,
// taking an average of 100us instead of 30.
// Benchmark results with reordering: ~5600ns/op, without: ~56000ns/op.
func BenchmarkGetPid(b *testing.B) {
	fdList := []string{"10", "9", "8", "7", "6", "5", "4", "3", "2", "1", "0"}
	addProcEntry(fmt.Sprint("/proc/", myPid, "/fd/"), fdList, myPid)
	for i := 0; i < b.N; i++ {
		getPidFromCache(0, "", "/dev/null")
	}
}

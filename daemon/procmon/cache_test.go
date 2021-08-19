package procmon

import (
	"fmt"
	"testing"
	"time"
)

func TestCacheProcs(t *testing.T) {
	fdList := []string{"0", "1", "2"}
	pidsCache.add(fmt.Sprint("/proc/", myPid, "/fd/"), fdList, myPid)
	t.Log("Pids in cache: ", pidsCache.countItems())

	t.Run("Test addProcEntry", func(t *testing.T) {
		if pidsCache.countItems() != 1 {
			t.Error("pidsCache should be 1")
		}
	})

	oldPid := pidsCache.getItem(0)
	pidsCache.add(fmt.Sprint("/proc/", myPid, "/fd/"), fdList, myPid)
	t.Run("Test addProcEntry update", func(t *testing.T) {
		if pidsCache.countItems() != 1 {
			t.Error("pidsCache should still be 1!", pidsCache)
		}
		oldTime := time.Unix(0, oldPid.LastSeen)
		newTime := time.Unix(0, pidsCache.getItem(0).LastSeen)
		if oldTime.Equal(newTime) == false {
			t.Error("pidsCache, time not updated: ", oldTime, newTime)
		}
	})

	pidsCache.add("/proc/2/fd", fdList, 2)
	pidsCache.delete(2)
	t.Run("Test deleteProcEntry", func(t *testing.T) {
		if pidsCache.countItems() != 1 {
			t.Error("pidsCache should be 1:", pidsCache.countItems())
		}
	})

	pid, _ := pidsCache.getPid(0, "", "/dev/null")
	t.Run("Test getPidFromCache", func(t *testing.T) {
		if pid != myPid {
			t.Error("pid not found in cache", pidsCache.countItems())
		}
	})

	// should not crash, and the number of items should still be 1
	pidsCache.deleteItem(1)
	t.Run("Test deleteItem check bounds", func(t *testing.T) {
		if pidsCache.countItems() != 1 {
			t.Error("deleteItem check bounds error", pidsCache.countItems())
		}
	})

	pidsCache.deleteItem(0)
	t.Run("Test deleteItem", func(t *testing.T) {
		if pidsCache.countItems() != 0 {
			t.Error("deleteItem error", pidsCache.countItems())
		}
	})
	t.Log("items in cache:", pidsCache.countItems())

	// the key of an inodeCache entry is formed as: inodeNumer + srcIP + srcPort + dstIP + dstPort
	inodeKey := "000000000127.0.0.144444127.0.0.153"
	// add() expects a path to the inode fd (/proc/<pid>/fd/12345), but as getPid() will check the path in order to retrieve the pid,
	// we just set it to "" and it'll use /proc/<pid>/exe
	inodesCache.add(inodeKey, "", myPid)
	t.Run("Test addInodeEntry", func(t *testing.T) {
		if _, found := inodesCache.items[inodeKey]; !found {
			t.Error("inodesCache, inode not added:", len(inodesCache.items), inodesCache.items)
		}
	})

	pid = inodesCache.getPid(inodeKey)
	t.Run("Test getPidByInodeFromCache", func(t *testing.T) {
		if pid != myPid {
			t.Error("inode not found in cache", pid, inodeKey, len(inodesCache.items), inodesCache.items)
		}
	})

	// should delete all inodes of a pid
	inodesCache.delete(myPid)
	t.Run("Test deleteInodeEntry", func(t *testing.T) {
		if _, found := inodesCache.items[inodeKey]; found {
			t.Error("inodesCache, key found in cache but it should not exist", inodeKey, len(inodesCache.items), inodesCache.items)
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
	pidsCache.add(fmt.Sprint("/proc/", myPid, "/fd/"), fdList, myPid)
	for i := 0; i < b.N; i++ {
		pidsCache.getPid(0, "", "/dev/null")
	}
}

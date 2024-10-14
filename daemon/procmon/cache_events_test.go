package procmon

import (
	"os"
	"testing"
	"time"
)

var (
	ourPid = os.Getpid()
)

func createNewProc(pid int) *Process {
	proc := NewProcess(pid, "")
	// we need to read the process details manually, because by default we exclude our own process.
	proc.ReadComm()
	proc.ReadPath()
	proc.ReadCmdline()
	proc.BuildTree()
	return proc
}

// Test regular use.
func TestCacheEvents(t *testing.T) {
	evtsCache := NewEventsStore()
	proc := createNewProc(ourPid)
	evtsCache.Add(proc)

	t.Run("PID isInStoreByPID()", func(t *testing.T) {
		item, found := evtsCache.IsInStoreByPID(ourPid)
		if !found {
			t.Error("PID not found in cache:", ourPid, item)
		}
		if item.Proc.Path != proc.Path {
			t.Error("invalid item returned:", ourPid, item)
		}
	})

	t.Run("PID isInStore()", func(t *testing.T) {
		item, _, found := evtsCache.IsInStore(ourPid, nil)
		if !found {
			t.Error("PID not found in cache:", ourPid, item)
		}
		if item.Proc.Path != proc.Path {
			t.Error("invalid item returned:", ourPid, item)
		}
	})

	// this process is or should be alive, so it must not be removed from cache.
	// we keep it until it exits.
	t.Run("Delete() isAlive()", func(t *testing.T) {
		evtsCache.Delete(ourPid)
		if _, _, found := evtsCache.IsInStore(ourPid, nil); !found {
			t.Error("PID deleted from cache. The PID should be kept in cache until it exits")
		}
	})
}

func TestCacheEvents2(t *testing.T) {
	fakePid := 1234
	evtsCache := NewEventsStore()
	proc := createNewProc(fakePid)
	proc.Path = "/tmp/1234"
	evtsCache.Add(proc)

	t.Run("PID isInStoreByPID()", func(t *testing.T) {
		item, found := evtsCache.IsInStoreByPID(fakePid)
		if !found {
			t.Error("PID not found in cache:", fakePid, item)
		}
		if item.Proc.Path != proc.Path {
			t.Error("invalid item returned:", fakePid, item)
		}
	})

	// this process does not exist, so it should be removed from cache
	t.Run("Delete() !isAlive()", func(t *testing.T) {
		evtsCache.Delete(fakePid)
		if _, _, found := evtsCache.IsInStore(ourPid, nil); found {
			t.Error("PID not deleted from cache.")
		}
	})

	t.Run("Len()", func(t *testing.T) {
		if evtsCache.Len() > 0 {
			t.Error("cache Len() should be 0:", evtsCache)
		}
	})
}

// Test replacements process.
// Many times we receive two exec events with the same PID, for example when
// systemd-run or gio-launch-desktop launches a new process.
//
// exec1: ppid: 532745, pid: 1349383, /usr/lib/x86_64-linux-gnu/glib-2.0/gio-launch-desktop /usr/local/bin/gnome-calculator
// exec2: ppid: 532745, pid: 1349383, /usr/local/bin/gnome-calculator
func TestCacheEventsUpdate(t *testing.T) {
	evtsCache := NewEventsStore()
	origProc := createNewProc(ourPid)
	newProc := createNewProc(ourPid)
	newProc.Path = "/tmp/xxx"
	evtsCache.Add(origProc)

	t.Run("PID isInStore() and needs update", func(t *testing.T) {
		item, needsUpdate, found := evtsCache.IsInStore(ourPid, newProc)
		if !found {
			t.Error("PID not found in cache:", ourPid, item)
		}
		if !needsUpdate {
			t.Error("PID needs update:", ourPid, item)
		}
	})
	t.Run("Update() replace origProc by newProc", func(t *testing.T) {
		evtsCache.Update(origProc, newProc)
		// now the item stored in cache by ourPid, should contain newProc instead of origProc
		item, found := evtsCache.IsInStoreByPID(ourPid)
		if !found {
			t.Error("Update() PID not found in cache")
		}
		if item.Proc.Path != newProc.Path {
			t.Error("Update() item not updated? Paths differ. expected:", newProc.Path, "got:", item.Proc.Path)
		}
	})

	t.Run("Delete()", func(t *testing.T) {
		evtsCache.Delete(ourPid)
		if _, _, found := evtsCache.IsInStore(ourPid, nil); !found {
			t.Error("PID deleted from cache. The PID should be kept in cache until it exits")
		}
	})
}

// Test that dead processes which have exceeded the TTL time, are deleted from
// the cache.
func TestCacheEventsDeleteOldItems(t *testing.T) {
	fakePid := 1234
	evtsCache := NewEventsStore()
	proc := createNewProc(fakePid)
	proc.Path = "/tmp/1234"
	evtsCache.Add(proc)

	t.Run("PID isInStoreByPID()", func(t *testing.T) {
		item, found := evtsCache.IsInStoreByPID(fakePid)
		if !found {
			t.Error("PID not found in cache:", fakePid, item)
		}
		if item.Proc.Path != proc.Path {
			t.Error("invalid item returned:", fakePid, item)
		}
	})

	t.Run("DeleteOldItems()", func(t *testing.T) {
		pidTTL = 1
		time.Sleep(1 * time.Second)
		evtsCache.DeleteOldItems()
	})

	t.Run("Len()", func(t *testing.T) {
		if evtsCache.Len() > 0 {
			t.Error("cache Len() should be 0:", evtsCache)
		}
	})
}

func BenchmarkAdd(b *testing.B) {
	proc := NewProcessEmpty(1, "comm")
	proc.Path = "/proc/self/exe"
	for i := 0; i < b.N; i++ {
		EventsCache.Add(proc)
	}
}

func BenchmarkIsInStoreByPID(b *testing.B) {
	proc := NewProcessEmpty(1, "comm")
	proc.Path = "/proc/self/exe"
	EventsCache.Add(proc)
	for i := 0; i < b.N; i++ {
		EventsCache.IsInStoreByPID(1)
	}
}

func BenchmarkIsNOTInStoreByPID(b *testing.B) {
	proc := NewProcessEmpty(1, "comm")
	proc.Path = "/proc/self/exe"
	EventsCache.Add(proc)
	for i := 0; i < b.N; i++ {
		EventsCache.IsInStoreByPID(2)
	}
}

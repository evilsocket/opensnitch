package procmon

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evilsocket/opensnitch/daemon/netlink/procmon"
)

// These tests never call NewEventsStore() nor replace EventsCache: that
// races with monitorEventsCache under -race. They add and remove their own
// entries in the shared EventsCache instead.

type treeNode struct {
	path string
	pid  int
}

// startChain starts test -> sh -> sleep and returns the pids of sleep and sh.
func startChain(t *testing.T) (child, parent int) {
	t.Helper()
	cmd := exec.Command("sh", "-c", `sh -c 'echo $$; exec sleep 30'; :`)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	child, err = strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscallKill(child) })
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if exe, _ := os.Readlink("/proc/" + strconv.Itoa(child) + "/exe"); strings.HasSuffix(exe, "/sleep") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("inner shell did not exec sleep")
		}
	}
	return child, cmd.Process.Pid
}

func syscallKill(pid int) {
	if p, err := os.FindProcess(pid); err == nil {
		p.Kill()
	}
}

// liveTree walks /proc/<pid>/stat up to the process whose PPID is 0, with
// the same primitives the daemon uses, but without GetParent or BuildTree.
func liveTree(t *testing.T, pid int) []treeNode {
	t.Helper()
	var tree []treeNode
	for pid != 0 {
		p := NewProcessEmpty(pid, "")
		if err := p.ReadPath(); err != nil {
			if errors.Is(err, os.ErrPermission) {
				t.Skipf("cannot read /proc/%d/exe as this user (an ancestor is owned by root): %v", pid, err)
			}
			t.Fatalf("reading /proc/%d/exe: %v", pid, err)
		}
		p.ReadPPID()
		tree = append(tree, treeNode{p.Path, pid})
		pid = p.PPID
	}
	if tree[len(tree)-1].pid != 1 {
		t.Fatalf("live tree does not reach PID 1: %v", tree)
	}
	return tree
}

func treeOf(p *Process) []treeNode {
	tree := make([]treeNode, 0, len(p.Tree))
	for _, n := range p.Tree {
		tree = append(tree, treeNode{n.Key, int(n.Value)})
	}
	return tree
}

func sameTree(a, b []treeNode) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// checkParentChain asserts that the Parent chain (what process.parent.path
// rules match on) lists the same ancestors as the Tree.
func checkParentChain(t *testing.T, p *Process) {
	t.Helper()
	i := 1
	for pp := p.Parent; pp != nil; pp = pp.Parent {
		if i >= len(p.Tree) || pp.Path != p.Tree[i].Key || uint32(pp.ID) != p.Tree[i].Value {
			t.Fatalf("Parent chain differs from Tree at %d: %s/%d, tree %v", i, pp.Path, pp.ID, treeOf(p))
		}
		i++
	}
	if i != len(p.Tree) {
		t.Fatalf("Parent chain has %d entries, Tree has %d", i, len(p.Tree))
	}
}

func uncache(pid int) {
	EventsCache.mu.Lock()
	delete(EventsCache.eventByPID, pid)
	EventsCache.mu.Unlock()
}

func TestExecEventExitedProcess(t *testing.T) {
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	if _, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		t.Fatalf("pid %d still exists", pid)
	}
	t.Cleanup(func() { uncache(pid) })

	// Must not panic: with no readable /proc/<pid>/stat there is no Parent.
	proc := onExecEvent(procmon.ProcEvent{PID: uint32(pid), TGID: uint32(pid)})
	if proc.Parent != nil {
		t.Errorf("exited process got a parent: %d %q", proc.Parent.ID, proc.Parent.Path)
	}
	if _, found := EventsCache.IsInStoreByPID(pid); found {
		t.Error("exited process without a path was cached")
	}
}

func TestExecEventLiveProcess(t *testing.T) {
	child, parent := startChain(t)
	t.Cleanup(func() { uncache(child) })
	want := liveTree(t, child)

	proc := onExecEvent(procmon.ProcEvent{PID: uint32(child), TGID: uint32(child)})
	if proc.Path != want[0].path || proc.PPID != parent {
		t.Fatalf("got path %q ppid %d, want %q %d", proc.Path, proc.PPID, want[0].path, parent)
	}
	if got := treeOf(proc); !sameTree(got, want) {
		t.Fatalf("tree\n got %v\nwant %v", got, want)
	}
	checkParentChain(t, proc)
	if item, found := EventsCache.IsInStoreByPID(child); !found || item.Proc.Path != want[0].path {
		t.Fatal("exec'd process not cached")
	}
}

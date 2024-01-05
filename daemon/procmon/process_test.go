package procmon

import (
	"os"
	"testing"
)

var (
	myPid = os.Getpid()
	proc  = NewProcessEmpty(myPid, "fakeComm")
)

func TestNewProcess(t *testing.T) {
	if proc.ID != myPid {
		t.Error("NewProcess PID not equal to ", myPid)
	}
	if proc.Comm != "fakeComm" {
		t.Error("NewProcess Comm not equal to fakeComm")
	}
}

func TestProcPath(t *testing.T) {
	if err := proc.ReadPath(); err != nil {
		t.Error("Proc path error:", err)
	}
	if proc.Path == "/fake/path" {
		t.Error("Proc path equal to /fake/path, should be different:", proc.Path)
	}
}

func TestProcCwd(t *testing.T) {
	err := proc.ReadCwd()

	if proc.CWD == "" {
		t.Error("Proc readCwd() not read:", err)
	}
}

func TestProcCmdline(t *testing.T) {
	proc.ReadCmdline()

	if len(proc.Args) == 0 {
		t.Error("Proc Args should not be empty:", proc.Args)
	}
}

func TestProcDescriptors(t *testing.T) {
	proc.readDescriptors()

	if len(proc.Descriptors) == 0 {
		t.Error("Proc Descriptors should not be empty:", proc.Descriptors)
	}
}

func TestProcEnv(t *testing.T) {
	proc.ReadEnv()

	if len(proc.Env) == 0 {
		t.Error("Proc Env should not be empty:", proc.Env)
	}
}

func TestProcIOStats(t *testing.T) {
	err := proc.readIOStats()

	if err != nil {
		t.Error("error reading proc IOStats:", err)
	}
}

func TestProcStatus(t *testing.T) {
	proc.readStatus()

	if proc.Status == "" {
		t.Error("Proc Status should not be empty:", proc)
	}
	if proc.Stat == "" {
		t.Error("Proc Stat should not be empty:", proc)
	}
	/*if proc.Stack == "" {
		t.Error("Proc Stack should not be empty:", proc)
	}*/
	if proc.Maps == "" {
		t.Error("Proc Maps should not be empty:", proc)
	}
	if proc.Statm.Size == 0 {
		t.Error("Proc Statm Size should not be 0:", proc.Statm)
	}
	if proc.Statm.Resident == 0 {
		t.Error("Proc Statm Resident should not be 0:", proc.Statm)
	}
	if proc.Statm.Shared == 0 {
		t.Error("Proc Statm Shared should not be 0:", proc.Statm)
	}
	if proc.Statm.Text == 0 {
		t.Error("Proc Statm Text should not be 0:", proc.Statm)
	}
	if proc.Statm.Lib != 0 {
		t.Error("Proc Statm Lib should not be 0:", proc.Statm)
	}
	if proc.Statm.Data == 0 {
		t.Error("Proc Statm Data should not be 0:", proc.Statm)
	}
	if proc.Statm.Dt != 0 {
		t.Error("Proc Statm Dt should not be 0:", proc.Statm)
	}
}

func TestProcCleanPath(t *testing.T) {
	proc.Path = "/fake/path/binary (deleted)"
	proc.CleanPath()
	if proc.Path != "/fake/path/binary" {
		t.Error("Proc cleanPath() not cleaned:", proc.Path)
	}
}

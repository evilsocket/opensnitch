package procmon

import (
	"os"
	"testing"
)

var (
	myPid = os.Getpid()
	proc  = NewProcess(myPid, "/fake/path")
)

func TestNewProcess(t *testing.T) {
	if proc.ID != myPid {
		t.Error("NewProcess PID not equal to ", myPid)
	}
	if proc.Path != "/fake/path" {
		t.Error("NewProcess path not equal to /fake/path")
	}
}

func TestProcPath(t *testing.T) {
	if err := proc.readPath(); err != nil {
		t.Error("Proc path error:", err)
	}
	if proc.Path == "/fake/path" {
		t.Error("Proc path equal to /fake/path, should be different:", proc.Path)
	}
}

func TestProcCwd(t *testing.T) {
	err := proc.readCwd()

	if proc.CWD == "" {
		t.Error("Proc readCwd() not read:", err)
	}

	proc.setCwd("/home")
	if proc.CWD != "/home" {
		t.Error("Proc setCwd() should be /home:", proc.CWD)
	}
}

func TestProcCmdline(t *testing.T) {
	proc.readCmdline()

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
	proc.readEnv()

	if len(proc.Env) == 0 {
		t.Error("Proc Env should not be empty:", proc.Env)
	}
}

func TestProcIOStats(t *testing.T) {
	proc.readIOStats()

	if proc.IOStats.RChar == 0 {
		t.Error("Proc.IOStats.RChar should not be 0:", proc.IOStats)
	}
	if proc.IOStats.WChar == 0 {
		t.Error("Proc.IOStats.WChar should not be 0:", proc.IOStats)
	}
	if proc.IOStats.SyscallRead == 0 {
		t.Error("Proc.IOStats.SyscallRead should not be 0:", proc.IOStats)
	}
	if proc.IOStats.SyscallWrite == 0 {
		t.Error("Proc.IOStats.SyscallWrite should not be 0:", proc.IOStats)
	}
	/*if proc.IOStats.ReadBytes == 0 {
		t.Error("Proc.IOStats.ReadBytes should not be 0:", proc.IOStats)
	}
	if proc.IOStats.WriteBytes == 0 {
		t.Error("Proc.IOStats.WriteBytes should not be 0:", proc.IOStats)
	}*/
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
	proc.cleanPath()
	if proc.Path != "/fake/path/binary" {
		t.Error("Proc cleanPath() not cleaned:", proc.Path)
	}
}

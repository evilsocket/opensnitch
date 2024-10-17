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
	proc.pathEnviron = "testdata/proc-environ"
	proc.ReadEnv()

	expected := map[string]string{
		"EMPTY":                    "",
		"TEST1":                    "xxx=123",
		"TEST2":                    "xxx=123==456",
		"SSH_AGENT_PID":            "4873",
		"XDG_CURRENT_DESKTOP":      "i3",
		"USER":                     "opensnitch",
		"HOME":                     "/tmp",
		"XDG_DATA_DIRS":            "/usr/share/gnome:/var/lib/flatpak/exports/share:/usr/local/share:/usr/share",
		"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
		// Test latest var
		"LS_COLORS": "rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;",

		//"LAST":      "",
	}

	for k, v := range expected {
		if env, found := proc.Env[k]; !found || env != v {
			t.Error("Proc Env error, expected", ":", v, "got:", env, "(", k, ")")
		}
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

func BenchmarkProcReadEnv(b *testing.B) {
	for i := 0; i < b.N; i++ {
		proc.ReadEnv()
	}
}

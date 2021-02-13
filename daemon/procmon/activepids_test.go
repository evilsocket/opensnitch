package procmon

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

//TestMonitorActivePids starts helper processes, adds them to activePids
//and then kills them and checks if monitorActivePids() removed the killed processes
//from activePids
func TestMonitorActivePids(t *testing.T) {

	if os.Getenv("helperBinaryMode") == "on" {
		//we are in the "helper binary" mode, we were started with helperCmd.Start() (see below)
		//do nothing, just wait to be killed
		time.Sleep(time.Second * 10)
		os.Exit(1) //will never get here; but keep it here just in case
	}

	//we are in a normal "go test" mode
	tmpDir := "/tmp/ostest_" + randString()
	os.Mkdir(tmpDir, 0777)
	fmt.Println("tmp dir", tmpDir)
	defer os.RemoveAll(tmpDir)

	go monitorActivePids()

	//build a "helper binary" with "go test -c -o /tmp/path" and put it into a tmp dir
	helperBinaryPath := tmpDir + "/helper1"
	goExecutable, _ := exec.LookPath("go")
	cmd := exec.Command(goExecutable, "test", "-c", "-o", helperBinaryPath)
	if err := cmd.Run(); err != nil {
		t.Error("Error running go test -c", err)
	}

	var numberOfHelpers = 5
	var helperProcs []*Process
	//start helper binaries
	for i := 0; i < numberOfHelpers; i++ {
		var helperCmd *exec.Cmd
		helperCmd = &exec.Cmd{
			Path: helperBinaryPath,
			Args: []string{helperBinaryPath},
			Env:  []string{"helperBinaryMode=on"},
		}
		if err := helperCmd.Start(); err != nil {
			t.Error("Error starting helper binary", err)
		}
		go func() {
			helperCmd.Wait() //must Wait(), otherwise the helper process becomes a zombie when kill()ed
		}()

		pid := helperCmd.Process.Pid
		proc := NewProcess(pid, helperBinaryPath)
		helperProcs = append(helperProcs, proc)
		addToActivePidsCache(uint32(pid), proc)
	}
	//sleep to make sure all processes started before we proceed
	time.Sleep(time.Second * 1)
	//make sure all PIDS are in the cache
	for i := 0; i < numberOfHelpers; i++ {
		proc := helperProcs[i]
		pid := proc.ID
		foundProc := findProcessInActivePidsCache(uint32(pid))
		if foundProc == nil {
			t.Error("PID not found among active processes", pid)
		}
		if proc.Path != foundProc.Path || proc.ID != foundProc.ID {
			t.Error("PID or path doesn't match with the found process")
		}
	}
	//kill all helpers except for one
	for i := 0; i < numberOfHelpers-1; i++ {
		if err := syscall.Kill(helperProcs[i].ID, syscall.SIGTERM); err != nil {
			t.Error("error in syscall.Kill", err)
		}
	}
	//give the cache time to remove killed processes
	time.Sleep(time.Second * 1)

	//make sure only the alive process is in the cache
	foundProc := findProcessInActivePidsCache(uint32(helperProcs[numberOfHelpers-1].ID))
	if foundProc == nil {
		t.Error("last alive PID is not found among active processes", foundProc)
	}
	if len(activePids) != 1 {
		t.Error("more than 1 active PIDs left in cache")
	}
}

func randString() string {
	rand.Seed(time.Now().UnixNano())
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 10)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

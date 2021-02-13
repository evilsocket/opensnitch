package procmon

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
)

type value struct {
	Process *Process
	//Starttime uniquely identifies a process, it is the 22nd value in /proc/<PID>/stat
	//if another process starts with the same PID, it's Starttime will be unique
	Starttime uint32
}

var (
	activePids     = make(map[uint32]value)
	activePidsLock = sync.RWMutex{}
)

//monitorActivePids checks that each process in activePids
//is still running and if not running (or another process with the same pid is running),
//removes the pid from activePids
func monitorActivePids() {
	for {
		time.Sleep(time.Second)
		activePidsLock.Lock()
		for k, v := range activePids {
			data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", k))
			if err != nil {
				//file does not exists, pid has quit
				delete(activePids, k)
				continue
			}
			startTime, err := strconv.Atoi(strings.Split(string(data), " ")[21])
			if err != nil {
				log.Error("Could not find or convert Starttime. This should never happen. Please report this incident to the Opensnitch developers.")
				delete(activePids, k)
				continue
			}
			if uint32(startTime) != v.Starttime {
				//extremely unlikely: the original process has quit and another process
				//was started with the same PID - all this in less than 1 second
				log.Error("Same PID but different Starttime. Please report this incident to the Opensnitch developers.")
				delete(activePids, k)
				continue
			}
		}
		activePidsLock.Unlock()
	}
}

func findProcessInActivePidsCache(pid uint32) *Process {
	activePidsLock.Lock()
	defer activePidsLock.Unlock()
	if value, ok := activePids[pid]; ok {
		return value.Process
	}
	return nil
}

func addToActivePidsCache(pid uint32, proc *Process) {

	data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		//most likely the process has quit by now
		return
	}
	startTime, err2 := strconv.Atoi(strings.Split(string(data), " ")[21])
	if err2 != nil {
		log.Error("Could not find or convert Starttime. This should never happen. Please report this incident to the Opensnitch developers.")
		return
	}

	activePidsLock.Lock()
	activePids[pid] = value{
		Process:   proc,
		Starttime: uint32(startTime),
	}
	activePidsLock.Unlock()
}

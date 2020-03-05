// Package audit reads auditd events from the builtin af_unix plugin, and parses
// the messages in order to proactively monitor pids which make connections.
// Once a connection is made and redirected to us via NFQUEUE, we
// lookup the connection inode in /proc, and add the corresponding PID with all
// the information of the process to a list of known PIDs.
//
// TODO: Prompt the user to allow/deny a connection/program as soon as it's
// started.
//
// Requisities:
// - install auditd and audisp-plugins
// - enable af_unix plugin /etc/audisp/plugins.d/af_unix.conf (active = yes)
// - auditctl -a always,exit -F arch=b64 -S socket,connect,execve -k opensnitchd
// - increase /etc/audisp/audispd.conf q_depth if there're dropped events
// - set write_logs to no if you don't need/want audit logs to be stored in the disk.
//
// Audit event fields:
// https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/app-Audit_Reference.html
// Record types:
// https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/sec-Audit_Record_Types.html
package audit

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/gustavo-iniguez-goya/opensnitch/daemon/core"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
)

// Event represents an audit event, which in our case can be an event of type
// socket, execve, socketpair or connect.
type Event struct {
	Timestamp   string // audit(xxxxxxx:nnnn)
	Serial      string
	ProcName    string // comm
	ProcPath    string // exe
	ProcCmdLine string // proctitle
	ProcDir     string // cwd
	ProcMode    string // mode
	TTY         string
	Pid         int
	Uid         int
	Gid         int
	PPid        int
	EUid        int
	EGid        int
	OUid        int
	OGid        int
	UserName    string // auid
	DstHost     net.IP
	DstPort     int
	NetFamily   string // inet, inet6, local
	Success     string
	INode       int
	Dev         string
	Syscall     int
	Exit        int
	EventType   string
	RawEvent    string
	LastSeen    time.Time
}

// MAX_EVENT_AGE is the maximum minutes an audit process can live without network activity.
const (
	MAX_EVENT_AGE = int(10)
)

var (
	Lock      sync.RWMutex
	Events    []*Event
	EventChan = (chan Event)(nil)
	stop      = false
	// TODO: we may need arm arch
	rule64       = []string{"exit,always", "-F", "arch=b64", "-S", "socket,connect", "-k", "opensnitch"}
	rule32       = []string{"exit,always", "-F", "arch=b32", "-S", "socket,connect", "-k", "opensnitch"}
	audispd_path = "/var/run/audispd_events"
	ourPid       = os.Getpid()
)

// OPENSNITCH_RULES_KEY is the mark we place on every event we are interested in.
const (
	OPENSNITCH_RULES_KEY = "key=\"opensnitch\""
)

func GetEvents() []*Event {
	return Events
}

func GetEventByPid(pid int) *Event {
	Lock.RLock()
	defer Lock.RUnlock()

	for _, event := range Events {
		if pid == event.Pid {
			return event
		}
	}

	return nil
}

// sortEvents sorts received events by time and elapsed time since latest network activity.
// newest PIDs will be placed on top of the list.
func sortEvents() {
	sort.Slice(Events, func(i, j int) bool {
		now := time.Now()
		elapsedTimeT := now.Sub(Events[i].LastSeen)
		elapsedTimeU := now.Sub(Events[j].LastSeen)
		t := Events[i].LastSeen.UnixNano()
		u := Events[j].LastSeen.UnixNano()
		return t > u && elapsedTimeT < elapsedTimeU
	})
}

// CleanoldEvents deletes the PIDs which do not exist or that are too old to
// live.
// We start searching from the oldest to the newest.
// If the last network activity of a PID has been greater than MAX_EVENT_AGE,
// then it'll be deleted.
func cleanOldEvents() {
	for n := len(Events) - 1; n >= 0; n-- {
		now := time.Now()
		elapsedTime := now.Sub(Events[n].LastSeen)
		if int(elapsedTime.Minutes()) >= MAX_EVENT_AGE {
			Events = append(Events[:n], Events[n+1:]...)
			continue
		}
		if core.Exists(fmt.Sprint("/proc/", Events[n].Pid)) == false {
			Events = append(Events[:n], Events[n+1:]...)
		}
	}
}

func DeleteEvent(pid int) {
	for n, _ := range Events {
		if Events[n].Pid == pid || Events[n].PPid == pid {
			DeleteEventByIndex(n)
			break
		}
	}
}

func DeleteEventByIndex(index int) {
	Lock.Lock()
	Events = append(Events[:index], Events[index+1:]...)
	Lock.Unlock()
}

// AddEvent adds new event to the list of PIDs which have generate network
// activity.
// If the PID is already in the list, the LastSeen field is updated, to keep
// it alive.
func AddEvent(aevent *Event) {
	if aevent == nil {
		return
	}
	Lock.Lock()
	defer Lock.Unlock()

	cleanOldEvents()
	for n := 0; n < len(Events); n++ {
		if Events[n].Pid == aevent.Pid {
			aevent.LastSeen = time.Now()
			Events[n] = aevent
			return
		}
	}
	aevent.LastSeen = time.Now()
	Events = append(Events, aevent)
	sortEvents()
}

func addRules() bool {
	r64 := append([]string{"-A"}, rule64...)
	r32 := append([]string{"-A"}, rule32...)
	_, err64 := core.Exec("auditctl", r64)
	_, err32 := core.Exec("auditctl", r32)
	if err64 == nil && err32 == nil {
		return true
	}
	log.Error("Error adding audit rule, err32=%v, err=%v", err32, err64)
	return false
}

func deleteRules() bool {
	r64 := append([]string{"-d"}, rule64...)
	r32 := append([]string{"-d"}, rule32...)
	_, err64 := core.Exec("auditctl", r64)
	_, err32 := core.Exec("auditctl", r32)
	if err64 == nil && err32 == nil {
		return true
	}
	log.Error("Error deleting audit rules, err32=%v, err64=%v", err32, err64)
	return false
}

func checkRules() bool {
	// TODO
	return true
}

func checkStatus() bool {
	// TODO
	return true
}

// Reader reads events from audisd af_unix pipe plugin.
// If the auditd daemon is stopped or restarted, the reader handle
// is closed, so we need to restablished the connection.
func Reader(r io.Reader, eventChan chan<- Event) {
	if r == nil {
		log.Error("Error reading auditd events. Is auditd running? is af_unix plugin enabled?")
		return
	}
	reader := bufio.NewReader(r)

	for {
		Lock.RLock()
		if stop == true {
			log.Important("audit: closing reader and exiting")
			Lock.RUnlock()
			break
		}
		Lock.RUnlock()
		buf, _, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				log.Error("AuditReader: auditd stopped, reconnecting in 30s", err)
				if new_reader, err := reconnect(); err == nil {
					reader = bufio.NewReader(new_reader)
					log.Important("Auditd reconnected, continue reading")
				}
				continue
			}
			log.Error("AuditReader: auditd error", err)
		}

		parseEvent(string(buf[0:len(buf)]), eventChan)
	}
}

// StartChannel creates a channel to receive events from Audit.
// Launch audit.Reader() in a goroutine:
// go audit.Reader(c, (chan<- audit.Event)(audit.EventChan))
func StartChannel() {
	EventChan = make(chan Event, 0)
}

func reconnect() (net.Conn, error) {
	deleteRules()
	time.Sleep(30 * time.Second)
	return connect()
}

func connect() (net.Conn, error) {
	addRules()
	// TODO: make the unix socket path configurable
	return net.Dial("unix", audispd_path)
}

func Stop() {
	Lock.Lock()
	stop = true
	Lock.Unlock()

	deleteRules()
	if EventChan != nil {
		close(EventChan)
	}
}

func Start() (net.Conn, error) {
	c, err := connect()
	if err != nil {
		log.Error("auditd connection error %v", err)
		deleteRules()
	}
	return c, err
}

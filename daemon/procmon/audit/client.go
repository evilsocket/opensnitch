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
// - install auditd and audispd-plugins
// - enable af_unix plugin /etc/audisp/plugins.d/af_unix.conf (active = yes)
// - auditctl -a always,exit -F arch=b64 -S socket,connect,execve -k opensnitchd
// - increase /etc/audisp/audispd.conf q_depth if there're dropped events
// - set write_logs to no if you don't need/want audit logs to be stored in the disk.
//
// read messages from the pipe to verify that it's working:
// socat unix-connect:/var/run/audispd_events stdio
//
// Audit event fields:
// https://github.com/linux-audit/audit-documentation/blob/master/specs/fields/field-dictionary.csv
// Record types:
// https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/sec-Audit_Record_Types.html
//
// Documentation:
// https://github.com/linux-audit/audit-documentation
package audit

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
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
	UID         int
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

// MaxEventAge is the maximum minutes an audit process can live without network activity.
const (
	MaxEventAge = int(10)
)

var (
	// Lock holds a mutex
	Lock   sync.RWMutex
	ourPid = os.Getpid()
	// cache of events
	events            []*Event
	eventsCleaner     *time.Ticker
	eventsCleanerChan = (chan bool)(nil)
	// TODO: EventChan is an output channel where incoming auditd events will be written.
	// If a client opens it.
	EventChan      = (chan Event)(nil)
	eventsExitChan = (chan bool)(nil)
	auditConn      net.Conn
	// TODO: we may need arm arch
	rule64      = []string{"exit,always", "-F", "arch=b64", "-F", fmt.Sprint("ppid!=", ourPid), "-F", fmt.Sprint("pid!=", ourPid), "-S", "socket,connect", "-k", "opensnitch"}
	rule32      = []string{"exit,always", "-F", "arch=b32", "-F", fmt.Sprint("ppid!=", ourPid), "-F", fmt.Sprint("pid!=", ourPid), "-S", "socketcall", "-F", "a0=1", "-k", "opensnitch"}
	audispdPath = "/var/run/audispd_events"
)

// OPENSNITCH_RULES_KEY is the mark we place on every event we are interested in.
const (
	OpensnitchRulesKey = "key=\"opensnitch\""
)

// GetEvents returns the list of processes which have opened a connection.
func GetEvents() []*Event {
	return events
}

// GetEventByPid returns an event given a pid.
func GetEventByPid(pid int) *Event {
	Lock.RLock()
	defer Lock.RUnlock()

	for _, event := range events {
		if pid == event.Pid {
			return event
		}
	}

	return nil
}

// sortEvents sorts received events by time and elapsed time since latest network activity.
// newest PIDs will be placed on top of the list.
func sortEvents() {
	sort.Slice(events, func(i, j int) bool {
		now := time.Now()
		elapsedTimeT := now.Sub(events[i].LastSeen)
		elapsedTimeU := now.Sub(events[j].LastSeen)
		t := events[i].LastSeen.UnixNano()
		u := events[j].LastSeen.UnixNano()
		return t > u && elapsedTimeT < elapsedTimeU
	})
}

// cleanOldEvents deletes the PIDs which do not exist or that are too old to
// live.
// We start searching from the oldest to the newest.
// If the last network activity of a PID has been greater than MaxEventAge,
// then it'll be deleted.
func cleanOldEvents() {
	Lock.Lock()
	defer Lock.Unlock()

	for n := len(events) - 1; n >= 0; n-- {
		now := time.Now()
		elapsedTime := now.Sub(events[n].LastSeen)
		if int(elapsedTime.Minutes()) >= MaxEventAge {
			events = append(events[:n], events[n+1:]...)
			continue
		}
		if core.Exists(fmt.Sprint("/proc/", events[n].Pid)) == false {
			events = append(events[:n], events[n+1:]...)
		}
	}
}

func deleteEvent(pid int) {
	for n := range events {
		if events[n].Pid == pid || events[n].PPid == pid {
			deleteEventByIndex(n)
			break
		}
	}
}

func deleteEventByIndex(index int) {
	Lock.Lock()
	events = append(events[:index], events[index+1:]...)
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

	for n := 0; n < len(events); n++ {
		if events[n].Pid == aevent.Pid && events[n].Syscall == aevent.Syscall {
			if aevent.ProcCmdLine != "" || (aevent.ProcCmdLine == events[n].ProcCmdLine) {
				events[n] = aevent
			}
			events[n].LastSeen = time.Now()

			sortEvents()
			return
		}
	}
	aevent.LastSeen = time.Now()
	events = append([]*Event{aevent}, events...)
}

// startEventsCleaner will review if the events in the cache need to be cleaned
// every 5 minutes.
func startEventsCleaner() {
	for {
		select {
		case <-eventsCleanerChan:
			goto Exit
		case <-eventsCleaner.C:
			cleanOldEvents()
		}
	}
Exit:
	log.Debug("audit: cleanerRoutine stopped")
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

func configureSyscalls() {
	// XXX: what about a i386 process running on a x86_64 system?
	if runtime.GOARCH == "386" {
		syscallSOCKET = "1"
		syscallCONNECT = "3"
		syscallSOCKETPAIR = "8"
	}
}

func deleteRules() bool {
	r64 := []string{"-D", "-k", "opensnitch"}
	r32 := []string{"-D", "-k", "opensnitch"}
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
	go startEventsCleaner()

	for {
		select {
		case <-eventsExitChan:
			goto Exit
		default:
			buf, _, err := reader.ReadLine()
			if err != nil {
				if err == io.EOF {
					log.Error("AuditReader: auditd stopped, reconnecting in 30s %s", err)
					if newReader, err := reconnect(); err == nil {
						reader = bufio.NewReader(newReader)
						log.Important("Auditd reconnected, continue reading")
					}
					continue
				}
				log.Warning("AuditReader: auditd error %s", err)
				break
			}

			parseEvent(string(buf[0:len(buf)]), eventChan)
		}
	}
Exit:
	log.Debug("audit.Reader() closed")
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
	return net.Dial("unix", audispdPath)
}

// Stop stops listening for events from auditd and delete the auditd rules.
func Stop() {
	if auditConn != nil {
		if err := auditConn.Close(); err != nil {
			log.Warning("audit.Stop() error closing socket: %v", err)
		}
	}

	if eventsCleaner != nil {
		eventsCleaner.Stop()
	}
	if eventsExitChan != nil {
		eventsExitChan <- true
		close(eventsExitChan)
	}
	if eventsCleanerChan != nil {
		eventsCleanerChan <- true
		close(eventsCleanerChan)
	}

	deleteRules()
	if EventChan != nil {
		close(EventChan)
	}
}

// Start makes a new connection to the audisp af_unix socket.
func Start() (net.Conn, error) {
	auditConn, err := connect()
	if err != nil {
		log.Error("auditd Start() connection error %v", err)
		deleteRules()
		return nil, err
	}

	configureSyscalls()
	eventsCleaner = time.NewTicker(time.Minute * 5)
	eventsCleanerChan = make(chan bool)
	eventsExitChan = make(chan bool)
	return auditConn, err
}

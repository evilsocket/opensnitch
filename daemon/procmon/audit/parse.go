package audit

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
	"github.com/mozilla/libaudit-go"
)

var (
	newEvent = false
	netEvent = &Event{}
)

const (
	SYSCALL_SOCKET     = "41"
	SYSCALL_CONNECT    = "42"
	SYSCALL_SOCKETPAIR = "53"
	SYSCALL_EXECVE     = "59"

	// /usr/include/x86_64-linux-gnu/bits/socket_type.h
	SOCK_STREAM    = "1"
	SOCK_DGRAM     = "2"
	SOCK_RAW       = "3"
	SOCK_SEQPACKET = "5"
	SOCK_PACKET    = "10"

	// /usr/include/x86_64-linux-gnu/bits/socket.h
	PF_UNSPEC = "0"
	PF_LOCAL  = "1" // PF_UNIX
	PF_INET   = "2"
	PF_INET6  = "10"

	// /etc/protocols
	PROTO_IP  = "0"
	PROTO_TCP = "6"
	PROTO_UDP = "17"
)

const (
	AUDIT_TYPE_PROCTITLE = "type=PROCTITLE"
	AUDIT_TYPE_CWD       = "type=CWD"
	AUDIT_TYPE_PATH      = "type=PATH"
	AUDIT_TYPE_EXECVE    = "type=EXECVE"
	AUDIT_TYPE_SOCKADDR  = "type=SOCKADDR"
	AUDIT_TYPE_EOE       = "type=EOE"
)

var (
	SYSCALL_SOCKET_STR     = fmt.Sprint("syscall=", syscall.SYS_SOCKET)
	SYSCALL_CONNECT_STR    = fmt.Sprint("syscall=", syscall.SYS_CONNECT)
	SYSCALL_SOCKETPAIR_STR = fmt.Sprint("syscall=", syscall.SYS_SOCKETPAIR)
	SYSCALL_EXECVE_STR     = fmt.Sprint("syscall=", syscall.SYS_EXECVE)
)

func isFromOurPid(pid, ppid string) bool {
	return pid == strconv.Itoa(ourPid) || ppid == strconv.Itoa(ourPid)
}

// parse raw SOCKADDR saddr string: inet6 host:2001:4860:4860::8888 serv:53
func parseNetLine(line string, decode bool) (family string, dstHost net.IP, dstPort int) {
	if decode == true {
		line = decodeString(line)
	}
	pieces := strings.Split(line, " ")
	family = pieces[0]

	if family[:4] != "inet" {
		return family, dstHost, 0
	}

	if len(pieces) > 1 && pieces[1][:5] == "host:" {
		dstHost = net.ParseIP(strings.Split(pieces[1], "host:")[1])
	}
	if len(pieces) > 2 && pieces[2][:5] == "serv:" {
		_dstPort, err := strconv.Atoi(strings.Split(line, "serv:")[1])
		if err != nil {
			dstPort = -1
		} else {
			dstPort = _dstPort
		}
	}

	return family, dstHost, dstPort
}

func decodeString(s string) string {
	if decoded, err := hex.DecodeString(s); err != nil {
		return s
	} else {
		return fmt.Sprintf("%s", decoded)
	}
}

// populateEvent populates our Event from the libaudit parsed event.
func populateEvent(aevent *Event, event libaudit.AuditEvent, err error) *Event {
	if err == nil && aevent != nil {
		Lock.Lock()
		defer Lock.Unlock()

		aevent.Timestamp = event.Timestamp
		aevent.Serial = event.Serial
		for k, v := range event.Data {
			switch k {
			case "a0":
				if event.Data["syscall"] == SYSCALL_SOCKET ||
					event.Data["syscall"] == SYSCALL_CONNECT ||
					event.Data["syscall"] == SYSCALL_SOCKETPAIR {
					// XXX: is it wort to intercept PF_LOCAL/PF_FILE as well?
					if v == PF_INET6 || v == "a" {
						aevent.NetFamily = "inet6"
					} else if v == PF_INET || v == PF_LOCAL || v == PF_UNSPEC {
						aevent.NetFamily = "inet"
					}
				}
			case "a1":
				if event.Data["syscall"] == SYSCALL_SOCKET {
					if aevent.NetFamily == "" &&
						(v == "0" || v == SOCK_STREAM || v == SOCK_DGRAM ||
							v == SOCK_RAW || v == SOCK_SEQPACKET || v == SOCK_PACKET) {
						aevent.NetFamily = "inet"
					}
				}
			case "fam":
				aevent.NetFamily = string(v)
			case "lport":
				aevent.DstPort, _ = strconv.Atoi(v)
			case "laddr":
				aevent.DstHost = net.ParseIP(string(v))
			// This depends on libaudit.ParseAuditEvent(msg, libaudit.AUDIT_SOCKADDR, true)
			/*case "saddr":
			log.Info(" ** saddr", v)
			if aevent.NetFamily == "" {
				aevent.NetFamily, aevent.DstHost, aevent.DstPort = parseNetLine(v, true)
			} else {
				_, aevent.DstHost, aevent.DstPort = parseNetLine(v, true)
			}*/
			case "exe":
				aevent.ProcPath = strings.Trim(decodeString(v), "\"")
			case "comm":
				aevent.ProcName = strings.Trim(decodeString(v), "\"")
			case "proctitle":
				aevent.ProcCmdLine = strings.Trim(decodeString(v), "\"")
			case "tty":
				aevent.TTY = string(v)
			case "pid":
				aevent.Pid, _ = strconv.Atoi(v)
			case "ppid":
				aevent.PPid, _ = strconv.Atoi(v)
			case "uid":
				aevent.Uid, _ = strconv.Atoi(v)
			case "gid":
				aevent.Gid, _ = strconv.Atoi(v)
			case "success":
				aevent.Success = string(v)
			case "cwd":
				aevent.ProcDir = string(v)
			case "inode":
				aevent.INode, _ = strconv.Atoi(v)
			case "dev":
				aevent.Dev = string(v)
			case "mode":
				aevent.ProcMode = string(v)
			case "ouid":
				aevent.OUid, _ = strconv.Atoi(v)
			case "ogid":
				aevent.OGid, _ = strconv.Atoi(v)
			case "syscall":
				aevent.Syscall, _ = strconv.Atoi(v)
			case "msgtype":
				aevent.EventType = event.Type
			}
		}
	}

	return aevent
}

// parseEvent parses an auditd event, discards the unwanted ones, and adds
// the ones we're interested in to an array.
// We're only interested in the socket,socketpair,connect and execve syscalls.
// Events from us are excluded.
//
// When we received an event, we parse and add it to the list as soon as we can.
// If the next messages of the set have additional information, we update the
// event.
func parseEvent(buf_str string, eventChan chan<- Event) {
	msg_parts := strings.Split(buf_str, "msg=")
	if len(msg_parts) < 2 {
		return
	}
	msg := msg_parts[1]

	if newEvent == false && strings.Index(buf_str, OPENSNITCH_RULES_KEY) == -1 {
		return
	}
	if strings.Index(buf_str, SYSCALL_SOCKET_STR) != -1 ||
		strings.Index(buf_str, SYSCALL_CONNECT_STR) != -1 ||
		strings.Index(buf_str, SYSCALL_SOCKETPAIR_STR) != -1 ||
		strings.Index(buf_str, SYSCALL_EXECVE_STR) != -1 {

		aevent, err := libaudit.ParseAuditEvent(msg, libaudit.AUDIT_SYSCALL, false)
		if aevent != nil && isFromOurPid(aevent.Data["pid"], aevent.Data["ppid"]) {
			return
		}

		newEvent = true
		netEvent = &Event{}
		netEvent = populateEvent(netEvent, *aevent, err)
		netEvent.RawEvent = aevent.Raw
		AddEvent(netEvent)

	} else if newEvent == true && strings.Index(buf_str, AUDIT_TYPE_PROCTITLE) != -1 {
		if aevent, err := libaudit.ParseAuditEvent(msg, libaudit.AUDIT_PROCTITLE, true); err == nil {
			netEvent = populateEvent(netEvent, *aevent, err)
			AddEvent(netEvent)
		}
		return

	} else if newEvent == true && strings.Index(buf_str, AUDIT_TYPE_CWD) != -1 {
		if aevent, err := libaudit.ParseAuditEvent(msg, libaudit.AUDIT_CWD, true); err == nil {
			netEvent = populateEvent(netEvent, *aevent, err)
			AddEvent(netEvent)
		}
		return

	} else if newEvent == true && strings.Index(buf_str, AUDIT_TYPE_EXECVE) != -1 {
		if aevent, err := libaudit.ParseAuditEvent(msg, libaudit.AUDIT_EXECVE, false); err == nil {
			netEvent = populateEvent(netEvent, *aevent, err)
			AddEvent(netEvent)
		}
		return

	} else if newEvent == true && strings.Index(buf_str, AUDIT_TYPE_PATH) != -1 {
		if aevent, err := libaudit.ParseAuditEvent(msg, libaudit.AUDIT_PATH, false); err == nil {
			netEvent = populateEvent(netEvent, *aevent, err)
			AddEvent(netEvent)
		}
		return

	} else if newEvent == true && strings.Index(buf_str, AUDIT_TYPE_SOCKADDR) != -1 {
		aevent, err := libaudit.ParseAuditEvent(msg, libaudit.AUDIT_SOCKADDR, false)
		if err != nil {
			aevent = nil
			return
		}
		if isFromOurPid(aevent.Data["pid"], aevent.Data["ppid"]) {
			return
		}

		netEvent = populateEvent(netEvent, *aevent, err)
		AddEvent(netEvent)
		if EventChan != nil {
			eventChan <- *netEvent
		}

	} else if newEvent == true && strings.Index(buf_str, AUDIT_TYPE_EOE) != -1 {
		newEvent = false
		if syscall.SYS_SOCKET == netEvent.Syscall && (netEvent.NetFamily == "" || netEvent.NetFamily[:4] != "inet") {
			log.Warning("Excluding event EOE", netEvent.NetFamily, netEvent)
			return
		}
		if netEvent.Pid == ourPid || netEvent.PPid == ourPid {
			return
		}

		AddEvent(netEvent)
		if EventChan != nil {
			eventChan <- *netEvent
		}
	}
}

package audit

import (
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var (
	newEvent = false
	netEvent = &Event{}

	// RegExp for parse audit messages
	// https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-understanding_audit_log_files
	auditRE, _ = regexp.Compile(`([a-zA-Z0-9\-_]+)=([a-zA-Z0-9:'\-\/\"\.\,_\(\)]+)`)
	rawEvent   = make(map[string]string)
)

// amd64 syscalls definition
// if the platform is not amd64, it's redefined on Start()
var (
	syscallSOCKET     = "41"
	syscallCONNECT    = "42"
	syscallSOCKETPAIR = "53"
	syscallEXECVE     = "59"
	syscallSOCKETCALL = "102"
)

// /usr/include/x86_64-linux-gnu/bits/socket_type.h
const (
	sockSTREAM    = "1"
	sockDGRAM     = "2"
	sockRAW       = "3"
	sockSEQPACKET = "5"
	sockPACKET    = "10"

	// /usr/include/x86_64-linux-gnu/bits/socket.h
	pfUNSPEC = "0"
	pfLOCAL  = "1" // PF_UNIX
	pfINET   = "2"
	pfINET6  = "10"

	// /etc/protocols
	protoIP  = "0"
	protoTCP = "6"
	protoUDP = "17"
)

// https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/sec-Audit_Record_Types.html
const (
	AuditTypePROCTITLE  = "type=PROCTITLE"
	AuditTypeCWD        = "type=CWD"
	AuditTypePATH       = "type=PATH"
	AuditTypeEXECVE     = "type=EXECVE"
	AuditTypeSOCKADDR   = "type=SOCKADDR"
	AuditTypeSOCKETCALL = "type=SOCKETCALL"
	AuditTypeEOE        = "type=EOE"
)

var (
	syscallSOCKETstr     = fmt.Sprint("syscall=", syscallSOCKET)
	syscallCONNECTstr    = fmt.Sprint("syscall=", syscallCONNECT)
	syscallSOCKETPAIRstr = fmt.Sprint("syscall=", syscallSOCKETPAIR)
	syscallEXECVEstr     = fmt.Sprint("syscall=", syscallEXECVE)
	syscallSOCKETCALLstr = fmt.Sprint("syscall=", syscallSOCKETCALL)
)

// parseNetLine parses a SOCKADDR message type of the form:
// saddr string: inet6 host:2001:4860:4860::8888 serv:53
func parseNetLine(line string, decode bool) (family string, dstHost net.IP, dstPort int) {

	// 0:4 - type
	// 4:8 - port
	// 8:16 - ip
	switch family := line[0:4]; family {
	// local
	// case "0100":
	// ipv4
	case "0200":
		octet2 := decodeString(line[4:8])
		octet := decodeString(line[8:16])
		host := fmt.Sprint(octet[0], ".", octet[1], ".", octet[2], ".", octet[3])
		fmt.Printf("dest ip: %s -- %s:%s\n", line[4:8], octet2, host)
		// ipv6
		//case "0A00":
	}

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

// decodeString will try to decode a string encoded in hexadecimal.
// If the string can not be decoded, the original string will be returned.
// In that case, usually it means that it's a non-encoded string.
func decodeString(s string) string {
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return s
	}
	return fmt.Sprintf("%s", decoded)
}

// extractFields parsed an audit raw message, and extracts all the fields.
func extractFields(rawMessage string, newEvent *map[string]string) {
	Lock.Lock()
	defer Lock.Unlock()

	if auditRE == nil {
		newEvent = nil
		return
	}
	fieldList := auditRE.FindAllStringSubmatch(rawMessage, -1)
	if fieldList == nil {
		newEvent = nil
		return
	}
	for _, field := range fieldList {
		(*newEvent)[field[1]] = field[2]
	}
}

// populateEvent populates our Event from a raw parsed message.
func populateEvent(aevent *Event, eventFields *map[string]string) *Event {
	if aevent == nil {
		return nil
	}
	Lock.Lock()
	defer Lock.Unlock()

	for k, v := range *eventFields {
		switch k {
		//case "a0":
		//case "a1":
		//case "a2":
		case "fam":
			if v == "local" {
				return nil
			}
			aevent.NetFamily = v
		case "lport":
			aevent.DstPort, _ = strconv.Atoi(v)
		// TODO
		/*case "addr":
			fmt.Println("addr: ", v)
		case "daddr":
			fmt.Println("daddr: ", v)
		case "laddr":
			aevent.DstHost = net.ParseIP(v)
		case "saddr":
		parseNetLine(v, true)
		fmt.Println("saddr:", v)
		*/
		case "exe":
			aevent.ProcPath = strings.Trim(decodeString(v), "\"")
		case "comm":
			aevent.ProcName = strings.Trim(decodeString(v), "\"")
		// proctitle may be truncated to 128 characters, so don't rely on it, parse /proc/<pid>/instead
		//case "proctitle":
		//	aevent.ProcCmdLine = strings.Trim(decodeString(v), "\"")
		case "tty":
			aevent.TTY = v
		case "pid":
			aevent.Pid, _ = strconv.Atoi(v)
		case "ppid":
			aevent.PPid, _ = strconv.Atoi(v)
		case "uid":
			aevent.UID, _ = strconv.Atoi(v)
		case "gid":
			aevent.Gid, _ = strconv.Atoi(v)
		case "success":
			aevent.Success = v
		case "cwd":
			aevent.ProcDir = strings.Trim(decodeString(v), "\"")
		case "inode":
			aevent.INode, _ = strconv.Atoi(v)
		case "dev":
			aevent.Dev = v
		case "mode":
			aevent.ProcMode = v
		case "ouid":
			aevent.OUid, _ = strconv.Atoi(v)
		case "ogid":
			aevent.OGid, _ = strconv.Atoi(v)
		case "syscall":
			aevent.Syscall, _ = strconv.Atoi(v)
		case "exit":
			aevent.Exit, _ = strconv.Atoi(v)
		case "type":
			aevent.EventType = v
		case "msg":
			parts := strings.Split(v[6:], ":")
			aevent.Timestamp = parts[0]
			aevent.Serial = parts[1][:len(parts[1])-1]
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
func parseEvent(rawMessage string, eventChan chan<- Event) {
	if newEvent == false && strings.Index(rawMessage, OpensnitchRulesKey) == -1 {
		return
	}

	aEvent := make(map[string]string)
	if strings.Index(rawMessage, syscallSOCKETstr) != -1 ||
		strings.Index(rawMessage, syscallCONNECTstr) != -1 ||
		strings.Index(rawMessage, syscallSOCKETPAIRstr) != -1 ||
		strings.Index(rawMessage, syscallEXECVEstr) != -1 ||
		strings.Index(rawMessage, syscallSOCKETCALLstr) != -1 {

		extractFields(rawMessage, &aEvent)
		if aEvent == nil {
			return
		}
		newEvent = true
		netEvent = &Event{}
		netEvent = populateEvent(netEvent, &aEvent)
		AddEvent(netEvent)
	} else if newEvent == true && strings.Index(rawMessage, AuditTypePROCTITLE) != -1 {
		extractFields(rawMessage, &aEvent)
		if aEvent == nil {
			return
		}
		netEvent = populateEvent(netEvent, &aEvent)
		AddEvent(netEvent)
	} else if newEvent == true && strings.Index(rawMessage, AuditTypeCWD) != -1 {
		extractFields(rawMessage, &aEvent)
		if aEvent == nil {
			return
		}
		netEvent = populateEvent(netEvent, &aEvent)
		AddEvent(netEvent)
	} else if newEvent == true && strings.Index(rawMessage, AuditTypeEXECVE) != -1 {
		extractFields(rawMessage, &aEvent)
		if aEvent == nil {
			return
		}
		netEvent = populateEvent(netEvent, &aEvent)
		AddEvent(netEvent)
	} else if newEvent == true && strings.Index(rawMessage, AuditTypePATH) != -1 {
		extractFields(rawMessage, &aEvent)
		if aEvent == nil {
			return
		}
		netEvent = populateEvent(netEvent, &aEvent)
		AddEvent(netEvent)
	} else if newEvent == true && strings.Index(rawMessage, AuditTypeSOCKADDR) != -1 {
		extractFields(rawMessage, &aEvent)
		if aEvent == nil {
			return
		}

		netEvent = populateEvent(netEvent, &aEvent)
		AddEvent(netEvent)
		if EventChan != nil {
			eventChan <- *netEvent
		}
	} else if newEvent == true && strings.Index(rawMessage, AuditTypeEOE) != -1 {
		newEvent = false
		AddEvent(netEvent)
		if EventChan != nil {
			eventChan <- *netEvent
		}
	}
}

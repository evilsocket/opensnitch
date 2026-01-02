package rule

import (
	"fmt"
	"net"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/procmon"
)

// Type is the type of rule.
// Every type has its own way of checking the user data against connections.
type Type string

// Sensitive defines if a rule is case-sensitive or not. By default no.
type Sensitive bool

// Operand is what we check on a connection.
type Operand string

// Available types
const (
	Simple  = Type("simple")
	Regexp  = Type("regexp")
	Complex = Type("complex") // for future use
	List    = Type("list")
	Network = Type("network")
	Lists   = Type("lists")
)

// Available operands
const (
	OpTrue                = Operand("true")
	OpProcessID           = Operand("process.id")
	OpProcessPath         = Operand("process.path")
	OpProcessParentPath   = Operand("process.parent.path")
	OpProcessCmd          = Operand("process.command")
	OpProcessEnvPrefix    = Operand("process.env.")
	OpProcessEnvPrefixLen = 12
	OpProcessHashMD5      = Operand("process.hash.md5")
	OpProcessHashSHA1     = Operand("process.hash.sha1")
	OpUserID              = Operand("user.id")
	OpUserName            = Operand("user.name")
	OpSrcIP               = Operand("source.ip")
	OpSrcPort             = Operand("source.port")
	OpDstIP               = Operand("dest.ip")
	OpDstHost             = Operand("dest.host")
	OpDstPort             = Operand("dest.port")
	OpDstNetwork          = Operand("dest.network")
	OpSrcNetwork          = Operand("source.network")
	OpProto               = Operand("protocol")
	OpIfaceIn             = Operand("iface.in")
	OpIfaceOut            = Operand("iface.out")
	OpList                = Operand("list")
	OpDomainsLists        = Operand("lists.domains")
	OpDomainsRegexpLists  = Operand("lists.domains_regexp")
	OpIPLists             = Operand("lists.ips")
	OpNetLists            = Operand("lists.nets")
	OpHashMD5Lists        = Operand("lists.hash.md5")

	// TODO
	//OpQuota        = Operand("quota")
	//OpQuotaTxOver  = Operand("quota.sent.over") // 1000b, 1kb, 1mb, 1gb, ...
	//OpQuotaRxOver  = Operand("quota.recv.over") // 1000b, 1kb, 1mb, 1gb, ...
)

type opCallback func(value interface{}) bool

// Operator represents what we want to filter of a connection, and how.
type Operator struct {
	cb              opCallback
	re              *regexp.Regexp
	netMask         *net.IPNet
	lists           map[string]interface{}
	exitMonitorChan chan (bool)

	Operand             Operand    `json:"operand"`
	Data                string     `json:"data"`
	Type                Type       `json:"type"`
	List                []Operator `json:"list"`
	Sensitive           Sensitive  `json:"sensitive"`
	isCompiled          bool
	listsMonitorRunning bool

	sync.RWMutex
}

// NewOperator returns a new operator object
func NewOperator(t Type, s Sensitive, o Operand, data string, list []Operator) (*Operator, error) {
	op := Operator{
		Type:      t,
		Sensitive: s,
		Operand:   o,
		Data:      data,
		List:      list,
	}
	return &op, nil
}

// Compile translates the operator type field to its callback counterpart
func (o *Operator) Compile() error {
	if o.isCompiled {
		return nil
	}

	// The only operator Type that can have the Data field empty are:
	// Simple, Regexp, List.
	// For List, because it uses List field and not Data field.
	// For Simple and Regexp, because it can be useful to match on some
	// operands that can in practice be equal to an empty string. This is the
	// case, for example, when a request has a "bare" IP instead of a domain
	// name, therefore DstHost field will be empty. You can match empty string
	// with simple comparison or the "^$" regexp pattern.
	if !(o.Type == Simple || o.Type == Regexp || o.Type == List) &&
		o.Operand != OpTrue && o.Data == "" {
		return fmt.Errorf("Operand %s cannot be empty (%s)", o.Operand, o.Type)
	}

	if o.Type == Simple {
		if o.Operand == OpUserName {
			// TODO: allow regexps, take into account users from containers.
			u, err := user.Lookup(o.Data)
			if err != nil {
				return fmt.Errorf("user.name Operand error: %s", err)
			}
			o.cb = o.simpleCmp
			o.Data = u.Uid
			return nil
		} else if o.Operand == OpProcessHashMD5 || o.Operand == OpProcessHashSHA1 {
			o.cb = o.hashCmp
			return nil
		}

		o.cb = o.simpleCmp

	} else if o.Type == Regexp {
		o.cb = o.reCmp
		if o.Sensitive == false {
			o.Data = strings.ToLower(o.Data)
		}
		re, err := regexp.Compile(o.Data)
		if err != nil {
			return err
		}
		o.re = re
	} else if o.Type == List {
		o.Operand = OpList
	} else if o.Type == Network {
		// Check if the operator's data is an alias present in the cache
		if ipNets, found := AliasIPCache[o.Data]; found {
			o.cb = func(value interface{}) bool {
				ip := value.(net.IP)
				matchFound := false

				for _, ipNet := range ipNets {
					if ipNet.Contains(ip) {
						matchFound = true
						break
					}
				}
				/*
					if !matchFound {
						fmt.Printf(" -> No match found: IP %s for alias '%s'\n", ip, o.Data)
					}
				*/
				return matchFound
			}
		} else {
			// Parse the data as a CIDR if it's not an alias
			_, netMask, err := net.ParseCIDR(o.Data)
			if err != nil {
				return fmt.Errorf("CIDR parsing error: %s", err)
			}
			o.netMask = netMask
			o.cb = o.cmpNetwork
		}
	} else if o.Type == Lists {
		if o.Operand == OpDomainsLists {
			o.loadLists()
			o.cb = o.domainsListsCmp
		} else if o.Operand == OpDomainsRegexpLists {
			o.loadLists()
			o.cb = o.reListCmp
		} else if o.Operand == OpIPLists {
			o.loadLists()
			o.cb = o.simpleListsCmp
		} else if o.Operand == OpNetLists {
			o.loadLists()
			o.cb = o.ipNetCmp
		} else if o.Operand == OpHashMD5Lists {
			o.loadLists()
			o.cb = o.simpleListsCmp
		} else {
			return fmt.Errorf("Unknown Lists operand %s", o.Operand)
		}

	} else {
		return fmt.Errorf("Unknown Operator type %s", o.Type)
	}

	log.Debug("Operator compiled: %s", o)
	o.isCompiled = true

	return nil
}

func (o *Operator) String() string {
	how := "is"
	if o.Type == Regexp {
		how = "matches"
	}
	return fmt.Sprintf("%s %s '%s'", log.Bold(string(o.Operand)), how, log.Yellow(string(o.Data)))
}

func (o *Operator) simpleCmp(v interface{}) bool {
	if o.Sensitive == false {
		return strings.EqualFold(v.(string), o.Data)
	}
	return v == o.Data
}

func (o *Operator) reCmp(v interface{}) bool {
	dstHost, ok := v.(string)
	if !ok {
		log.Warning("Operator.reCmp() bad interface type: %T", v)
		return false
	}
	if o.Sensitive == false {
		v = strings.ToLower(dstHost)
	}
	return o.re.MatchString(dstHost)
}

func (o *Operator) cmpNetwork(destIP interface{}) bool {
	// 192.0.2.1/24, 2001:db8:a0b:12f0::1/32
	if o.netMask == nil {
		log.Warning("cmpNetwork() NULL: %s", destIP)
		return false
	}
	return o.netMask.Contains(destIP.(net.IP))
}

func (o *Operator) matchListsCmp(msg, what string) bool {
	if item, found := o.lists[what]; found {
		log.Debug("%s: %s, %s", log.Red(msg), what, item)
		return true
	}
	return false
}

func (o *Operator) domainsListsCmp(v interface{}) bool {
	dstHost := v.(string)
	if dstHost == "" {
		return false
	}
	if o.Sensitive == false {
		dstHost = strings.ToLower(dstHost)
	}
	o.RLock()
	defer o.RUnlock()

	return o.matchListsCmp("domains list match", dstHost)
}

func (o *Operator) simpleListsCmp(v interface{}) bool {
	what := v.(string)
	if what == "" {
		return false
	}
	o.RLock()
	defer o.RUnlock()

	return o.matchListsCmp("simple list match", what)
}

func (o *Operator) ipNetCmp(dstIP interface{}) bool {
	o.RLock()
	defer o.RUnlock()

	for host, netMask := range o.lists {
		n := netMask.(*net.IPNet)
		if n.Contains(dstIP.(net.IP)) {
			log.Debug("%s: %s, %s", log.Red("Net list match"), dstIP, host)
			return true
		}
	}
	return false
}

func (o *Operator) reListCmp(v interface{}) bool {
	dstHost := v.(string)
	if dstHost == "" {
		return false
	}
	if o.Sensitive == false {
		dstHost = strings.ToLower(dstHost)
	}
	o.RLock()
	defer o.RUnlock()

	for file, re := range o.lists {
		r := re.(*regexp.Regexp)
		if r.MatchString(dstHost) {
			log.Debug("%s: %s, %s", log.Red("Regexp list match"), dstHost, file)
			return true
		}
	}
	return false
}

func (o *Operator) hashCmp(v interface{}) bool {
	hash := v.(string)
	if hash == "" {
		return true // fake a match to avoid displaying a pop-up
	}
	return hash == o.Data
}

func (o *Operator) listMatch(con interface{}, hasChecksums bool) bool {
	res := true
	for i := 0; i < len(o.List); i++ {
		res = res && o.List[i].Match(con.(*conman.Connection), hasChecksums)
	}
	return res
}

// Match tries to match parts of a connection with the given operator.
func (o *Operator) Match(con *conman.Connection, hasChecksums bool) bool {

	if o.Operand == OpTrue {
		return true
	} else if o.Operand == OpList {
		return o.listMatch(con, hasChecksums)
	} else if o.Operand == OpProcessPath {
		return o.cb(con.Process.Path)
	} else if o.Operand == OpProcessParentPath {
		p := con.Process
		for pp := p.Parent; pp != nil; pp = pp.Parent {
			if o.cb(pp.Path) {
				return true
			}
		}
		return false
	} else if o.Operand == OpProcessCmd {
		return o.cb(strings.Join(con.Process.Args, " "))
	} else if o.Operand == OpDstHost {
		return o.cb(con.DstHost)
	} else if o.Operand == OpDstIP {
		return o.cb(con.DstIP.String())
	} else if o.Operand == OpDstPort {
		return o.cb(strconv.FormatUint(uint64(con.DstPort), 10))
	} else if o.Operand == OpDomainsLists {
		return o.cb(con.DstHost)
	} else if o.Operand == OpIPLists {
		return o.cb(con.DstIP.String())
	} else if o.Operand == OpHashMD5Lists {
		return o.cb(con.Process.Checksums[procmon.HashMD5])
	} else if o.Operand == OpUserID || o.Operand == OpUserName {
		return o.cb(strconv.Itoa(con.Entry.UserId))
	} else if o.Operand == OpDstNetwork {
		return o.cb(con.DstIP)
	} else if o.Operand == OpSrcNetwork {
		return o.cb(con.SrcIP)
	} else if o.Operand == OpNetLists {
		return o.cb(con.DstIP)
	} else if o.Operand == OpDomainsRegexpLists {
		return o.cb(con.DstHost)
	} else if o.Operand == OpIfaceIn {
		if ifname, err := net.InterfaceByIndex(con.Pkt.IfaceInIdx); err == nil {
			return o.cb(ifname.Name)
		}
	} else if o.Operand == OpIfaceOut {
		if ifname, err := net.InterfaceByIndex(con.Pkt.IfaceOutIdx); err == nil {
			return o.cb(ifname.Name)
		}
	} else if o.Operand == OpProcessHashMD5 || o.Operand == OpProcessHashSHA1 {
		ret := true
		if !hasChecksums {
			return ret
		}
		con.Process.RLock()
		for algo := range con.Process.Checksums {
			ret = o.cb(con.Process.Checksums[algo])
			if ret {
				break
			}
		}
		con.Process.RUnlock()
		return ret
	} else if o.Operand == OpProto {
		return o.cb(con.Protocol)
	} else if o.Operand == OpSrcIP {
		return o.cb(con.SrcIP.String())
	} else if o.Operand == OpSrcPort {
		return o.cb(strconv.FormatUint(uint64(con.SrcPort), 10))
	} else if o.Operand == OpProcessID {
		return o.cb(strconv.Itoa(con.Process.ID))
	} else if strings.HasPrefix(string(o.Operand), string(OpProcessEnvPrefix)) {
		envVarName := core.Trim(string(o.Operand[OpProcessEnvPrefixLen:]))
		envVarValue, _ := con.Process.Env[envVarName]
		return o.cb(envVarValue)
	}

	return false
}

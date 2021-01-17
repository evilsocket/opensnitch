package rule

import (
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
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
)

// Available operands
const (
	OpTrue                = Operand("true")
	OpProcessID           = Operand("process.id")
	OpProcessPath         = Operand("process.path")
	OpProcessCmd          = Operand("process.command")
	OpProcessEnvPrefix    = Operand("process.env.")
	OpProcessEnvPrefixLen = 12
	OpUserID              = Operand("user.id")
	OpDstIP               = Operand("dest.ip")
	OpDstHost             = Operand("dest.host")
	OpDstPort             = Operand("dest.port")
	OpDstNetwork          = Operand("dest.network")
	OpProto               = Operand("protocol")
	OpList                = Operand("list")
)

type opCallback func(value interface{}) bool

// Operator represents what we want to filter of a connection, and how.
type Operator struct {
	Type      Type       `json:"type"`
	Operand   Operand    `json:"operand"`
	Sensitive Sensitive  `json:"sensitive"`
	Data      string     `json:"data"`
	List      []Operator `json:"list"`

	cb      opCallback
	re      *regexp.Regexp
	netMask *net.IPNet
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
	if err := op.Compile(); err != nil {
		log.Error("NewOperator() failed to compile: %s", err)
		return nil, err
	}
	return &op, nil
}

// Compile translates the operator type field to its callback counterpart
func (o *Operator) Compile() error {
	if o.Type == Simple {
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
		var err error
		_, o.netMask, err = net.ParseCIDR(o.Data)
		if err != nil {
			return err
		}
		o.cb = o.cmpNetwork
	}

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
	if vt := reflect.ValueOf(v).Kind(); vt != reflect.String {
		log.Warning("Operator.reCmp() bad interface type: %T", v)
		return false
	}
	if o.Sensitive == false {
		v = strings.ToLower(v.(string))
	}
	return o.re.MatchString(v.(string))
}

func (o *Operator) cmpNetwork(destIP interface{}) bool {
	// 192.0.2.1/24, 2001:db8:a0b:12f0::1/32
	if o.netMask == nil {
		log.Warning("cmpNetwork() NULL: %s", destIP)
		return false
	}
	return o.netMask.Contains(destIP.(net.IP))
}

func (o *Operator) listMatch(con interface{}) bool {
	res := true
	for i := 0; i < len(o.List); i += 1 {
		o := o.List[i]
		if err := o.Compile(); err != nil {
			return false
		}
		res = res && o.Match(con.(*conman.Connection))
	}
	return res
}

// Match tries to match parts of a connection with the given operator.
func (o *Operator) Match(con *conman.Connection) bool {

	if o.Operand == OpTrue {
		return true
	} else if o.Operand == OpUserID {
		return o.cb(fmt.Sprintf("%d", con.Entry.UserId))
	} else if o.Operand == OpProcessID {
		return o.cb(fmt.Sprint(con.Process.ID))
	} else if o.Operand == OpProcessPath {
		return o.cb(con.Process.Path)
	} else if o.Operand == OpProcessCmd {
		return o.cb(strings.Join(con.Process.Args, " "))
	} else if strings.HasPrefix(string(o.Operand), string(OpProcessEnvPrefix)) {
		envVarName := core.Trim(string(o.Operand[OpProcessEnvPrefixLen:]))
		envVarValue, _ := con.Process.Env[envVarName]
		return o.cb(envVarValue)
	} else if o.Operand == OpDstIP {
		return o.cb(con.DstIP.String())
	} else if o.Operand == OpDstHost && con.DstHost != "" {
		return o.cb(con.DstHost)
	} else if o.Operand == OpProto {
		return o.cb(con.Protocol)
	} else if o.Operand == OpDstPort {
		return o.cb(fmt.Sprintf("%d", con.DstPort))
	} else if o.Operand == OpDstNetwork {
		return o.cb(con.DstIP)
	} else if o.Operand == OpList {
		return o.listMatch(con)
	}

	return false
}

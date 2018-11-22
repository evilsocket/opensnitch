package rule

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
)

type Type string

const (
	Simple  = Type("simple")
	Regexp  = Type("regexp")
	Complex = Type("complex") // for future use
	List    = Type("list")
)

type Operand string

const (
	OpTrue                = Operand("true")
	OpProcessPath         = Operand("process.path")
	OpProcessCmd          = Operand("process.command")
	OpProcessEnvPrefix    = Operand("process.env.")
	OpProcessEnvPrefixLen = 12
	OpUserId              = Operand("user.id")
	OpDstIP               = Operand("dest.ip")
	OpDstHost             = Operand("dest.host")
	OpDstPort             = Operand("dest.port")
	OpList                = Operand("list")
)

type opCallback func(value string) bool

type Operator struct {
	Type    Type    `json:"type"`
	Operand Operand `json:"operand"`
	Data    string  `json:"data"`
	List    []Operator  `json:"list"`

	cb opCallback
	re *regexp.Regexp
}

func NewOperator(t Type, o Operand, data string, list []Operator) Operator {
	op := Operator{
		Type:    t,
		Operand: o,
		Data:    data,
		List:    list,
	}
	op.Compile()
	return op
}

func (o *Operator) Compile() {
	if o.Type == Simple {
		o.cb = o.simpleCmp
	} else if o.Type == Regexp {
		o.cb = o.reCmp
		o.re = regexp.MustCompile(o.Data)
	} else if o.Type == List {
		o.Operand = OpList
	}
}

func (o *Operator) String() string {
	how := "is"
	if o.Type == Regexp {
		how = "matches"
	}
	return fmt.Sprintf("%s %s '%s'", log.Bold(string(o.Operand)), how, log.Yellow(string(o.Data)))
}

func (o *Operator) simpleCmp(v string) bool {
	return v == o.Data
}

func (o *Operator) reCmp(v string) bool {
	return o.re.MatchString(v)
}

func (o *Operator) listMatch(con *conman.Connection) bool {
	res := true
	for i := 0; i < len(o.List); i += 1 {
		o := o.List[i]
		o.Compile()
		res = res && o.Match(con)
	}
	return res
}

func (o *Operator) Match(con *conman.Connection) bool {
	if o.Operand == OpTrue {
		return true
	} else if o.Operand == OpUserId {
		return o.cb(fmt.Sprintf("%d", con.Entry.UserId))
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
	} else if o.Operand == OpDstHost {
		return o.cb(con.DstHost)
	} else if o.Operand == OpDstPort {
		return o.cb(fmt.Sprintf("%d", con.DstPort))
	} else if o.Operand == OpList {
		return o.listMatch(con)
	}

	return false
}

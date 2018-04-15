package rule

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/log"
)

type Type string

const (
	Simple  = Type("simple")
	Regexp  = Type("regexp")
	Complex = Type("complex") // for future use
)

type Operand string

const (
	OpTrue        = Operand("true")
	OpProcessPath = Operand("process.path")
	OpProcessCmd  = Operand("process.command")
	OpUserId      = Operand("user.id")
	OpDstIP       = Operand("dest.ip")
	OpDstHost     = Operand("dest.host")
	OpDstPort     = Operand("dest.port")
)

type opCallback func(value string) bool

type Operator struct {
	Type    Type    `json:"type"`
	Operand Operand `json:"operand"`
	Data    string  `json:"data"`

	cb opCallback
	re *regexp.Regexp
}

func NewOperator(t Type, o Operand, data string) Operator {
	op := Operator{
		Type:    t,
		Operand: o,
		Data:    data,
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
	}
}

func (o *Operator) String() string {
	how := "is"
	if o.Type == Regexp {
		how = "matches"
	}
	return fmt.Sprintf("%s %s %s", log.Bold(string(o.Operand)), how, log.Yellow(string(o.Data)))
}

func (o *Operator) simpleCmp(v string) bool {
	return v == o.Data
}

func (o *Operator) reCmp(v string) bool {
	return o.re.MatchString(v)
}

func (o *Operator) Match(con *conman.Connection) bool {
	switch o.Operand {
	case OpTrue:
		return true

	case OpUserId:
		return o.cb(fmt.Sprintf("%d", con.Entry.UserId))

	case OpProcessPath:
		return o.cb(con.Process.Path)

	case OpProcessCmd:
		return o.cb(strings.Join(con.Process.Args, " "))

	case OpDstIP:
		return o.cb(con.DstIP.String())

	case OpDstHost:
		return o.cb(con.DstHost)

	case OpDstPort:
		return o.cb(fmt.Sprintf("%d", con.DstPort))
	}

	return false
}

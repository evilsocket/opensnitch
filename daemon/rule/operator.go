package rule

import (
	"encoding/json"
	"fmt"
	"regexp"

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

func (o *Operator) UnmarshalJSON(b []byte) error {
	err := json.Unmarshal(b, o)
	if err != nil {
		return err
	}

	// make sure it's ready to be used
	o.Compile()
	return nil
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
	if o.Operand == OpTrue {
		return true
	} else if o.Operand == OpUserId {
		return o.cb(fmt.Sprintf("%d", con.Entry.UserId))
	} else if o.Operand == OpProcessPath {
		return o.cb(con.Process.Path)
	} else if o.Operand == OpDstIP {
		return o.cb(con.DstIP.String())
	} else if o.Operand == OpDstHost {
		return o.cb(con.DstHost)
	} else if o.Operand == OpDstPort {
		return o.cb(fmt.Sprintf("%d", con.DstPort))
	}
	return false
}

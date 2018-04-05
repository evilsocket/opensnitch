package rule

import (
	"fmt"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	protocol "github.com/evilsocket/opensnitch/ui.proto"
)

type OperandType string

const (
	OpTrue        = OperandType("true")
	OpProcessPath = OperandType("process.path")
	OpDstIP       = OperandType("dest.ip")
	OpDstHost     = OperandType("dest.host")
)

type Cmp struct {
	What OperandType
	With string
}

type Action string

const (
	Allow = Action("allow")
	Deny  = Action("deny")
)

type Duration string

const (
	Once    = Duration("once")
	Restart = Duration("until restart")
	Always  = Duration("always")
)

type Type string

const (
	Simple  = Type("simple")
	Complex = Type("complex") // for future use
)

type Rule struct {
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
	Name     string    `json:"name"`
	Enabled  bool      `json:"enabled"`
	Action   Action    `json:"action"`
	Duration Duration  `json:"duration"`
	Type     Type      `json:"type"`
	Rule     Cmp       `json:"rule"`
}

func FromReply(reply *protocol.RuleReply) *Rule {
	return Create(
		reply.Name,
		Action(reply.Action),
		Duration(reply.Duration),
		Cmp{
			What: OperandType(reply.What),
			With: reply.Value,
		},
	)
}

func Create(name string, action Action, duration Duration, rule Cmp) *Rule {
	return &Rule{
		Created:  time.Now(),
		Enabled:  true,
		Name:     name,
		Action:   action,
		Duration: duration,
		Type:     Simple,
		Rule:     rule,
	}
}

func (r *Rule) String() string {
	return fmt.Sprintf("%s: if(%s == '%s'){ %s %s }", r.Name, r.Rule.What, r.Rule.With, r.Action, r.Duration)
}

func (r *Rule) Match(con *conman.Connection) bool {
	if r.Enabled == false {
		return false
	} else if r.Rule.What == OpTrue {
		return true
	} else if r.Rule.What == OpProcessPath {
		return con.Process.Path == r.Rule.With
	} else if r.Rule.What == OpDstIP {
		return con.DstIP.String() == r.Rule.With
	} else if r.Rule.What == OpDstHost {
		return con.DstHost == r.Rule.With
	}
	return false
}

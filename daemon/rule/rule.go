package rule

import (
	"fmt"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

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

type Rule struct {
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
	Name     string    `json:"name"`
	Enabled  bool      `json:"enabled"`
	Action   Action    `json:"action"`
	Duration Duration  `json:"duration"`
	Operator Operator  `json:"operator"`
}

func Create(name string, action Action, duration Duration, op Operator) *Rule {
	return &Rule{
		Created:  time.Now(),
		Enabled:  true,
		Name:     name,
		Action:   action,
		Duration: duration,
		Operator: op,
	}
}

func (r *Rule) String() string {
	return fmt.Sprintf("%s: if(%s){ %s %s }", r.Name, r.Operator.String(), r.Action, r.Duration)
}

func (r *Rule) Match(con *conman.Connection) bool {
	if r.Enabled == false {
		return false
	}
	return r.Operator.Match(con)
}

func Deserialize(reply *protocol.Rule) *Rule {
	operator := NewOperator(
		Type(reply.Operator.Type),
		Operand(reply.Operator.Operand),
		reply.Operator.Data,
		make([]Operator, 0),
	)

	return Create(
		reply.Name,
		Action(reply.Action),
		Duration(reply.Duration),
		operator,
	)
}

func (r *Rule) Serialize() *protocol.Rule {
	return &protocol.Rule{
		Name:     string(r.Name),
		Action:   string(r.Action),
		Duration: string(r.Duration),
		Operator: &protocol.Operator{
			Type:    string(r.Operator.Type),
			Operand: string(r.Operator.Operand),
			Data:    string(r.Operator.Data),
		},
	}
}

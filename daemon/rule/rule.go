package rule

import (
	"fmt"
	"time"

	"github.com/gustavo-iniguez-goya/opensnitch/daemon/conman"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/ui/protocol"
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

// Rule represents an action on a connection.
// The fields match the ones saved as json to disk.
// If a .json rule file is modified on disk, it's reloaded automatically.
type Rule struct {
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
	Name     string    `json:"name"`
	Enabled  bool      `json:"enabled"`
	Action   Action    `json:"action"`
	Duration Duration  `json:"duration"`
	Operator Operator  `json:"operator"`
}

// Create creates a new rule object with the specified parameters.
func Create(name string, enabled bool, action Action, duration Duration, op *Operator) *Rule {
	return &Rule{
		Created:  time.Now(),
		Enabled:  enabled,
		Name:     name,
		Action:   action,
		Duration: duration,
		Operator: *op,
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

func Deserialize(reply *protocol.Rule) (*Rule, error) {
	if reply.Operator == nil {
		log.Warning("Deserialize rule, Operator nil")
		return nil, fmt.Errorf("invalid operator")
	}
	operator, err := NewOperator(
		Type(reply.Operator.Type),
		Operand(reply.Operator.Operand),
		reply.Operator.Data,
		make([]Operator, 0),
	)
	if err != nil {
		log.Warning("Deserialize rule, NewOperator() error:", err)
		return nil, err
	}

	return Create(
		reply.Name,
		reply.Enabled,
		Action(reply.Action),
		Duration(reply.Duration),
		operator,
	), nil
}

func (r *Rule) Serialize() *protocol.Rule {
	if r == nil {
		return nil
	}
	return &protocol.Rule{
		Name:     string(r.Name),
		Enabled:  bool(r.Enabled),
		Action:   string(r.Action),
		Duration: string(r.Duration),
		Operator: &protocol.Operator{
			Type:    string(r.Operator.Type),
			Operand: string(r.Operator.Operand),
			Data:    string(r.Operator.Data),
		},
	}
}

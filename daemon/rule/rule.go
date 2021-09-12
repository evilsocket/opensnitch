package rule

import (
	"fmt"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

// Action of a rule
type Action string

// Actions of rules
const (
	Allow  = Action("allow")
	Deny   = Action("deny")
	Reject = Action("reject")
)

// Duration of a rule
type Duration string

// daemon possible durations
const (
	Once    = Duration("once")
	Restart = Duration("until restart")
	Always  = Duration("always")
)

// Rule represents an action on a connection.
// The fields match the ones saved as json to disk.
// If a .json rule file is modified on disk, it's reloaded automatically.
type Rule struct {
	Created    time.Time `json:"created"`
	Updated    time.Time `json:"updated"`
	Name       string    `json:"name"`
	Enabled    bool      `json:"enabled"`
	Precedence bool      `json:"precedence"`
	Action     Action    `json:"action"`
	Duration   Duration  `json:"duration"`
	Operator   Operator  `json:"operator"`
}

// Create creates a new rule object with the specified parameters.
func Create(name string, enabled bool, precedence bool, action Action, duration Duration, op *Operator) *Rule {
	return &Rule{
		Created:    time.Now(),
		Enabled:    enabled,
		Precedence: precedence,
		Name:       name,
		Action:     action,
		Duration:   duration,
		Operator:   *op,
	}
}

func (r *Rule) String() string {
	return fmt.Sprintf("%s: if(%s){ %s %s }", r.Name, r.Operator.String(), r.Action, r.Duration)
}

// Match performs on a connection the checks a Rule has, to determine if it
// must be allowed or denied.
func (r *Rule) Match(con *conman.Connection) bool {
	return r.Operator.Match(con)
}

// Deserialize translates back the rule received to a Rule object
func Deserialize(reply *protocol.Rule) (*Rule, error) {
	if reply.Operator == nil {
		log.Warning("Deserialize rule, Operator nil")
		return nil, fmt.Errorf("invalid operator")
	}
	operator, err := NewOperator(
		Type(reply.Operator.Type),
		Sensitive(reply.Operator.Sensitive),
		Operand(reply.Operator.Operand),
		reply.Operator.Data,
		make([]Operator, 0),
	)
	if err != nil {
		log.Warning("Deserialize rule, NewOperator() error: %s", err)
		return nil, err
	}

	return Create(
		reply.Name,
		reply.Enabled,
		reply.Precedence,
		Action(reply.Action),
		Duration(reply.Duration),
		operator,
	), nil
}

// Serialize translates a Rule to the protocol object
func (r *Rule) Serialize() *protocol.Rule {
	if r == nil {
		return nil
	}
	return &protocol.Rule{
		Name:       string(r.Name),
		Enabled:    bool(r.Enabled),
		Precedence: bool(r.Precedence),
		Action:     string(r.Action),
		Duration:   string(r.Duration),
		Operator: &protocol.Operator{
			Type:      string(r.Operator.Type),
			Sensitive: bool(r.Operator.Sensitive),
			Operand:   string(r.Operator.Operand),
			Data:      string(r.Operator.Data),
		},
	}
}

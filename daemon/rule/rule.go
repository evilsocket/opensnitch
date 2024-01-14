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
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Action      Action    `json:"action"`
	Duration    Duration  `json:"duration"`
	Operator    Operator  `json:"operator"`
	Enabled     bool      `json:"enabled"`
	Precedence  bool      `json:"precedence"`
	Nolog       bool      `json:"nolog"`
}

// Create creates a new rule object with the specified parameters.
func Create(name, description string, enabled, precedence, nolog bool, action Action, duration Duration, op *Operator) *Rule {
	return &Rule{
		Created:     time.Now(),
		Enabled:     enabled,
		Precedence:  precedence,
		Nolog:       nolog,
		Name:        name,
		Description: description,
		Action:      action,
		Duration:    duration,
		Operator:    *op,
	}
}

func (r *Rule) String() string {
	enabled := "Disabled"
	if r.Enabled {
		enabled = "Enabled"
	}
	return fmt.Sprintf("[%s] %s: if(%s){ %s %s }", enabled, r.Name, r.Operator.String(), r.Action, r.Duration)
}

// Match performs on a connection the checks a Rule has, to determine if it
// must be allowed or denied.
func (r *Rule) Match(con *conman.Connection, hasChecksums bool) bool {
	return r.Operator.Match(con, hasChecksums)
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

	newRule := Create(
		reply.Name,
		reply.Description,
		reply.Enabled,
		reply.Precedence,
		reply.Nolog,
		Action(reply.Action),
		Duration(reply.Duration),
		operator,
	)

	if Type(reply.Operator.Type) == List {
		newRule.Operator.Data = ""
		reply.Operator.Data = ""
		for i := 0; i < len(reply.Operator.List); i++ {
			newRule.Operator.List = append(
				newRule.Operator.List,
				Operator{
					Type:      Type(reply.Operator.List[i].Type),
					Sensitive: Sensitive(reply.Operator.List[i].Sensitive),
					Operand:   Operand(reply.Operator.List[i].Operand),
					Data:      string(reply.Operator.List[i].Data),
				},
			)
		}
	}

	return newRule, nil
}

// Serialize translates a Rule to the protocol object
func (r *Rule) Serialize() *protocol.Rule {
	if r == nil {
		return nil
	}
	r.Operator.Lock()
	defer r.Operator.Unlock()

	protoRule := &protocol.Rule{
		Created:     r.Created.Unix(),
		Name:        string(r.Name),
		Description: string(r.Description),
		Enabled:     bool(r.Enabled),
		Precedence:  bool(r.Precedence),
		Nolog:       bool(r.Nolog),
		Action:      string(r.Action),
		Duration:    string(r.Duration),
		Operator: &protocol.Operator{
			Type:      string(r.Operator.Type),
			Sensitive: bool(r.Operator.Sensitive),
			Operand:   string(r.Operator.Operand),
			Data:      string(r.Operator.Data),
		},
	}
	if r.Operator.Type == List {
		r.Operator.Data = ""
		for i := 0; i < len(r.Operator.List); i++ {
			protoRule.Operator.List = append(protoRule.Operator.List,
				&protocol.Operator{
					Type:      string(r.Operator.List[i].Type),
					Sensitive: bool(r.Operator.List[i].Sensitive),
					Operand:   string(r.Operator.List[i].Operand),
					Data:      string(r.Operator.List[i].Data),
				})
		}
	}

	return protoRule
}

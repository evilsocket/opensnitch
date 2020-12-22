package statistics

import (
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

type Event struct {
	Time       time.Time
	Connection *conman.Connection
	Rule       *rule.Rule
}

func NewEvent(con *conman.Connection, match *rule.Rule) *Event {
	return &Event{
		Time:       time.Now(),
		Connection: con,
		Rule:       match,
	}
}

func (e *Event) Serialize() *protocol.Event {
	return &protocol.Event{
		Time:       e.Time.Format("2006-01-02 15:04:05"),
		Connection: e.Connection.Serialize(),
		Rule:       e.Rule.Serialize(),
		Unixnano:   e.Time.UnixNano(),
	}
}

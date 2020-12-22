package statistics

import (
	"fmt"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

const (
	// max number of events to keep in the buffer
	maxEvents = 100
	// max number of entries for each By* map
	maxStats = 25
)

type conEvent struct {
	con       *conman.Connection
	match     *rule.Rule
	wasMissed bool
}

type Statistics struct {
	sync.RWMutex

	Started      time.Time
	DNSResponses int
	Connections  int
	Ignored      int
	Accepted     int
	Dropped      int
	RuleHits     int
	RuleMisses   int
	Events       []*Event
	ByProto      map[string]uint64
	ByAddress    map[string]uint64
	ByHost       map[string]uint64
	ByPort       map[string]uint64
	ByUID        map[string]uint64
	ByExecutable map[string]uint64

	rules *rule.Loader
	jobs  chan conEvent
}

func New(rules *rule.Loader) (stats *Statistics) {
	stats = &Statistics{
		Started:      time.Now(),
		Events:       make([]*Event, 0),
		ByProto:      make(map[string]uint64),
		ByAddress:    make(map[string]uint64),
		ByHost:       make(map[string]uint64),
		ByPort:       make(map[string]uint64),
		ByUID:        make(map[string]uint64),
		ByExecutable: make(map[string]uint64),

		rules: rules,
		jobs:  make(chan conEvent),
	}

	go stats.eventWorker(0)
	go stats.eventWorker(1)
	go stats.eventWorker(2)
	go stats.eventWorker(3)

	return stats
}

func (s *Statistics) OnDNSResponse() {
	s.Lock()
	defer s.Unlock()
	s.DNSResponses++
	s.Accepted++
}

func (s *Statistics) OnIgnored() {
	s.Lock()
	defer s.Unlock()
	s.Ignored++
	s.Accepted++
}

func (s *Statistics) incMap(m *map[string]uint64, key string) {
	if val, found := (*m)[key]; found == false {
		// do we have enough space left?
		nElems := len(*m)
		if nElems >= maxStats {
			// find the element with less hits
			nMin := uint64(9999999999)
			minKey := ""
			for k, v := range *m {
				if v < nMin {
					minKey = k
					nMin = v
				}
			}
			// remove it
			if minKey != "" {
				delete(*m, minKey)
			}
		}

		(*m)[key] = 1
	} else {
		(*m)[key] = val + 1
	}
}

func (s *Statistics) eventWorker(id int) {
	log.Debug("Stats worker #%d started.", id)

	for true {
		select {
		case job := <-s.jobs:
			s.onConnection(job.con, job.match, job.wasMissed)
		}
	}
}

func (s *Statistics) onConnection(con *conman.Connection, match *rule.Rule, wasMissed bool) {
	s.Lock()
	defer s.Unlock()

	s.Connections++

	if wasMissed {
		s.RuleMisses++
	} else {
		s.RuleHits++
	}

	if wasMissed == false && match.Action == rule.Allow {
		s.Accepted++
	} else {
		s.Dropped++
	}

	s.incMap(&s.ByProto, con.Protocol)
	s.incMap(&s.ByAddress, con.DstIP.String())
	if con.DstHost != "" {
		s.incMap(&s.ByHost, con.DstHost)
	}
	s.incMap(&s.ByPort, fmt.Sprintf("%d", con.DstPort))
	s.incMap(&s.ByUID, fmt.Sprintf("%d", con.Entry.UserId))
	s.incMap(&s.ByExecutable, con.Process.Path)

	// if we reached the limit, shift everything back
	// by one position
	nEvents := len(s.Events)
	if nEvents == maxEvents {
		s.Events = s.Events[1:]
	}
	if wasMissed {
		return
	}
	s.Events = append(s.Events, NewEvent(con, match))
}

func (s *Statistics) OnConnectionEvent(con *conman.Connection, match *rule.Rule, wasMissed bool) {
	s.jobs <- conEvent{
		con:       con,
		match:     match,
		wasMissed: wasMissed,
	}
}

func (s *Statistics) serializeEvents() []*protocol.Event {
	nEvents := len(s.Events)
	serialized := make([]*protocol.Event, nEvents)

	for i, e := range s.Events {
		serialized[i] = e.Serialize()
	}

	return serialized
}

func (s *Statistics) Serialize() *protocol.Statistics {
	s.Lock()
	defer s.Unlock()

	return &protocol.Statistics{
		DaemonVersion: core.Version,
		Rules:         uint64(s.rules.NumRules()),
		Uptime:        uint64(time.Since(s.Started).Seconds()),
		DnsResponses:  uint64(s.DNSResponses),
		Connections:   uint64(s.Connections),
		Ignored:       uint64(s.Ignored),
		Accepted:      uint64(s.Accepted),
		Dropped:       uint64(s.Dropped),
		RuleHits:      uint64(s.RuleHits),
		RuleMisses:    uint64(s.RuleMisses),
		Events:        s.serializeEvents(),
		ByProto:       s.ByProto,
		ByAddress:     s.ByAddress,
		ByHost:        s.ByHost,
		ByPort:        s.ByPort,
		ByUid:         s.ByUID,
		ByExecutable:  s.ByExecutable,
	}
}

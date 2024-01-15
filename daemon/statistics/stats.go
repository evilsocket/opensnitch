package statistics

import (
	"strconv"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/log/loggers"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

// StatsConfig holds the stats confguration
type StatsConfig struct {
	MaxEvents int `json:"MaxEvents"`
	MaxStats  int `json:"MaxStats"`
	Workers   int `json:"Workers"`
}

type conEvent struct {
	con       *conman.Connection
	match     *rule.Rule
	wasMissed bool
}

// Statistics holds the connections and statistics the daemon intercepts.
// The connections are stored in the Events slice.
type Statistics struct {
	Started      time.Time
	logger       *loggers.LoggerManager
	rules        *rule.Loader
	ByExecutable map[string]uint64
	ByUID        map[string]uint64
	ByAddress    map[string]uint64
	ByPort       map[string]uint64
	ByHost       map[string]uint64
	ByProto      map[string]uint64
	jobs         chan conEvent
	Events       []*Event

	RuleHits     int
	Accepted     int
	Ignored      int
	Connections  int
	RuleMisses   int
	DNSResponses int
	// max number of events to keep in the buffer
	maxEvents int
	// max number of entries for each By* map
	maxStats   int
	maxWorkers int
	Dropped    int

	sync.RWMutex
}

// New returns a new Statistics object and initializes the go routines to update the stats.
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

		rules:     rules,
		jobs:      make(chan conEvent),
		maxEvents: 150,
		maxStats:  25,
	}

	return stats
}

// SetLoggers sets the configured loggers where we'll write the events.
func (s *Statistics) SetLoggers(loggers *loggers.LoggerManager) {
	s.logger = loggers
}

// SetLimits configures the max events to keep in the backlog before sending
// the stats to the UI, or while the UI is not connected.
// if the backlog is full, it'll be shifted by one.
func (s *Statistics) SetLimits(config StatsConfig) {
	if config.MaxEvents > 0 {
		s.maxEvents = config.MaxEvents
	}
	if config.MaxStats > 0 {
		s.maxStats = config.MaxStats
	}
	s.maxWorkers = config.Workers
	if s.maxWorkers == 0 {
		s.maxWorkers = 6
	}
	log.Info("Stats, max events: %d, max stats: %d, max workers: %d", s.maxStats, s.maxEvents, s.maxWorkers)
	for i := 0; i < s.maxWorkers; i++ {
		go s.eventWorker(i)
	}

}

// OnConnectionEvent sends the details of a new connection throughout a channel,
// in order to add the connection to the stats.
func (s *Statistics) OnConnectionEvent(con *conman.Connection, match *rule.Rule, wasMissed bool) {
	s.jobs <- conEvent{
		con:       con,
		match:     match,
		wasMissed: wasMissed,
	}
	action := "<nil>"
	rname := "<nil>"
	if match != nil {
		action = string(match.Action)
		rname = string(match.Name)
	}

	s.logger.Log(con.Serialize(), action, rname)
}

// OnDNSResponse increases the counter of dns and accepted connections.
func (s *Statistics) OnDNSResponse() {
	s.Lock()
	defer s.Unlock()
	s.DNSResponses++
	s.Accepted++
}

// OnIgnored increases the counter of ignored and accepted connections.
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
		if nElems >= s.maxStats {
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
	s.incMap(&s.ByPort, strconv.FormatUint(uint64(con.DstPort), 10))
	s.incMap(&s.ByUID, strconv.Itoa(con.Entry.UserId))
	s.incMap(&s.ByExecutable, con.Process.Path)

	// if we reached the limit, shift everything back
	// by one position
	nEvents := len(s.Events)
	if nEvents == s.maxEvents {
		s.Events = s.Events[1:]
	}
	if wasMissed {
		return
	}
	s.Events = append(s.Events, NewEvent(con, match))
}

func (s *Statistics) serializeEvents() []*protocol.Event {
	nEvents := len(s.Events)
	serialized := make([]*protocol.Event, nEvents)

	for i, e := range s.Events {
		serialized[i] = e.Serialize()
	}

	return serialized
}

// emptyStats empties the stats once we've sent them to the GUI.
// We don't need them anymore here.
func (s *Statistics) emptyStats() {
	s.Lock()
	if len(s.Events) > 0 {
		s.Events = make([]*Event, 0)
	}
	s.Unlock()
}

// Serialize returns the collected statistics.
// After return the stats, the Events are emptied, to keep collecting more stats
// and not miss connections.
func (s *Statistics) Serialize() *protocol.Statistics {
	s.Lock()
	defer s.emptyStats()
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

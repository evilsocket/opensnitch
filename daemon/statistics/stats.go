package statistics

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/log"
)

type Statistics struct {
	sync.Mutex

	Started      time.Time
	DNSResponses int
	Connections  int
	Ignored      int
	Accepted     int
	Dropped      int
	RuleHits     int
	RuleMisses   int
	ByProto      map[string]uint64
	ByAddress    map[string]uint64
	ByHost       map[string]uint64
	ByPort       map[string]uint64
	ByUID        map[string]uint64
	ByExecutable map[string]uint64
}

func New() *Statistics {
	return &Statistics{
		Started:      time.Now(),
		ByProto:      make(map[string]uint64),
		ByAddress:    make(map[string]uint64),
		ByHost:       make(map[string]uint64),
		ByPort:       make(map[string]uint64),
		ByUID:        make(map[string]uint64),
		ByExecutable: make(map[string]uint64),
	}
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
		(*m)[key] = 1
	} else {
		(*m)[key] = val + 1
	}
}

func (s *Statistics) OnConnection(con *conman.Connection) {
	s.Lock()
	defer s.Unlock()

	s.Connections++

	s.incMap(&s.ByProto, con.Protocol)
	s.incMap(&s.ByAddress, con.DstIP.String())
	if con.DstHost != "" {
		s.incMap(&s.ByHost, con.DstHost)
	}
	s.incMap(&s.ByPort, fmt.Sprintf("%d", con.DstPort))
	s.incMap(&s.ByUID, fmt.Sprintf("%d", con.Entry.UserId))
	s.incMap(&s.ByExecutable, con.Process.Path)
}

func (s *Statistics) OnRuleHit() {
	s.Lock()
	defer s.Unlock()
	s.RuleHits++
}

func (s *Statistics) OnRuleMiss() {
	s.Lock()
	defer s.Unlock()
	s.RuleMisses++
}

func (s *Statistics) OnAccept() {
	s.Lock()
	defer s.Unlock()
	s.Accepted++
}

func (s *Statistics) OnDrop() {
	s.Lock()
	defer s.Unlock()
	s.Dropped++
}

func (s *Statistics) logMap(m *map[string]uint64, name string) {
	log.Raw("%s\n", name)
	log.Raw("----\n")

	type kv struct {
		Key   string
		Value uint64
	}

	var padLen int
	var asList []kv

	for k, v := range *m {
		asList = append(asList, kv{k, v})
		kLen := len(k)
		if kLen > padLen {
			padLen = kLen
		}
	}

	sort.Slice(asList, func(i, j int) bool {
		return asList[i].Value > asList[j].Value
	})

	for _, e := range asList {
		log.Raw("%"+fmt.Sprintf("%d", padLen)+"s : %d\n", e.Key, e.Value)
	}

	log.Raw("\n")
}

func (s *Statistics) Log() {
	s.Lock()
	defer s.Unlock()

	log.Raw("Statistics\n")
	log.Raw("-------------------------------------\n")
	log.Raw("Uptime        : %s\n", time.Since(s.Started))
	log.Raw("DNS responses : %d\n", s.DNSResponses)
	log.Raw("Connections   : %d\n", s.Connections)
	log.Raw("Accepted      : %d\n", s.Accepted)
	log.Raw("Ignored       : %d\n", s.Ignored)
	log.Raw("Dropped       : %d\n", s.Dropped)
	log.Raw("Rule hits     : %d\n", s.RuleHits)
	log.Raw("Rule misses   : %d\n", s.RuleMisses)
	log.Raw("\n")

	s.logMap(&s.ByProto, "By protocol")
	s.logMap(&s.ByAddress, "By IP")
	s.logMap(&s.ByHost, "By hostname")
	s.logMap(&s.ByPort, "By port")
	s.logMap(&s.ByUID, "By uid")
	s.logMap(&s.ByExecutable, "By executable")
}

package portscan

import (
	"encoding/binary"
	"net/netip"
	"sync"
)

// portFilterGeneration is the size of the exact ring of recently accepted
// ports that deduplicates destination ports.
//
// Deduplication is mandatory: the six SYN retransmissions Linux sends for one
// unanswered connection must count as one port, not six. The ring is exact, so
// a new port is never mistaken for a repeat, and fixed-size, so nothing a
// source sends makes its entry grow. A source cycling over more ports than the
// ring holds is re-scored as it comes round again; what keeps such a peer from
// being reported over and over is the evidence gate in shouldReport, and its
// full bucket is why hasTCPEvidence has a clock of its own (Engine.ageFacts).
const portFilterGeneration = 64

// sampledPorts is how many destination ports are retained verbatim for
// reporting. Enough to make an alert legible without unbounded growth.
const sampledPorts = 16

// sourceState is everything tracked for one source address.
//
// It is a fixed-size value with no slice or map in it, so the whole table's
// memory is bounded by MaxSources * sizeof(sourceState), and nothing an
// attacker sends can make an individual entry grow.
type sourceState struct {
	firstSeenNs uint64
	lastSeenNs  uint64
	lastDecayNs uint64

	// reportedAtNs is when this source was last reported, for the cooldown.
	reportedAtNs uint64
	// reportedEvidence is how much this source had shown when it was last
	// reported; it is reported again only once it has shown more of some kind
	// of fact (see evidence.isNews). The cooldown is a timer, not a reason to
	// report again.
	reportedEvidence evidence

	// suppressedUntilNs is when the alert-limiter window that last refused this
	// source ends, or 0 if it never was. Until then the source does not ask the
	// limiter again: asking could only be refused, and asking on every packet
	// would make the "N further alerts were suppressed" figure a packet count
	// the sender chooses, and put the global limiter lock on the packet path.
	// A deadline rather than a window start, because a window start of zero is
	// a real value.
	suppressedUntilNs uint64
	// queuedEvidence is how many facts this source had shown when its entry in
	// the pending queue was last written (see Engine.Process).
	queuedEvidence uint32

	score uint32

	// distinctPorts counts ports accepted as new.
	distinctPorts uint32
	tcpProbes     uint32
	udpProbes     uint32

	// portsThisGen counts ports accepted since the ring last turned over, and
	// generations how many times it has.
	portsThisGen uint32
	generations  uint32

	// recentPorts is the ring of the last accepted ports, keyed on
	// (protocol, port): TCP/53 and UDP/53 are two distinct things to score.
	recentPorts  [portFilterGeneration]uint32
	nRecentPorts uint8
	recentNext   uint8
	// protoSeen is an exact 256-bit set of the IP protocol numbers seen.
	protoSeen  [4]uint64
	protoCount uint16

	// icmpTypesSeen is an exact set of the ICMP query types seen, and
	// icmpTypeCount how many. nmap -PE -PP -PM sends three types; ordinary
	// traffic sends echo and nothing else, however much of it there is.
	icmpTypesSeen [4]uint64
	icmpTypeCount uint16
	icmpSweep     bool

	// icmpProbes counts scored ICMP probes, so describeMethod can tally ICMP
	// as a family of its own; evasionProbes likewise counts probes that
	// exhausted the IPv6 extension-header walk.
	icmpProbes    uint32
	evasionProbes uint32

	// flagsOr is the OR of every TCP flag byte seen, flagsAnd their AND.
	// Together they recover the exact combination when it was constant and
	// show that it varied otherwise (scanlogd.c:52-53).
	flagsOr  uint8
	flagsAnd uint8
	// flagsSeen records whether any TCP flags were seen at all: a NULL scan
	// leaves both masks looking like "no data".
	flagsSeen bool
	// tcpProbesNoFlags counts TCP probes whose flag octet could not be read,
	// which is what nmap -f produces. Keeping them apart is what stops those
	// packets being reported as a NULL scan.
	tcpProbesNoFlags uint32

	minPort uint16
	maxPort uint16

	samplePorts [sampledPorts]uint16
	nSample     uint8

	// dstSeen is a small exact set of the local addresses targeted, to report
	// whether a multi-homed host was probed on several of them.
	dstSeen  [4]netip.Addr
	nDstSeen uint8

	srcMAC    [6]byte
	hasMAC    bool
	protoScan bool
	reported  bool
	anomalies Anomaly

	// hasTCPEvidence records that a probe only a scanner sends has scored: a SYN,
	// flags that cannot acknowledge anything, or TCP flags that could not be read
	// (nmap -f). It is what BlockConfig.RequireTCPEvidence gates on. The name
	// follows that setting; a forged FIN|ACK is TCP and is not evidence (see
	// probeClass.isEvidence).
	hasTCPEvidence bool
	// reportedEligible records whether the last report of this source could be
	// proposed for blocking. One that could not is followed, as soon as the
	// source becomes blockable, by one that can (see Engine.shouldReport).
	reportedEligible bool

	// lastEvidenceNs is when a probe last supplied hasTCPEvidence, and
	// lastNewFactNs when a protocol or an ICMP query type was last seen for the
	// first time. Both give a fact its own clock, separate from the bucket; see
	// Engine.ageFacts.
	lastEvidenceNs uint64
	lastNewFactNs  uint64
}

// addPort records a destination port and reports whether it was new.
func (s *sourceState) addPort(proto uint8, port uint16) bool {
	// ICMP is keyed on its type alone (see below): with the code in the key,
	// one type sent with three codes scored three times.
	if proto == ProtoICMP || proto == ProtoICMPv6 {
		port &^= 0xff
	}
	key := uint32(proto)<<16 | uint32(port)
	for i := uint8(0); i < s.nRecentPorts; i++ {
		if s.recentPorts[i] == key {
			return false
		}
	}
	s.recentPorts[s.recentNext] = key
	s.recentNext = (s.recentNext + 1) % portFilterGeneration
	if s.nRecentPorts < portFilterGeneration {
		s.nRecentPorts++
	}
	s.portsThisGen++
	if s.portsThisGen >= portFilterGeneration {
		s.portsThisGen = 0
		s.generations++
	}

	// ICMP has no ports: its type and code travel in this field as
	// type<<8|code, so a source is scored once per distinct type. Deduplicated
	// like a port, but not reported as one -- an ICMP sweep is not "3 ports
	// probed between 3328 and 4352".
	if proto != ProtoICMP && proto != ProtoICMPv6 {
		s.distinctPorts++
		if s.nSample < sampledPorts {
			s.samplePorts[s.nSample] = port
			s.nSample++
		}
		if s.distinctPorts == 1 {
			s.minPort, s.maxPort = port, port
		} else {
			if port < s.minPort {
				s.minPort = port
			}
			if port > s.maxPort {
				s.maxPort = port
			}
		}
	}
	return true
}

// addProtocol records an IP protocol number and reports whether it was new.
func (s *sourceState) addProtocol(proto uint8) bool {
	w, m := proto/64, uint64(1)<<(proto%64)
	if s.protoSeen[w]&m != 0 {
		return false
	}
	s.protoSeen[w] |= m
	s.protoCount++
	s.lastNewFactNs = s.lastSeenNs
	return true
}

// addICMPType records an ICMP message type, reporting whether it is new.
func (s *sourceState) addICMPType(t uint8) bool {
	w, m := t/64, uint64(1)<<(t%64)
	if s.icmpTypesSeen[w]&m != 0 {
		return false
	}
	s.icmpTypesSeen[w] |= m
	s.icmpTypeCount++
	s.lastNewFactNs = s.lastSeenNs
	return true
}

// addDst records a targeted local address, keeping at most len(dstSeen).
func (s *sourceState) addDst(a netip.Addr) {
	for i := uint8(0); i < s.nDstSeen; i++ {
		if s.dstSeen[i] == a {
			return
		}
	}
	if int(s.nDstSeen) < len(s.dstSeen) {
		s.dstSeen[s.nDstSeen] = a
		s.nDstSeen++
	}
}

// observeFlags folds a TCP flag byte into the OR/AND masks.
func (s *sourceState) observeFlags(flags uint8) {
	if !s.flagsSeen {
		s.flagsOr, s.flagsAnd, s.flagsSeen = flags, flags, true
		return
	}
	s.flagsOr |= flags
	s.flagsAnd &= flags
}

// decay applies the leaky bucket up to nowNs.
//
// The subtraction is saturating and the elapsed time is guarded against going
// backwards, the same defence scanlogd applies to clock_t wrap-around
// (`now - current->timestamp <= threshold && now >= current->timestamp`,
// scanlogd.c:237-238). Portmaster left an unresolved "TODO: Integer over-
// &Underflow on score" in its equivalent code for the whole life of the patch.
func (s *sourceState) decay(nowNs uint64, decayIntervalNs uint64) {
	if decayIntervalNs == 0 || nowNs <= s.lastDecayNs {
		return
	}
	elapsed := nowNs - s.lastDecayNs
	steps := elapsed / decayIntervalNs
	if steps == 0 {
		return
	}
	if steps >= uint64(s.score) {
		s.score = 0
		s.releaseEvidence()
	} else {
		s.score -= uint32(steps)
	}
	// Advance only by the whole steps consumed, so the remainder is not lost
	// and a stream of sub-interval updates still decays at the right rate.
	s.lastDecayNs += steps * decayIntervalNs
}

// releaseEvidence clears what permits a block once the bucket beside it has
// emptied: a source quiet for that long is no longer held to anything, and one
// forged anomalous packet must not leave it blockable for good.
// Engine.ageFacts also expires the evidence on its own clock, for a source
// whose bucket never empties.
//
// The protocol and ICMP-type facts are not cleared here. Those probes add
// nothing to the bucket, so for a source sending nothing else it is always
// empty, and clearing them here would require every protocol of an nmap -sO
// scan within one DecayInterval. They expire in Engine.ageFacts.
func (s *sourceState) releaseEvidence() {
	s.hasTCPEvidence = false
	s.icmpProbes = 0
}

// releaseFacts forgets the protocol and ICMP-type facts.
//
// The evidence baseline is left where it is, so the same facts coming back
// are not news: a source whose facts expired is reported again only when it
// shows more of some kind than it already had. New ports after a protocol
// scan are news, since each kind has its own baseline. Forgetting the whole
// source (IdleExpiry without any packet) starts it from nothing.
func (s *sourceState) releaseFacts() {
	s.protoScan = false
	s.icmpSweep = false
	s.protoSeen = [4]uint64{}
	s.protoCount = 0
	s.icmpTypesSeen = [4]uint64{}
	s.icmpTypeCount = 0
	s.lastNewFactNs = 0
}

// decayedScore is the score this source would have at nowNs, without writing it.
//
// It exists for eviction, which has to compare sources it is not otherwise
// touching. Whatever it computes must be what decay would produce, or the two
// would drift apart and the ranking would stop meaning what it says.
func (s *sourceState) decayedScore(nowNs, decayIntervalNs uint64) uint32 {
	if decayIntervalNs == 0 || nowNs <= s.lastDecayNs {
		return s.score
	}
	steps := (nowNs - s.lastDecayNs) / decayIntervalNs
	if steps >= uint64(s.score) {
		return 0
	}
	return s.score - uint32(steps)
}

// addScore adds to the score with saturation at a hard ceiling.
//
// The ceiling exists so that a long scan cannot bank an arbitrarily large
// score that would keep the source "hot" for hours after it stopped
// (Portmaster caps at maxScore = 2 * scoreBlock for the same reason).
func (s *sourceState) addScore(delta, ceiling uint32) {
	if ceiling == 0 {
		return
	}
	if s.score >= ceiling-min32(delta, ceiling) {
		s.score = ceiling
		return
	}
	s.score += delta
}

func min32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// sourceTable is a fixed-capacity LRU over source addresses.
//
// Go maps use a per-process random hash seed, so an attacker cannot force
// collisions the way they could against scanlogd's fixed hash -- which is why
// scanlogd has to truncate over-long chains explicitly (HASH_MAX,
// scanlogd.c:303-306). The bound here serves the other half of that defence:
// capping total memory.
type sourceTable struct {
	mu       sync.Mutex
	capacity int
	// decayIntervalNs is the leaky bucket rate, needed by evictionRank so that
	// eviction compares scores as of now rather than as of whenever each source
	// last sent a packet.
	decayIntervalNs uint64
	// scoreThreshold is the reporting threshold, used by evictionRank to put a
	// protocol scan -- which carries no score at all -- on the same scale as
	// everything else it is ranked against.
	scoreThreshold uint32

	// memo is a ring of reports that outlive their entry, memoAt its index by
	// address and memoNext the slot to overwrite next. See reportMemoPerShard.
	memo     []reportMemo
	memoAt   map[netip.Addr]int
	memoNext int

	// Entries are carved from slabs and recycled through a free list, so
	// admitting a source never allocates: the forged-source flood is the path
	// whose rate an attacker chooses, and it must not choose how often the
	// garbage collector runs. The slabs grow on demand rather than being
	// allocated up front, because tableEntry holds pointers and the collector
	// walks the whole array on every cycle: an idle desktop pays only for the
	// sources it has seen. allocated counts the entries carved so far.
	slabs     [][]tableEntry
	allocated int
	// entries maps an address to its entry inside slabs.
	entries map[netip.Addr]*tableEntry
	// head and tail are the most and least recently used entries, free the head
	// of the free list (chained through next).
	head, tail, free *tableEntry
	// nlive is how many entries are in the LRU list.
	nlive   int
	evicted uint64
	// counted is bumped under this shard's lock, which the caller already
	// holds, so it costs nothing. An atomic here would be a second locked
	// read-modify-write on the packet path for no gain.
	counted uint64
}

// shardedTable is the source table split across independently locked shards,
// so that a flood on one core does not make every other packet wait behind
// it. An address's shard is chosen by a hash seeded per process: with a fixed
// hash an attacker could aim all his forged sources at one shard and evict a
// real scanner from it for a fraction of MaxSources.
type shardedTable struct {
	shards []*sourceTable
	mask   uint64
	seed   uint64
}

// tableShardCount picks a shard count that is a power of two, no larger than
// maxTableShards, and never so large that a shard holds fewer than
// minEntriesPerShard entries -- a shard too small would evict useful state long
// before the configured capacity was reached.
const (
	maxTableShards     = 16
	minEntriesPerShard = 128
)

func newShardedTable(capacity int, decayIntervalNs uint64, scoreThreshold uint32, seed uint64) *shardedTable {
	n := 1
	for n*2 <= maxTableShards && capacity/(n*2) >= minEntriesPerShard {
		n *= 2
	}
	t := &shardedTable{
		shards: make([]*sourceTable, n),
		mask:   uint64(n - 1),
		seed:   seed,
	}
	// Rounded up, so the sum of the shard capacities is never below the
	// configured MaxSources.
	per := (capacity + n - 1) / n
	for i := range t.shards {
		t.shards[i] = newSourceTable(per, decayIntervalNs, scoreThreshold)
	}
	return t
}

// shardFor selects the shard owning an address. The finaliser is splitmix64's:
// the octets that vary in a v4-mapped address sit in the top bits, and a
// weaker mix would put a whole /16 in one shard (TestShardDistributionIsEven).
func (t *shardedTable) shardFor(a netip.Addr) *sourceTable {
	h := t.seed
	// As16 materialises the v4-mapped form, which is wasted work for an IPv4
	// address on a path that runs once per packet. As4 is four bytes and no
	// conversion.
	if a.Is4() {
		v := a.As4()
		h ^= uint64(binary.LittleEndian.Uint32(v[:]))
		h *= 0xff51afd7ed558ccd
	} else {
		b := a.As16()
		h ^= binary.LittleEndian.Uint64(b[0:8])
		h *= 0xff51afd7ed558ccd
		h ^= binary.LittleEndian.Uint64(b[8:16])
	}

	// splitmix64 finalisation: three avalanche rounds, enough that every input
	// bit reaches every output bit.
	h ^= h >> 30
	h *= 0xbf58476d1ce4e5b9
	h ^= h >> 27
	h *= 0x94d049bb133111eb
	h ^= h >> 31

	return t.shards[h&t.mask]
}

func (t *shardedTable) len() int {
	n := 0
	for _, s := range t.shards {
		s.mu.Lock()
		n += s.nlive
		s.mu.Unlock()
	}
	return n
}

func (t *shardedTable) evictedCount() uint64 {
	var n uint64
	for _, s := range t.shards {
		s.mu.Lock()
		n += s.evicted
		s.mu.Unlock()
	}
	return n
}

func (t *shardedTable) expire(nowNs, idleNs uint64) int {
	n := 0
	for _, s := range t.shards {
		s.mu.Lock()
		n += s.expire(nowNs, idleNs)
		s.mu.Unlock()
	}
	return n
}

func (t *shardedTable) remove(a netip.Addr) {
	s := t.shardFor(a)
	s.mu.Lock()
	s.remove(a)
	s.mu.Unlock()
}

type tableEntry struct {
	addr  netip.Addr
	state sourceState
	// prev and next are the intrusive LRU links. They point into
	// sourceTable.slabs and nowhere else; next doubles as the free-list link
	// while the entry is not in use.
	prev, next *tableEntry
}

func newSourceTable(capacity int, decayIntervalNs uint64, scoreThreshold uint32) *sourceTable {
	if capacity < 1 {
		capacity = 1
	}
	n := reportMemoPerShard
	if capacity < n {
		n = capacity
	}
	return &sourceTable{
		capacity:        capacity,
		decayIntervalNs: decayIntervalNs,
		scoreThreshold:  scoreThreshold,
		// Sized like the slab, not like the capacity: a map of *tableEntry reserved
		// for every slot is exactly what the chunked slab avoids, and would be the
		// whole of an idle engine's footprint (84 MB at the maximum MaxSources).
		entries: make(map[netip.Addr]*tableEntry, mapHint(capacity)),
		memo:    make([]reportMemo, n),
		memoAt:  make(map[netip.Addr]int, n),
	}
}

// reportMemoPerShard is how many reported addresses a shard remembers after
// their entry has been evicted.
//
// Eviction favours unreported sources, but a decoy scan fills the table with
// reported ones, and one forged probe then evicts a reported source along with
// its cooldown: it re-alerted 200 ms later against a cooldown of an hour. The
// memory holds reports, not sources, and reports are capped by AlertsPerMinute,
// so 16*64 addresses take hours to churn at the default rate; the seeded shard
// hash keeps an attacker from aiming at one shard's slots.
const reportMemoPerShard = 64

// reportMemo is what survives an eviction: that this address was reported, when,
// and how long it was suppressed for. Never the score -- losing the score is
// what eviction MEANS, and a source that comes back has to earn it again.
type reportMemo struct {
	addr              netip.Addr
	reportedAtNs      uint64
	suppressedUntilNs uint64
	// reported separates the two reasons an address is here. A source REPORTED
	// owes a cooldown; a source merely REFUSED by the alert limiter owes only
	// the rest of the current window, which is at most one alert window long.
	reported bool
	// reportedEligible is sourceState.reportedEligible: without it a source
	// evicted after a blockable report would come back owing nothing, and
	// shouldReport would let it past the cooldown as newly blockable.
	reportedEligible bool
}

// remember records a report, or a refusal, so that evicting the entry does not
// erase it. A refusal keeps the source from asking the global limiter again on
// its next packet; it is worth less than a report and never displaces one, or a
// flood of refused crossings would push reported addresses and their cooldowns
// out of the ring.
func (t *sourceTable) remember(addr netip.Addr, reportedAtNs, suppressedUntilNs uint64, reported, reportedEligible bool) {
	if len(t.memo) == 0 {
		return
	}
	if i, ok := t.memoAt[addr]; ok {
		t.memo[i].reportedAtNs = reportedAtNs
		t.memo[i].suppressedUntilNs = suppressedUntilNs
		t.memo[i].reported = t.memo[i].reported || reported
		// Copied, not merged: it describes the last report, and one that could
		// not be blocked after one that could must let the next blockable
		// report through.
		t.memo[i].reportedEligible = reportedEligible
		return
	}
	// Walk forward to the first slot this write may take, at most one lap. The
	// cursor always advances: stopping on a reported slot would freeze the ring,
	// and from then on no refusal could be recorded at all.
	for k := 0; k < len(t.memo); k++ {
		i := (t.memoNext + k) % len(t.memo)
		if t.memo[i].reported && !reported {
			continue
		}
		t.memoNext = (i + 1) % len(t.memo)
		if old := t.memo[i].addr; old.IsValid() {
			delete(t.memoAt, old)
		}
		t.memo[i] = reportMemo{
			addr: addr, reportedAtNs: reportedAtNs,
			suppressedUntilNs: suppressedUntilNs, reported: reported,
			reportedEligible: reportedEligible,
		}
		t.memoAt[addr] = i
		return
	}
	// Every slot holds a report and this is only a suppression: drop it. Reports
	// are worth more, and a full lap of them is the case the refusal exists for.
}

// recall restores a remembered report onto a freshly admitted entry.
//
// The stale timestamps are restored as they were, not clamped to now: whether
// the cooldown still has time to run is shouldReport's comparison to make, and
// a memory that silently refreshed itself would extend the cooldown every time
// the attacker forced an eviction -- the defect inverted.
func (t *sourceTable) recall(addr netip.Addr, s *sourceState) {
	i, ok := t.memoAt[addr]
	if !ok {
		return
	}
	s.reported = t.memo[i].reported
	s.reportedEligible = t.memo[i].reportedEligible
	s.reportedAtNs = t.memo[i].reportedAtNs
	s.suppressedUntilNs = t.memo[i].suppressedUntilNs
}

// tableChunk is how many entries one growth step carves at a time. Large
// enough that growing is rare -- one allocation per 64 sources admitted, and
// none at all once the table has been filled once -- and small enough that a
// desktop which never sees more than a handful of peers never allocates the
// rest.
const tableChunk = 64

// mapHint is the initial size for a shard's address map: the same granularity
// the slab grows by, so neither one reserves capacity nobody has used.
func mapHint(capacity int) int {
	if capacity > tableChunk {
		return tableChunk
	}
	return capacity
}

// grow carves another chunk onto the free list. It returns false when the
// table has already reached its configured capacity.
func (t *sourceTable) grow() bool {
	n := t.capacity - t.allocated
	if n <= 0 {
		return false
	}
	if n > tableChunk {
		n = tableChunk
	}
	c := make([]tableEntry, n)
	for i := 0; i < n-1; i++ {
		c[i].next = &c[i+1]
	}
	c[n-1].next = t.free
	t.free = &c[0]
	t.slabs = append(t.slabs, c)
	t.allocated += n
	return true
}

// unlink takes e out of the LRU list. It does not touch the free list.
func (t *sourceTable) unlink(e *tableEntry) {
	if e.prev == nil {
		t.head = e.next
	} else {
		e.prev.next = e.next
	}
	if e.next == nil {
		t.tail = e.prev
	} else {
		e.next.prev = e.prev
	}
	e.prev, e.next = nil, nil
	t.nlive--
}

// pushFront makes e the most recently used.
func (t *sourceTable) pushFront(e *tableEntry) {
	e.prev = nil
	e.next = t.head
	if t.head != nil {
		t.head.prev = e
	}
	t.head = e
	if t.tail == nil {
		t.tail = e
	}
	t.nlive++
}

// moveToFront is the recency update the packet path performs on every packet
// from an already-tracked source. It returns immediately when the entry is
// already at the front, which is the common case for a source sending a burst.
func (t *sourceTable) moveToFront(e *tableEntry) {
	if t.head == e {
		return
	}
	t.unlink(e)
	t.pushFront(e)
}

// release returns entry e to the free list, blanking its state. Entries are
// reused, so anything left behind would be read as the next source's history --
// its score or "already reported" flag attributed to another address, by an
// attacker who controls eviction.
func (t *sourceTable) release(e *tableEntry) {
	e.addr = netip.Addr{}
	e.state = sourceState{}
	e.prev = nil
	e.next = t.free
	t.free = e
}

// get returns the state for addr, creating it if needed, and marks it as most
// recently used. It never returns nil.
func (t *sourceTable) get(addr netip.Addr, nowNs uint64) *sourceState {
	if e, ok := t.entries[addr]; ok {
		t.moveToFront(e)
		return &e.state
	}
	if t.nlive >= t.capacity {
		t.evictOne(nowNs)
	}
	e := t.free
	if e == nil && t.grow() {
		e = t.free
	}
	if e == nil {
		// Unreachable: nlive < capacity implies either a free entry or room to
		// grow. Evicting rather than panicking keeps a bug here from taking the
		// daemon down.
		t.evictOne(nowNs)
		e = t.free
		if e == nil {
			return new(sourceState)
		}
	}
	t.free = e.next

	e.addr = addr
	e.state = sourceState{
		firstSeenNs: nowNs,
		lastSeenNs:  nowNs,
		lastDecayNs: nowNs,
	}
	// A source that was reported before it was evicted comes back still
	// reported, so that forcing an eviction does not reset its cooldown.
	t.recall(addr, &e.state)
	t.pushFront(e)
	t.entries[addr] = e
	return &e.state
}

// lookup returns the state for addr without creating it or changing its
// recency.
func (t *sourceTable) lookup(addr netip.Addr) (*sourceState, bool) {
	e, ok := t.entries[addr]
	if !ok {
		return nil, false
	}
	return &e.state, true
}

// evictScanDepth bounds how far back evictOne looks. It must stay small: this
// runs on the packet path, once per newly seen source.
const evictScanDepth = 8

// evictReportableBias lifts an already-reportable source above every score.
//
// Scores are uint32, so nothing can reach this by scoring alone, and the
// ordering within each class stays the score itself.
const evictReportableBias = 1 << 32

// evictOne makes room for a new source by discarding the weakest of the least
// recently used entries, not merely the least recently used.
//
// Strict LRU is a detection bypass: forged sources interleaved between two
// probes push the scanner out, and it comes back with a blank score every time.
// Ranking by the score each source would have now closes the cheap variants --
// a forged address with a packet or three does not displace a scanner with
// evidence, and an abandoned source decays out of the way.
//
// It does not make the flood's cost track the scan it hides: a scanner flooding
// from its first probe keeps its own score at one probe's worth. A bounded table
// cannot close that -- whoever presents more distinct sources than it holds can
// displace anything in it, and refusing new sources instead would let one
// filling stop every later scanner being tracked. Eviction sets the price
// (a little more than one full table of forged packets per hidden probe), and
// Engine.EvictionPressure reports when someone is paying it.
//
// The walk is bounded and always evicts something.
func (t *sourceTable) evictOne(nowNs uint64) {
	back := t.tail
	if back == nil {
		return
	}

	// Among equals the least recently used loses, which is what makes this a
	// refinement of LRU rather than a replacement for it.
	victim := back
	weakest := t.evictionRank(&back.state, nowNs)
	for i, e := 1, back.prev; e != nil && i < evictScanDepth; i, e = i+1, e.prev {
		if r := t.evictionRank(&e.state, nowNs); r < weakest {
			victim, weakest = e, r
		}
	}

	// Keep the report before the entry is wiped: release zeroes the whole
	// struct, reportedAtNs and suppressedUntilNs with it.
	if victim.state.reported || victim.state.suppressedUntilNs != 0 {
		t.remember(victim.addr, victim.state.reportedAtNs,
			victim.state.suppressedUntilNs, victim.state.reported,
			victim.state.reportedEligible)
	}

	delete(t.entries, victim.addr)
	t.unlink(victim)
	t.release(victim)
	t.evicted++
}

// evictionRank orders sources by how much is lost by forgetting one, at nowNs.
//
// It ranks by the score the source would have after decay: eviction candidates
// are the entries nothing has arrived for, so their stored score is the stale
// one, and comparing it would let a source scored once and abandoned outrank a
// scanner that had just started, for good. It does not write: idle entries are
// brought up to date by Expire.
func (t *sourceTable) evictionRank(s *sourceState, nowNs uint64) uint64 {
	r := uint64(s.decayedScore(nowNs, t.decayIntervalNs))

	// An IP protocol scan carries no score at all -- protocol probes have no port --
	// so a crossed protoScan is placed on the score scale at the threshold, and
	// ages from its last packet at the rate a score would. Otherwise a running,
	// reported nmap -sO would rank last and be the first entry discarded.
	if s.protoScan || s.icmpSweep {
		r += decayUnits(uint64(t.scoreThreshold), s.lastSeenNs, nowNs, t.decayIntervalNs)
	}

	if r == 0 {
		// The bucket has emptied: whatever this source once was, it has sent
		// nothing for long enough that the engine no longer holds it against
		// them. The bias below must not survive that, or "was reportable once"
		// would keep a slot for ever -- the same staleness, through the other
		// door.
		return 0
	}
	if s.protoScan || s.icmpSweep || s.reported {
		// Still live and already reportable: forgetting it loses an alert the
		// user was owed, or the cooldown that stops them being told twice.
		r += evictReportableBias
	}
	return r
}

// decayUnits is v reduced by one for each whole decayIntervalNs since `since`,
// saturating at zero -- the leaky bucket applied to a quantity the bucket does
// not itself hold.
func decayUnits(v, since, nowNs, decayIntervalNs uint64) uint64 {
	if decayIntervalNs == 0 || nowNs <= since {
		return v
	}
	steps := (nowNs - since) / decayIntervalNs
	if steps >= v {
		return 0
	}
	return v - steps
}

func (t *sourceTable) remove(addr netip.Addr) {
	if e, ok := t.entries[addr]; ok {
		delete(t.entries, addr)
		t.unlink(e)
		t.release(e)
	}
}

// expire removes entries idle for longer than idleNs. It walks from the least
// recently used end and stops at the first live entry, so its cost is
// proportional to the number of entries actually removed, not to the table
// size.
func (t *sourceTable) expire(nowNs, idleNs uint64) int {
	removed := 0
	for {
		e := t.tail
		if e == nil {
			return removed
		}
		// Strictly "longer than", so an entry sitting exactly on the boundary
		// is kept. The guard on nowNs going backwards mirrors the one in
		// sourceState.decay.
		if nowNs < e.state.lastSeenNs || nowNs-e.state.lastSeenNs <= idleNs {
			return removed
		}
		// Idle expiry forgets a report just as eviction does, so it remembers it the
		// same way; otherwise an operator raising ReportCooldown above IdleExpiry
		// would get a cooldown that ends after IdleExpiry of silence.
		if e.state.reported || e.state.suppressedUntilNs != 0 {
			t.remember(e.addr, e.state.reportedAtNs,
				e.state.suppressedUntilNs, e.state.reported,
				e.state.reportedEligible)
		}
		delete(t.entries, e.addr)
		t.unlink(e)
		t.release(e)
		removed++
	}
}

// lookup returns a COPY of a source's state, without touching its recency.
//
// A copy, not the pointer, because the pointer would outlive the lock: the
// caller (Engine.LookupForBlock, from outside the packet path) would read a
// *sourceState with no lock held while Process mutates the same struct under
// the shard's. sourceState holds no slice or map, and netip.Addr is an
// immutable value, so the copy shares nothing mutable and is cheap.
func (t *shardedTable) lookup(a netip.Addr) (sourceState, bool) {
	s := t.shardFor(a)
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.lookup(a)
	if !ok {
		return sourceState{}, false
	}
	return *st, true
}

// countedTotal sums the per-shard counters. Off the packet path.
func (t *shardedTable) countedTotal() uint64 {
	var n uint64
	for _, s := range t.shards {
		s.mu.Lock()
		n += s.counted
		s.mu.Unlock()
	}
	return n
}

package portscan

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// HostInfo supplies the local knowledge that lets a host-based detector tell a
// scan from ordinary traffic. A network sensor must guess from TCP flags
// whether a packet is return traffic, and scanlogd and PortSentry end up
// discarding every ACK and RST for that reason; a host can look.
type HostInfo interface {
	// IsLocalUnicast reports whether addr is one of this host's own unicast
	// addresses. Packets to broadcast or multicast destinations are not counted.
	IsLocalUnicast(addr netip.Addr) bool

	// IsListening reports whether a local service is bound to the given
	// protocol and port. A SYN to a closed port is far stronger evidence of
	// probing than a SYN to a running service; Portmaster keys on this
	// exclusively, PortSentry uses it to skip ports in use (IsPortInUse).
	IsListening(proto uint8, port uint16) bool

	// HasConnection reports whether the probe belongs to a connection this
	// host already knows about, in either direction.
	HasConnection(p *Probe) bool

	// IsOnLink reports whether addr belongs to a directly attached subnet.
	// Only then is the packet's source MAC the scanner's own MAC rather than
	// the last router's, and only then may it be reported as identifying.
	IsOnLink(addr netip.Addr) bool

	// IsExempt reports whether addr is on an operator or auto-derived
	// exemption list and must never be counted or blocked.
	IsExempt(addr netip.Addr) bool
}

// ScanEvent is the verdict emitted when a source crosses the threshold.
//
// Fields describe only what the observed packets establish. In particular
// nothing here claims that Src is the attacker: with nmap -D, nmap -S, an idle
// scan or an FTP bounce, the source address is a third party's, and the real
// origin is not recoverable from the packets. Consumers must treat Src as
// "the address the packets carried", which is why blocking is gated by policy.
type ScanEvent struct {
	Src    netip.Addr
	SrcMAC [6]byte
	// HasMAC reports that a link-layer address was available at all.
	HasMAC bool
	// MACIsSourceOwn reports that Src is on-link, and therefore that SrcMAC is
	// the scanner's own address rather than an intermediate router's.
	MACIsSourceOwn bool

	Method       ScanMethod
	MethodDetail string

	FlagsOr      uint8
	FlagsAnd     uint8
	FlagsSummary string

	DistinctPorts  uint32
	MinPort        uint16
	MaxPort        uint16
	SamplePorts    []uint16
	Protocols      uint16
	IsProtocolScan bool

	Score      uint32
	Anomalies  Anomaly
	IfaceIndex uint32

	// Targets lists the local addresses that were probed (capped).
	Targets []netip.Addr

	FirstSeenNs uint64
	LastSeenNs  uint64
	FirstSeen   time.Time
	LastSeen    time.Time

	// HasTCPEvidence reports whether a probe only a scanner sends contributed:
	// a SYN, flags that cannot acknowledge anything, or a TCP probe whose flags
	// could not be read (nmap -f; see probeClass.isEvidence). It is named after
	// BlockConfig.RequireTCPEvidence, and does not mean that TCP arrived: an ACK,
	// alone or with FIN, is TCP and is not evidence. Blocking without it is
	// refused by default: such a source address costs nothing to forge, which is
	// why PortSentry warns that UDP blocking enables "a possible Denial of
	// service attack" (examples/portsentry.conf:110-113).
	HasTCPEvidence bool

	// BlockEligible reports whether policy permits proposing or applying a
	// block for this source.
	BlockEligible bool

	// SuppressedSince is how many scan events were withheld by rate limiting
	// since the last emitted event. Non-zero means the consumer should say so
	// rather than pretend this is the only scan in progress.
	SuppressedSince uint64

	// evidence is sourceEvidence when the event was built: what reporting it
	// says, for the baseline markReported records.
	evidence evidence
}

// Stats are engine counters, for the status output and the coverage report.
type Stats struct {
	ProbesSeen       uint64
	ProbesCounted    uint64
	ProbesFiltered   uint64
	EventsEmitted    uint64
	EventsSuppressed uint64
	SourcesTracked   int
	SourcesEvicted   uint64
}

// engineStats are the counters, kept as atomics so the packet path never takes
// a lock to bump one.
type engineStats struct {
	probesSeen       atomic.Uint64
	probesFiltered   atomic.Uint64
	eventsEmitted    atomic.Uint64
	eventsSuppressed atomic.Uint64
}

// Engine is the pure detection core. It is safe for concurrent use.
//
// There is no engine-wide lock on the packet path: Process takes only the lock
// of the shard owning the source, after the structural filters and the HostInfo
// calls, so a flood on one core does not make other packets wait behind it.
type Engine struct {
	cfg  Config
	host HostInfo

	table *shardedTable

	excludedPorts map[uint16]struct{}
	// ifaceAllowed is replaced wholesale, never mutated, so the packet path can
	// read it without a lock.
	ifaceAllowed atomic.Pointer[map[uint32]bool]

	scoreCeiling    uint32
	decayIntervalNs uint64
	idleExpiryNs    uint64
	cooldownNs      uint64
	// evidenceWindowNs is how long hasTCPEvidence stands without a new
	// evidence probe: the time a full bucket takes to drain. See ageFacts.
	evidenceWindowNs uint64

	// startNs is the monotonic time the engine started, for the startup grace.
	// Atomic because SetWallClockAnchor may replace it after construction.
	startNs atomic.Uint64
	graceNs uint64
	// startWallNs is the wall clock of the anchor, in Unix nanoseconds, or zero
	// when it was never set; wallAnchorNs is the monotonic reading it was taken at.
	// They are separate from startNs, which also arms the startup grace: re-anchoring
	// through it would push the grace forward every time.
	startWallNs  atomic.Int64
	wallAnchorNs atomic.Uint64

	// Rate limiting, modelled on scanlogd's safe_log (scanlogd.c:172-186). Global
	// by nature -- a decoy scan's hundred sources must share one budget -- so it has
	// a lock of its own, reached only by a source that has crossed and passed its
	// cooldown.
	rlMu            sync.Mutex
	rlWindowStartNs uint64
	rlCount         int
	suppressed      uint64

	// lastEvicted is the eviction count at the previous EvictionPressure call.
	lastEvicted atomic.Uint64

	// pending holds crossings the alert limiter refused. See pendingReports.
	pending *pendingReports

	stats engineStats
}

// NewEngine builds an Engine. It returns an error if cfg is invalid.
//
// startNs must be the current monotonic clock reading in nanoseconds, the same
// clock later fed to Process through Probe.TimeNs.
func NewEngine(cfg Config, host HostInfo, startNs uint64) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	var seed [16]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("portscan: seeding the engine: %w", err)
	}

	e := &Engine{
		cfg:     cfg,
		host:    host,
		pending: newPendingReports(),
		// Eviction discards the weakest of the least recently used, ranked by
		// the score each source would have NOW, so the table needs the decay
		// rate. See sourceTable.evictOne. The seed decides which shard an
		// address lands in, and must be as unpredictable as the port seed: a
		// fixed one lets an attacker aim a flood at a single shard.
		table:            newShardedTable(cfg.MaxSources, uint64(cfg.DecayInterval), cfg.ScoreThreshold, binary.LittleEndian.Uint64(seed[8:])),
		excludedPorts:    make(map[uint16]struct{}, len(cfg.ExcludedPorts)),
		scoreCeiling:     cfg.ScoreThreshold * 2,
		decayIntervalNs:  uint64(cfg.DecayInterval),
		idleExpiryNs:     uint64(cfg.IdleExpiry),
		cooldownNs:       uint64(cfg.ReportCooldown),
		evidenceWindowNs: saturatingMul(uint64(cfg.ScoreThreshold), uint64(cfg.DecayInterval)),
		graceNs:          uint64(cfg.StartupGrace),
		rlWindowStartNs:  startNs,
	}
	e.startNs.Store(startNs)
	for _, p := range cfg.ExcludedPorts {
		e.excludedPorts[p] = struct{}{}
	}
	return e, nil
}

// SetWallClockAnchor records the wall-clock time corresponding to a monotonic
// reading, so events can carry human-readable timestamps. Without it, the
// ScanEvent time fields stay zero and only the monotonic ones are meaningful.
func (e *Engine) SetWallClockAnchor(wall time.Time, monoNs uint64) {
	e.startNs.Store(monoNs)
	e.RefreshWallClockAnchor(wall, monoNs)
}

// RefreshWallClockAnchor re-pairs the wall clock with the monotonic one,
// without touching the startup grace. It is called periodically: probe
// timestamps are CLOCK_MONOTONIC, which does not advance during suspend, so
// without it every alert time would drift by the total time the machine has
// slept, plus any NTP step.
func (e *Engine) RefreshWallClockAnchor(wall time.Time, monoNs uint64) {
	e.wallAnchorNs.Store(monoNs)
	e.startWallNs.Store(wall.UnixNano())
}

// SetAllowedInterfaces restricts detection to the given interface indices.
// An empty or nil map means every interface is allowed.
func (e *Engine) SetAllowedInterfaces(idx map[uint32]bool) {
	e.ifaceAllowed.Store(&idx)
}

// probeClass is the outcome of classifying one probe.
type probeClass struct {
	multiplier uint32
	counted    bool
	isTCP      bool
	// known marks a probe that belongs to a connection this host already knows
	// about, so the distinct-protocol counter can leave it out.
	known bool
	// isICMP marks a scored ICMP probe, tallied as ICMP rather than as UDP, so an
	// ICMP-only sweep is not reported as several techniques combined.
	isICMP bool
	// isEvidence marks a probe only a scanner sends -- a SYN, flags that cannot
	// acknowledge anything, or TCP flags that could not be read (nmap -f) -- as
	// opposed to one with the shape of return traffic. It is what
	// BlockConfig.RequireTCPEvidence gates on. A forged FIN|ACK is TCP and costs
	// as little as a forged datagram; what matters is whether a legitimate peer
	// could have sent it. It does not make the source address trustworthy, which
	// no passive sensor can do; that is why the default policy asks.
	isEvidence bool
	// fixedWeight, when non-zero, is what this probe scores outright, instead of
	// the port class times the multiplier. ICMP has no port to classify.
	fixedWeight uint32
	// evasion marks a probe that exhausted the IPv6 extension-header walk. It
	// has no readable port to deduplicate on, so every such packet scores.
	evasion bool
	reason  string
}

// classify decides how much a probe is worth.
//
// The ordering matters: cheap structural rejections come before any oracle
// call, so that flood traffic is discarded without consulting the connection
// table or the listening-socket table.
func (e *Engine) classify(p *Probe) probeClass {
	// A packet that exhausted the extension-header walk carries a transport
	// header the parser could not reach, and the host answers it anyway: every
	// walk here is bounded and Linux's is not, so without this a scan behind
	// nine empty headers, or one long one, would score nothing. Ordinary traffic
	// never has such a chain, so each packet scores like a SYN to a system
	// port. It is not evidence -- nothing corroborates its source.
	//
	// Only a walk that failed counts, one that stopped on an extension header.
	// The same anomaly marks a jumbogram (Payload Length 0 behind Hop-by-Hop),
	// the shape Linux gives IPv6 segments over 64 KiB with BIG TCP: its TCP
	// header is read like any other, and counting the flag alone would report
	// a download over a known connection as a scan.
	if p.Anomalies&AnomalyExtHeaderChain != 0 && isIPv6ExtHeader(p.Proto) &&
		(e.cfg.DetectTCP || e.cfg.DetectUDP) {
		return probeClass{counted: true, evasion: true,
			fixedWeight: ProbeWeight(PortSystem, multSynClosed), reason: "ipv6-extension-evasion"}
	}
	switch {
	case p.IsTCP():
		if !e.cfg.DetectTCP {
			return probeClass{reason: "tcp-detection-disabled"}
		}
		// A packet carrying RST alone, or RST|ACK, is a rejection, not a probe:
		// counting it would let anyone raise our score by bouncing traffic off us. Only
		// when the flags were actually read, or a forged RST on the first fragment of a
		// fragmented scan would exempt the whole scan. And exactly those two values,
		// not any packet with RST set: nmap --scanflags ALL sets RST alongside
		// everything else. The kernel program tests the same two values.
		if p.TCPFlagsValid && p.Anomalies&(AnomalyTruncated|AnomalyTrailer) == 0 &&
			(p.TCPFlags == TCPRst || p.TCPFlags == TCPRst|TCPAck) {
			return probeClass{reason: "tcp-reset"}
		}
		// Anything belonging to a connection we know about is return traffic.
		// This is the check scanlogd cannot make and compensates for by
		// dropping every ACK and RST.
		if e.host != nil && e.host.HasConnection(p) {
			return probeClass{known: true, reason: "known-connection"}
		}
		if !p.TCPFlagsValid {
			// The flag octet was not captured -- nmap -f's first fragment ends after the
			// eighth byte of the TCP header. The port is present, so the probe counts, but
			// as an ordinary SYN: flags that were not seen cannot be called anomalous.
			return probeClass{multiplier: multSynClosed, counted: true, isTCP: true, isEvidence: true, reason: "tcp-flags-unreadable"}
		}
		switch {
		case p.hasFlags(TCPSyn) && !p.hasAnyFlag(TCPAck|TCPRst|TCPFin):
			// A plain SYN: a connection attempt. Whether it is a scan depends
			// on how many distinct ports it is repeated across, and on whether
			// anything is listening.
			if e.host != nil && e.host.IsListening(ProtoTCP, p.DstPort) {
				return probeClass{multiplier: multSynOpen, counted: true, isTCP: true, isEvidence: true, reason: "syn-open-port"}
			}
			return probeClass{multiplier: multSynClosed, counted: true, isTCP: true, isEvidence: true, reason: "syn-closed-port"}
		case p.hasFlags(TCPAck):
			// ACK is set: this has the shape of return traffic, whatever rides with it --
			// a straggler from a socket that just closed, or a connection's teardown. The
			// connection table is a snapshot up to ten seconds old, so a short-lived
			// connection is often not in it. Such packets count at the lowest weight and are
			// not evidence (see isEvidence).
			//
			// Aimed at our ephemeral range with nothing listening, they do not count at
			// all: the SYN|ACK that opens every outbound connection lands in that snapshot
			// gap on a new ephemeral port each time, which deduplication cannot absorb, and
			// ordinary outbound traffic to one peer would cross the threshold within the hour.
			// Return traffic arrives where we chose the port, a scan where the scanner did;
			// see ephemeralRange.
			if isEphemeralPort(p.DstPort) && (e.host == nil || !e.host.IsListening(ProtoTCP, p.DstPort)) {
				return probeClass{isTCP: true, reason: "ack-return-traffic"}
			}
			return probeClass{multiplier: multAckNoConn, counted: true, isTCP: true, reason: "ack-no-connection"}
		default:
			// Everything else -- FIN alone, NULL, Xmas, SYN|FIN, any --scanflags
			// combination without ACK -- cannot be return traffic, since a peer that
			// believes it has a connection always acknowledges. The highest weight, and
			// expressed as "anything not matched above" so that a novel combination is
			// still caught.
			return probeClass{
				multiplier: multAnomalousFlags, counted: true, isTCP: true,
				isEvidence: true, reason: "anomalous-tcp-flags",
			}
		}

	case p.IsUDP():
		if !e.cfg.DetectUDP {
			return probeClass{reason: "udp-detection-disabled"}
		}
		if e.host != nil && e.host.HasConnection(p) {
			return probeClass{known: true, reason: "known-connection"}
		}
		if isTracerouteUDPPort(p.DstPort) {
			// UDP traceroute walks this IANA range one port at a time, which looks
			// exactly like a scan: a monitoring station running mtr --udp would otherwise
			// be reported all day. Only UDP, and only this range, where nothing listens; a
			// TCP scan of the same ports still counts.
			return probeClass{reason: "udp-traceroute"}
		}
		if e.host != nil && e.host.IsListening(ProtoUDP, p.DstPort) {
			return probeClass{reason: "udp-open-port"}
		}
		return probeClass{multiplier: multUDP, counted: true, reason: "udp-closed-port"}

	case p.IsICMP():
		// ICMP is scored by message type, and only for the types a scanner sends. The
		// type travels in DstPort (see Probe.ICMPType) and is deduplicated like a port,
		// so a source is worth one score per distinct type however many packets it
		// sends: an echo request is the most ordinary packet there is, and a ping -f
		// must not look like an attack. DetectICMPSweep gates the score as well as the
		// distinct-type counter.
		if !e.cfg.DetectICMPSweep {
			return probeClass{reason: "icmp-detection-off"}
		}
		// Read per address family, never pooled (see Probe.IsICMPSweepProbe): types
		// 13, 15 and 17 are unassigned in ICMPv6 and 139 in ICMPv4, and pooling let
		// forged packets with meaningless types score.
		switch p.Proto {
		case ProtoICMP:
			switch p.ICMPType() {
			case icmpv4Timestamp, icmpv4Information, icmpv4AddressMask:
				// Dead protocols. RFC 1122 allowed them; nothing has used them
				// in decades except nmap -PP and -PM. One of these arriving is
				// already abnormal, which is why it scores on its own.
				return probeClass{counted: true, isICMP: true, fixedWeight: weightICMPRecon, reason: "icmp-recon"}
			}
		case ProtoICMPv6:
			switch p.ICMPType() {
			case icmpv6NodeInfoQuery:
				// RFC 4620 Node Information Query: asks the host for its names
				// and addresses. Reconnaissance by definition.
				return probeClass{counted: true, isICMP: true, fixedWeight: weightICMPRecon, reason: "icmp-recon"}
			}
		}
		// Everything else, echo included, is counted towards the distinct-type
		// total below but scores nothing by itself.
		return probeClass{reason: "icmp-other"}

	default:
		// Other IP protocols are not scored per port -- they have none -- but
		// they feed the distinct-protocol counter used for nmap -sO.
		return probeClass{reason: "other-protocol"}
	}
}

// Process feeds one probe to the engine and returns a ScanEvent when the source
// has just crossed the reporting threshold, or nil otherwise. Its work is
// bounded: nothing here grows with the ports already seen or the sources
// tracked, so a scan does not get more expensive to observe the longer it runs.
func (e *Engine) Process(p *Probe) *ScanEvent {
	if !e.cfg.Enabled {
		return nil
	}

	e.stats.probesSeen.Add(1)

	// accept and classify both consult HostInfo, whose cost the interface does
	// not bound and which takes locks of its own. They run before any lock here
	// is taken, so a slow oracle can never serialise the whole engine.
	if !e.accept(p) {
		e.stats.probesFiltered.Add(1)
		return nil
	}
	cls := e.classify(p)

	shard := e.table.shardFor(p.Src)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	st := shard.get(p.Src, p.TimeNs)
	st.decay(p.TimeNs, e.decayIntervalNs)
	if p.TimeNs > st.lastSeenNs {
		st.lastSeenNs = p.TimeNs
	}
	e.ageFacts(st)
	st.anomalies |= p.Anomalies
	if p.HasMAC && !st.hasMAC {
		st.srcMAC, st.hasMAC = p.SrcMAC, true
	}
	st.addDst(p.Dst)

	// The distinct-protocol counter is fed by probes that score nothing, since
	// that is what an IP protocol scan is: many protocols, no ports. It is not fed
	// by traffic of a connection this host knows about -- a peer terminating
	// tunnels sends ESP, AH, GRE, TCP, UDP and ICMP in ordinary operation.
	if !cls.known {
		newProto := st.addProtocol(p.Proto)
		if e.cfg.DetectProtocolScan && newProto && st.protoCount >= e.cfg.ProtoScanMinProtocols {
			st.protoScan = true
		}
	}

	// An ICMP sweep crosses on the count of distinct query types, as a protocol
	// scan does on distinct protocols: nmap -PE -PP -PM sends three, a monitoring
	// system one, whatever the rate. Replies and errors never count; they are what
	// this host asked for (see Probe.IsICMPSweepProbe).
	if e.cfg.DetectICMPSweep && p.IsICMP() && p.IsICMPSweepProbe() &&
		st.addICMPType(p.ICMPType()) &&
		st.icmpTypeCount >= icmpSweepThreshold(e.cfg.ICMPSweepMinTypes, p.Proto) {
		st.icmpSweep = true
	}

	if cls.counted {
		switch {
		case cls.isTCP:
			st.tcpProbes++
			if p.TCPFlagsValid {
				st.observeFlags(p.TCPFlags)
			} else {
				st.tcpProbesNoFlags++
			}
		case cls.isICMP:
			st.icmpProbes++
		case cls.evasion:
			st.evasionProbes++
		default:
			st.udpProbes++
		}
		// Deduplicate before scoring. Without this, the SYN retransmissions of
		// a single unanswered connection attempt would each count as another
		// scanned port. An evasion probe has no port to deduplicate on.
		if cls.evasion || st.addPort(p.Proto, p.DstPort) {
			weight := cls.fixedWeight
			if weight == 0 {
				weight = ProbeWeight(ClassifyPort(p.DstPort), cls.multiplier)
			}
			st.addScore(weight, e.scoreCeiling)
			if cls.isEvidence {
				st.hasTCPEvidence = true
				st.lastEvidenceNs = st.lastSeenNs
			}
			shard.counted++
		}
	}

	report, suppressed, queue := e.shouldReport(st, p.TimeNs)
	if queue {
		// The crossing happened; only the budget said no. Build the event and
		// keep it, so DrainPending can name this source once a slot frees --
		// rather than requiring another probe from a scanner that may well have
		// finished. That requirement would let three forged decoys and 27
		// packets buy a real scan permanent silence.
		e.pending.add(e.buildEvent(p, st, 0))
		st.queuedEvidence = sourceEvidence(st).total()
		return nil
	}
	if !report {
		// A source queued in this window is not asked about again until the
		// window ends, and a fast scan is over by then: queued as it stood at
		// the packet that crossed, nine ports into a thousand, it would rank
		// below forged sources that crossed higher and be named, if ever, as a
		// nine-port scan. Its entry follows it instead, each time what it has
		// shown doubles: a few updates per source, never one per packet.
		if p.TimeNs < st.suppressedUntilNs {
			if ev := sourceEvidence(st).total(); ev > st.queuedEvidence && ev >= 2*st.queuedEvidence {
				e.pending.add(e.buildEvent(p, st, 0))
				st.queuedEvidence = ev
			}
		}
		return nil
	}
	e.pending.forget(p.Src)
	return e.buildEvent(p, st, suppressed)
}

// accept applies the cheap structural filters.
func (e *Engine) accept(p *Probe) bool {
	if !p.Src.IsValid() || !p.Dst.IsValid() {
		return false
	}
	// scanlogd reserves 0.0.0.0 as its "entry unused" sentinel and refuses to
	// let a spoofed source claim it (scanlogd.c:217-219). We have no such
	// sentinel, but an unspecified or loopback source on an external interface
	// is malformed regardless.
	if p.Src.IsUnspecified() || p.Src.IsLoopback() {
		return false
	}
	if p.Src.IsMulticast() {
		return false
	}
	if m := e.ifaceAllowed.Load(); m != nil && len(*m) > 0 && !(*m)[p.IfaceIndex] {
		return false
	}
	// Only packets aimed at one of our own unicast addresses count. This
	// discards broadcast, multicast and anything merely passing through.
	if e.host != nil && !e.host.IsLocalUnicast(p.Dst) {
		return false
	}
	if e.host != nil && e.host.IsExempt(p.Src) {
		return false
	}
	if p.IsTCP() || p.IsUDP() {
		if _, bad := e.excludedPorts[p.DstPort]; bad {
			return false
		}
	}
	// A non-initial fragment has no L4 header at any assumed offset. It is
	// recorded as an anomaly by the packet source but must never be scored as
	// if its port fields were real.
	if p.Anomalies&AnomalyFragment != 0 {
		return false
	}
	// Startup grace, applied only to TCP carrying ACK: the packets of a
	// connection that was open before the daemon started, whose owner the
	// socket table may not show yet. A SYN, a FIN alone, a NULL or an Xmas
	// cannot be part of one, because a peer that believes it has a connection
	// always acknowledges. Nor is there a start-up reason to spare UDP or an
	// ICMP query: a datagram for a socket that still exists is recognised by
	// the socket table, and one for a socket that has closed looks the same a
	// minute after start-up as during it.
	//
	// The grace is a blind window an attacker can wait for, sixty seconds on
	// every boot; it must be no wider than what it is for. The eBPF program
	// applies the same condition in the kernel.
	if p.TimeNs < e.startNs.Load()+e.graceNs && p.IsTCP() && p.hasFlags(TCPAck) {
		return false
	}
	return true
}

// shouldReport decides whether the source has just become reportable.
func (e *Engine) shouldReport(st *sourceState, nowNs uint64) (report bool, suppressedSince uint64, queue bool) {
	crossed := st.score >= e.cfg.ScoreThreshold || st.protoScan || st.icmpSweep
	if !crossed {
		return false, 0, false
	}
	eligible := e.blockEligible(st)
	// A source that becomes blockable is reported again at once, past the
	// cooldown and whatever else it has shown: otherwise a first report that
	// could not be blocked -- three ICMP queries, a few UDP or ACK probes --
	// would hold back for the whole cooldown the SYN scan that follows it, and
	// with it the question or the block. At most once per report that could
	// not be blocked, and still subject to the limiter below.
	if !st.reported || st.reportedEligible || !eligible {
		// A zero cooldown means no cooldown, as the configuration documents it.
		if st.reported && e.cooldownNs > 0 && nowNs < st.reportedAtNs+e.cooldownNs {
			return false, 0, false
		}
		// Past the cooldown, there must also be something new to say: the
		// cooldown is a timer, not a reason. Evidence is measured by quantities
		// that stop growing when a source repeats itself, so a scanner that
		// walks new ports, protocols or ICMP types keeps clearing this bar and
		// one that loops does not.
		if st.reported && !sourceEvidence(st).isNews(st.reportedEvidence) {
			return false, 0, false
		}
	}
	// A source already refused in the current limiter window does not ask again;
	// see sourceState.suppressedUntilNs.
	if nowNs < st.suppressedUntilNs {
		// Already queued in this window; asking again would only re-queue it.
		return false, 0, false
	}
	ok, suppressed, window := e.allowEvent(nowNs)
	if !ok {
		st.suppressedUntilNs = window + alertWindowNs
		e.stats.eventsSuppressed.Add(1)
		// Refused by the budget, not by policy: the crossing is real and is
		// queued rather than dropped. See pendingReports.
		return false, 0, true
	}
	st.suppressedUntilNs = 0
	st.reported = true
	st.reportedAtNs = nowNs
	st.reportedEligible = eligible
	st.reportedEvidence = st.reportedEvidence.raise(sourceEvidence(st))
	e.stats.eventsEmitted.Add(1)
	return true, suppressed, false
}

// evidence measures how much a source has shown, in quantities that do not
// grow when it merely repeats itself. Each kind of fact is kept apart: its
// own count is what tells whether that kind has something new.
type evidence struct {
	ports, protos, icmpTypes uint32
}

// sourceEvidence is what a source has shown so far.
//
// The port count is the clamped one: a source cycling over more ports than
// the ring holds has them accepted again on every round, so distinctPorts
// climbs without limit while the clamped count does not.
func sourceEvidence(st *sourceState) evidence {
	return evidence{
		ports:     reportedPortCount(st),
		protos:    uint32(st.protoCount),
		icmpTypes: uint32(st.icmpTypeCount),
	}
}

// isNews reports whether a source has shown more of some kind of fact than
// when it was last reported.
//
// Each kind is compared with its own baseline. A single sum would let an
// expired protocol scan hold the bar high for good (the baseline is never
// lowered; see sourceState.releaseFacts): a later scan of up to that many
// ports would add nothing to the sum and never be reported, nor proposed for
// blocking.
func (ev evidence) isNews(reported evidence) bool {
	return ev.ports > reported.ports || ev.protos > reported.protos ||
		ev.icmpTypes > reported.icmpTypes
}

// total is how many facts a source has shown, of every kind.
func (ev evidence) total() uint32 {
	return ev.ports + ev.protos + ev.icmpTypes
}

// raise returns the baseline b lifted to at least what ev has shown, kind by
// kind. A baseline only goes up, so facts that expire and come back are not
// news.
func (b evidence) raise(ev evidence) evidence {
	return evidence{
		ports:     max(b.ports, ev.ports),
		protos:    max(b.protos, ev.protos),
		icmpTypes: max(b.icmpTypes, ev.icmpTypes),
	}
}

// alertWindowNs is the alert limiter's window: AlertsPerMinute, per minute.
const alertWindowNs = uint64(time.Minute)

// windowRolled reports whether a rate-limiting window that began at startNs has
// ended by nowNs. It is the Go half of window_rolled in
// ebpf_prog/opensnitch-scan.c, and keeps the same asymmetry: a timestamp
// slightly behind the window start is not a new window. Probe timestamps arrive
// out of order on both paths (per-interface goroutines for AF_PACKET, per-CPU
// submission for eBPF), and treating every backward step as a new window handed
// out a fresh budget each time. A timestamp a whole window behind is a clock
// anomaly and does roll, or the start would sit in the future for good.
func windowRolled(startNs, nowNs, windowNs uint64) bool {
	if nowNs >= startNs {
		return nowNs-startNs >= windowNs
	}
	return startNs-nowNs >= windowNs
}

// allowEvent is the alert rate limiter. A decoy scan (nmap -D) makes up to a
// hundred forged sources cross legitimately; without a cap that is a hundred
// notifications. It returns how many sources were silenced since the last
// event it allowed -- sources, not packets, so the figure is not the
// sender's to choose -- and the start of the window it decided in.
func (e *Engine) allowEvent(nowNs uint64) (ok bool, suppressed, windowStartNs uint64) {
	e.rlMu.Lock()
	defer e.rlMu.Unlock()
	if windowRolled(e.rlWindowStartNs, nowNs, alertWindowNs) {
		e.rlWindowStartNs = nowNs
		e.rlCount = 0
	}
	if e.rlCount >= e.cfg.AlertsPerMinute {
		e.suppressed++
		return false, 0, e.rlWindowStartNs
	}
	e.rlCount++
	suppressed = e.suppressed
	e.suppressed = 0
	return true, suppressed, e.rlWindowStartNs
}

// reportedPortCount is the port count shown to the user, clamped to what is
// arithmetically possible.
//
// sourceState.distinctPorts counts ports accepted as new, and a port that has
// left the ring is accepted again when it comes back: for scoring that is the
// safe direction, but as the size of a scan shown to a user it overstates, and
// without a bound. The observed range is exact, so the count is clamped to it:
// a source that touched ports 20 through 220 cannot have touched more than 201
// of them. It remains an upper bound; the exact count would need memory
// proportional to the scan.
func reportedPortCount(st *sourceState) uint32 {
	if st.distinctPorts == 0 {
		return 0
	}
	span := uint32(st.maxPort) - uint32(st.minPort) + 1
	if st.distinctPorts > span {
		return span
	}
	return st.distinctPorts
}

func (e *Engine) buildEvent(p *Probe, st *sourceState, suppressed uint64) *ScanEvent {
	ev := &ScanEvent{
		Src:             p.Src,
		SrcMAC:          st.srcMAC,
		HasMAC:          st.hasMAC,
		Method:          describeMethod(st),
		FlagsOr:         st.flagsOr,
		FlagsAnd:        st.flagsAnd,
		DistinctPorts:   reportedPortCount(st),
		MinPort:         st.minPort,
		MaxPort:         st.maxPort,
		Protocols:       st.protoCount,
		IsProtocolScan:  st.protoScan,
		Score:           st.score,
		Anomalies:       st.anomalies,
		IfaceIndex:      p.IfaceIndex,
		FirstSeenNs:     st.firstSeenNs,
		LastSeenNs:      st.lastSeenNs,
		HasTCPEvidence:  st.hasTCPEvidence,
		SuppressedSince: suppressed,
	}

	if st.flagsSeen {
		ev.FlagsSummary = FlagsString(st.flagsOr, st.flagsAnd)
	}
	if ev.Method == MethodCustomFlags {
		ev.MethodDetail = CustomFlagsLabel(st.flagsOr)
	} else {
		ev.MethodDetail = ev.Method.Description()
	}

	ev.SamplePorts = make([]uint16, st.nSample)
	copy(ev.SamplePorts, st.samplePorts[:st.nSample])
	ev.Targets = make([]netip.Addr, st.nDstSeen)
	copy(ev.Targets, st.dstSeen[:st.nDstSeen])

	if e.host != nil {
		ev.MACIsSourceOwn = st.hasMAC && e.host.IsOnLink(p.Src)
	}

	ev.BlockEligible = e.blockEligible(st)
	ev.evidence = sourceEvidence(st)

	if wallNs := e.startWallNs.Load(); wallNs != 0 {
		ev.FirstSeen = e.wall(wallNs, st.firstSeenNs)
		ev.LastSeen = e.wall(wallNs, st.lastSeenNs)
	}
	return ev
}

// BlockDecision is what the engine knows about an address that something
// outside the packet path has asked to block.
type BlockDecision struct {
	// Reported is true when this engine actually told the user that this
	// address was scanning.
	Reported bool
	// BlockEligible is the same policy gate buildEvent applied when it did.
	BlockEligible bool
}

// LookupForBlock answers, for an address arriving from outside, whether this
// engine ever reported it and whether policy lets it be blocked. The raw score
// cannot answer the first: one forged packet makes it non-zero, and a reported
// protocol scan has none.
func (e *Engine) LookupForBlock(addr netip.Addr) BlockDecision {
	st, ok := e.table.lookup(normalizeAddr(addr))
	if !ok {
		return BlockDecision{}
	}
	return BlockDecision{
		Reported:      st.reported,
		BlockEligible: e.blockEligible(&st),
	}
}

// ageFacts expires the facts that do not live in the bucket, each on its own
// clock.
//
// The protocol and ICMP-type sets are forgotten after IdleExpiry without a new
// protocol or type. A slow scan keeps adding one, so nmap -sO or -PE -PP -PM at
// -T0 still accumulates; a peer that terminates tunnels, or pings on a schedule,
// loses them, and when they come back they are not news.
//
// hasTCPEvidence is forgotten once no evidence probe has arrived for as long as
// a full bucket takes to drain: a peer looping over more ports than the ring
// holds never lets its bucket empty, and must not stay blockable for good on the
// strength of one forged packet.
func (e *Engine) ageFacts(st *sourceState) {
	now := st.lastSeenNs
	if st.hasTCPEvidence && now-st.lastEvidenceNs >= e.evidenceWindowNs {
		st.hasTCPEvidence = false
	}
	if st.protoCount+st.icmpTypeCount > 0 && now-st.lastNewFactNs >= e.idleExpiryNs {
		st.releaseFacts()
	}
}

// saturatingMul is a*b, or the largest uint64 when that overflows. The
// evidence window is a threshold times a decay interval, both operator
// settings, and their product at the configured maxima does not fit.
func saturatingMul(a, b uint64) uint64 {
	if a != 0 && b > ^uint64(0)/a {
		return ^uint64(0)
	}
	return a * b
}

// blockEligible applies the policy gates that decide whether a block may even
// be proposed for this source.
func (e *Engine) blockEligible(st *sourceState) bool {
	if e.cfg.Block.Policy == BlockNever {
		return false
	}
	if e.cfg.Block.RequireTCPEvidence && !st.hasTCPEvidence {
		return false
	}
	return true
}

func (e *Engine) wall(anchorNs int64, ns uint64) time.Time {
	anchor := time.Unix(0, anchorNs)
	start := e.wallAnchorNs.Load()
	if ns >= start {
		return anchor.Add(time.Duration(ns - start))
	}
	return anchor.Add(-time.Duration(start - ns))
}

// Expire drops state for sources idle longer than the configured expiry.
// The caller runs it periodically; it is not on the packet path.
func (e *Engine) Expire(nowNs uint64) int {
	return e.table.expire(nowNs, e.idleExpiryNs)
}

// Forget drops all state for a source, used when the operator releases its
// block. A crossing still queued for the alert limiter goes too: drained
// after the release, it would block the source again under the policy auto,
// with no packet from it since.
func (e *Engine) Forget(addr netip.Addr) {
	addr = normalizeAddr(addr)
	e.table.remove(addr)
	e.pending.forget(addr)
}

// EvictionPressure reports how many sources have been evicted since the last
// call, and how many full turnovers of the table that is. Eviction pressure is
// the signature of the one bypass a bounded table cannot close (see evictOne):
// on an ordinary desktop it is zero for days, and a table turning over within a
// minute means someone is presenting thousands of source addresses, which is
// worth telling the user even though the engine cannot say what hides behind
// it.
func (e *Engine) EvictionPressure() (evicted uint64, turnovers float64) {
	total := e.table.evictedCount()
	since := total - e.lastEvicted.Swap(total)
	capacity := e.cfg.MaxSources
	if capacity <= 0 {
		return since, 0
	}
	return since, float64(since) / float64(capacity)
}

// Stats returns a snapshot of the engine counters.
func (e *Engine) Stats() Stats {
	return Stats{
		ProbesSeen:       e.stats.probesSeen.Load(),
		ProbesCounted:    e.table.countedTotal(),
		ProbesFiltered:   e.stats.probesFiltered.Load(),
		EventsEmitted:    e.stats.eventsEmitted.Load(),
		EventsSuppressed: e.stats.eventsSuppressed.Load(),
		SourcesTracked:   e.table.len(),
		SourcesEvicted:   e.table.evictedCount(),
	}
}

// Score returns the current score of a source, or 0 if it is not tracked.
// Intended for tests and for the status output.
func (e *Engine) Score(addr netip.Addr) uint32 {
	addr = normalizeAddr(addr)
	shard := e.table.shardFor(addr)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if st, ok := shard.lookup(addr); ok {
		return st.score
	}
	return 0
}

// Config returns the configuration, which is immutable after construction.
func (e *Engine) Config() Config { return e.cfg }

// DrainPending reports crossings the alert limiter refused earlier, as far as
// the current window allows, so the limiter is a queue and not a silence
// button: a scanner that has finished sends no further probe to be named by.
// The monitor calls it once a minute, which is the limiter's window.
func (e *Engine) DrainPending(nowNs uint64) []*ScanEvent {
	var out []*ScanEvent
	for {
		var suppressed uint64
		ev := e.pending.takeIf(func() bool {
			var ok bool
			ok, suppressed = e.allowDrain(nowNs)
			return ok
		})
		if ev == nil {
			return out
		}
		ev.SuppressedSince = suppressed
		ev = e.markReported(ev, nowNs)
		e.stats.eventsEmitted.Add(1)
		out = append(out, ev)
	}
}

// allowDrain is allowEvent for the queue: a refusal is not a suppressed alert.
// The event it would have released was counted as suppressed when it was
// queued; counting every refused drain as well added one per minute of
// saturation to the "N further alerts were suppressed" figure.
func (e *Engine) allowDrain(nowNs uint64) (ok bool, suppressed uint64) {
	e.rlMu.Lock()
	defer e.rlMu.Unlock()
	if windowRolled(e.rlWindowStartNs, nowNs, alertWindowNs) {
		e.rlWindowStartNs = nowNs
		e.rlCount = 0
	}
	if e.rlCount >= e.cfg.AlertsPerMinute {
		return false, 0
	}
	e.rlCount++
	suppressed = e.suppressed
	e.suppressed = 0
	return true, suppressed
}

// markReported records that a queued event has now been surfaced, exactly as
// shouldReport records one reported inline -- including the evidence baseline.
// Leaving that out would let a source named from the queue be named again on
// every cooldown with nothing new to say: 240 alerts a day for a looping peer,
// as soon as three crossings a minute elsewhere kept the limiter saturated.
//
// It returns the event brought up to date: the queued one can be up to half
// of what the source has shown since (see Process), and the alert should say
// all of it -- but only when the state still shows everything the queued
// event said. Facts expire while an entry waits (see ageFacts), and a
// protocol scan rebuilt after that would be reported as "unknown", with
// nothing in it; the score also leaks, and the alert gives the higher of the
// two.
//
// A state at the same address that is not the one the event was queued from
// belongs to a new source: it is left alone, so the old scan's report and
// baseline cannot silence what the new one does. A source evicted or expired
// since keeps the event it was queued with; a released one has none left,
// since Forget takes it out of the queue.
func (e *Engine) markReported(ev *ScanEvent, nowNs uint64) *ScanEvent {
	shard := e.table.shardFor(ev.Src)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if st, ok := shard.lookup(ev.Src); ok && st.firstSeenNs == ev.FirstSeenNs {
		if !ev.evidence.isNews(sourceEvidence(st)) {
			queuedScore := ev.Score
			ev = e.buildEvent(&Probe{Src: ev.Src, IfaceIndex: ev.IfaceIndex}, st, ev.SuppressedSince)
			ev.Score = max(ev.Score, queuedScore)
		}
		st.reported = true
		st.reportedAtNs = nowNs
		st.reportedEligible = ev.BlockEligible
		st.suppressedUntilNs = 0
		st.reportedEvidence = st.reportedEvidence.raise(ev.evidence)
	}
	return ev
}

// tracerouteUDPLow and tracerouteUDPHigh bound the destination ports UDP
// traceroute uses: the classic 33434 base plus the range implementations walk.
const (
	tracerouteUDPLow  = 33434
	tracerouteUDPHigh = 33534
)

// isTracerouteUDPPort reports whether a UDP destination port belongs to the
// range reserved for traceroute.
func isTracerouteUDPPort(port uint16) bool {
	return port >= tracerouteUDPLow && port <= tracerouteUDPHigh
}

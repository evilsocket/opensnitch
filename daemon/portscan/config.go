package portscan

import (
	"fmt"
	"time"
)

// Default engine parameters. Every threshold may be overridden, and
// Config.Validate rejects out-of-range values rather than clamping them: a
// runtime-configurable constant is how scanlogd's off-by-one on SCAN_MAX_COUNT
// became reachable (scanlogd commit 66f425d).
const (
	DefaultScoreThreshold = 100
	DefaultDecayInterval  = 10 * time.Second
	DefaultMaxSources     = 4096
	DefaultStartupGrace   = 60 * time.Second
	DefaultIdleExpiry     = 30 * time.Minute
	DefaultProtoScanMin   = 5
	// Three: nmap -PE -PP -PM is exactly three distinct types, and nothing
	// legitimate sends more than one.
	DefaultICMPSweepMinTypes = 3
	DefaultAlertsPerMinute   = 3
	DefaultReportCooldown    = 5 * time.Minute
	DefaultBlockDuration     = 4 * time.Hour
	DefaultMaxBlockedSource  = 128
)

// Weights applied to a probe, as the product of a port-class weight and a
// probe-class multiplier. See Engine.classify for the rationale of each.
const (
	weightPortSystem     = 4
	weightPortRegistered = 2
	weightPortDynamic    = 1

	// multAnomalousFlags applies to any TCP packet whose flag combination
	// cannot belong to a legitimate new or established connection: no ACK
	// and not a plain SYN (FIN, NULL, Xmas, SYN|FIN...). A peer that believes
	// it has a connection always acknowledges, so such a packet carries the
	// least ambiguity and earns the highest multiplier.
	multAnomalousFlags = 4
	// multSynClosed applies to a SYN aimed at a port where nothing listens:
	// the strongest ordinary evidence of probing. This is the signal
	// Portmaster keys on exclusively (detect.go: "We don't handle connections
	// to running apps").
	multSynClosed = 3
	// multSynOpen applies to a SYN aimed at a listening service, which is what
	// ordinary clients do. Counted, but barely.
	multSynOpen = 1
	// multAckNoConn applies to TCP carrying ACK, alone or with other flags
	// (FIN|ACK, the Maimon scan), that matches no known connection. Both
	// scanlogd (scanlogd.c:248) and PortSentry (sentry_stealth.c:113) discard
	// ACKs outright because they cannot tell return traffic from an ACK scan.
	// We can consult the host's connection table, so we count it, but at the
	// lowest weight: a stale ACK from a just-closed socket is a real occurrence.
	multAckNoConn = 1
	// multUDP applies to UDP probes. UDP is trivially spoofable and legitimate
	// multi-port UDP traffic is common (mDNS, SSDP, games, P2P), so its weight
	// is low and, per Config.RequireTCPEvidence, it cannot on its own justify
	// blocking.
	multUDP = 1
)

// Config holds the tunable behaviour of the detection engine.
type Config struct {
	// Enabled turns the whole feature on or off.
	Enabled bool `json:"Enabled"`

	// Interfaces restricts detection to these interface names. Empty means
	// every interface except loopback.
	Interfaces []string `json:"Interfaces"`

	DetectTCP          bool `json:"DetectTCP"`
	DetectUDP          bool `json:"DetectUDP"`
	DetectProtocolScan bool `json:"DetectProtocolScan"`

	// DetectICMPSweep turns the ICMP host-sweep detector on or off, on its own:
	// ICMP is the family most likely to misbehave on an unusual network, and
	// silencing it must not cost TCP and UDP detection. It is not accepted as the
	// only detector, since a sweep alone carries no port evidence.
	DetectICMPSweep bool `json:"DetectICMPSweep"`

	// ScoreThreshold is the score at which a source is reported as scanning.
	ScoreThreshold uint32 `json:"ScoreThreshold"`

	// DecayInterval is how long it takes for one point of score to decay. A leaky
	// bucket (as in Portmaster) rather than scanlogd's fixed window: a fixed window
	// misses any scan slower than itself, a bucket keeps a trace of slow scans at
	// constant memory. SlowestDetectableScan reports the consequence of this value.
	DecayInterval time.Duration `json:"DecayInterval"`

	// MaxSources bounds the number of tracked source addresses; reaching it evicts
	// an entry (see sourceTable.evictOne). A hard bound is not optional: nothing a sender
	// does may grow the table.
	MaxSources int `json:"MaxSources"`

	// IdleExpiry drops a source's state after this long without any probe.
	IdleExpiry time.Duration `json:"IdleExpiry"`

	// StartupGrace suppresses, for this long after the engine starts, TCP carrying
	// ACK: packets of connections opened before the daemon began tracking, which
	// look like probes to closed ports. Portmaster documents the same delay.
	StartupGrace time.Duration `json:"StartupGrace"`

	// ICMPSweepMinTypes is how many distinct ICMP or ICMPv6 query types a source
	// must send before it is reported as sweeping. Types rather than packets:
	// nmap -PE -PP -PM sends three, ordinary traffic one, at any rate.
	ICMPSweepMinTypes uint16 `json:"ICMPSweepMinTypes"`

	// ProtoScanMinProtocols is how many distinct IP protocol numbers a single
	// source must send before it is reported as an IP protocol scan (nmap -sO).
	// psad uses 5, noting that tcp+udp+icmp from one host is unremarkable but
	// five distinct protocols is not (psad.conf:111).
	ProtoScanMinProtocols uint16 `json:"ProtoScanMinProtocols"`

	// AlertsPerMinute caps how many scan events are emitted per minute; further
	// events are queued and counted. Without it a decoy scan (nmap -D with a
	// hundred forged sources) is a hundred notifications.
	AlertsPerMinute int `json:"AlertsPerMinute"`

	// ReportCooldown is the minimum delay before the same source is reported
	// again.
	ReportCooldown time.Duration `json:"ReportCooldown"`

	// ExcludedPorts are destination ports never counted, because legitimate
	// discovery protocols naturally touch several of them: DHCP, NetBIOS
	// 137-139, mDNS, SSDP, LLMNR. PortSentry excludes 53, 67 and 137-138 for the
	// same reason (examples/portsentry.conf:40).
	ExcludedPorts []uint16 `json:"ExcludedPorts"`

	Block BlockConfig `json:"Block"`
}

// BlockPolicy decides what happens when a scan is detected.
type BlockPolicy string

// Block policies.
const (
	// BlockNever only raises an alert.
	BlockNever BlockPolicy = "never"
	// BlockAsk raises an actionable notification and blocks only if the user
	// accepts. This is the default: OpenSnitch is an interactive firewall, and
	// asking removes the self-inflicted denial of service that automatic
	// blocking on a spoofable source address otherwise enables.
	BlockAsk BlockPolicy = "ask"
	// BlockAuto blocks without asking.
	BlockAuto BlockPolicy = "auto"
)

// BlockConfig governs the response to a detected scan. scanlogd, PortSentry
// and psad all refuse automatic blocking by default, for the reason nmap -D
// makes plain: the source of a scan is chosen by its sender, so automatic
// blocking lets an attacker choose whom the host cuts itself off from.
type BlockConfig struct {
	Policy   BlockPolicy   `json:"Policy"`
	Duration time.Duration `json:"Duration"`

	// MaxBlockedSources caps how many sources may be blocked at once; the
	// oldest block is released when the cap is reached. This bounds the damage
	// of a decoy or spoofed-source scan.
	MaxBlockedSources int `json:"MaxBlockedSources"`

	// RequireTCPEvidence refuses to block a source that sent no TCP evidence:
	// a SYN, or flags without ACK. A UDP, ICMP or protocol probe, or TCP
	// carrying ACK, has a source address that costs nothing to forge and no
	// handshake behind it, the cheapest way to weaponise automatic blocking.
	RequireTCPEvidence bool `json:"RequireTCPEvidence"`

	// There is deliberately no "what happens when nobody answers" setting: under
	// "ask" an unanswered proposal expires. Blocking on timeout would reopen what
	// "ask" exists to close, whenever the user is away.
}

// DefaultConfig returns the shipped defaults. Enabled is false: a machine whose
// configuration has no PortScan key falls back to these, and an OpenSnitch
// upgrade must not start attaching programs or opening sockets nobody asked
// for. Turning detection on is a decision made in the configuration file.
func DefaultConfig() Config {
	return Config{
		Enabled:               false,
		DetectTCP:             true,
		DetectUDP:             true,
		DetectProtocolScan:    true,
		DetectICMPSweep:       true,
		ScoreThreshold:        DefaultScoreThreshold,
		DecayInterval:         DefaultDecayInterval,
		MaxSources:            DefaultMaxSources,
		IdleExpiry:            DefaultIdleExpiry,
		StartupGrace:          DefaultStartupGrace,
		ProtoScanMinProtocols: DefaultProtoScanMin,
		ICMPSweepMinTypes:     DefaultICMPSweepMinTypes,
		AlertsPerMinute:       DefaultAlertsPerMinute,
		ReportCooldown:        DefaultReportCooldown,
		ExcludedPorts: []uint16{
			67, 68, // DHCP
			137, 138, 139, // NetBIOS over TCP/IP
			546, 547, // DHCPv6
			1900, // SSDP
			5353, // mDNS
			5355, // LLMNR
		},
		Block: BlockConfig{
			Policy:             BlockAsk,
			Duration:           DefaultBlockDuration,
			MaxBlockedSources:  DefaultMaxBlockedSource,
			RequireTCPEvidence: true,
		},
	}
}

// Validate reports why a configuration is unusable, or nil if it is sound.
//
// Bounds are rejected, never clamped: a silently corrected threshold is a
// threshold the operator believes is in force when it is not.
func (c *Config) Validate() error {
	if c.ScoreThreshold == 0 {
		return fmt.Errorf("portscan: ScoreThreshold must be greater than 0")
	}
	if c.ScoreThreshold > 1<<20 {
		return fmt.Errorf("portscan: ScoreThreshold %d is unreachably large (max %d)", c.ScoreThreshold, 1<<20)
	}
	if c.DecayInterval <= 0 {
		return fmt.Errorf("portscan: DecayInterval must be greater than 0")
	}
	if c.DecayInterval > maxDecayInterval {
		return fmt.Errorf("portscan: DecayInterval %v exceeds the maximum of %v; beyond it the"+
			" bucket never leaks, so every source eventually crosses the threshold",
			c.DecayInterval, maxDecayInterval)
	}
	if c.MaxSources < 64 {
		return fmt.Errorf("portscan: MaxSources must be at least 64, got %d", c.MaxSources)
	}
	if c.MaxSources > 1<<20 {
		return fmt.Errorf("portscan: MaxSources %d exceeds the maximum of %d", c.MaxSources, 1<<20)
	}
	if c.IdleExpiry <= 0 {
		return fmt.Errorf("portscan: IdleExpiry must be greater than 0")
	}
	if c.IdleExpiry > maxIdleExpiry {
		return fmt.Errorf("portscan: IdleExpiry %v exceeds the maximum of %v", c.IdleExpiry, maxIdleExpiry)
	}
	if c.StartupGrace < 0 {
		return fmt.Errorf("portscan: StartupGrace must not be negative")
	}
	if c.StartupGrace > maxStartupGrace {
		// Ten hours of grace is already absurd; ten years would switch
		// detection off on both paths while the daemon logged itself as active.
		return fmt.Errorf("portscan: StartupGrace %v exceeds the maximum of %v; a longer"+
			" grace switches detection off while the daemon reports it as running",
			c.StartupGrace, maxStartupGrace)
	}
	if c.ICMPSweepMinTypes < 2 {
		return fmt.Errorf("portscan: ICMPSweepMinTypes must be at least 2, got %d", c.ICMPSweepMinTypes)
	}
	if c.ICMPSweepMinTypes > 256 {
		// Refused as nonsense. It is not an off switch: the effective threshold is
		// capped at what each family can produce, four types for IPv4 and two for
		// IPv6, and DetectICMPSweep is the switch.
		return fmt.Errorf("portscan: ICMPSweepMinTypes is %d, but there are only 256"+
			" ICMP message types; set DetectICMPSweep to false to turn the detector off",
			c.ICMPSweepMinTypes)
	}
	if c.ProtoScanMinProtocols < 2 {
		return fmt.Errorf("portscan: ProtoScanMinProtocols must be at least 2, got %d", c.ProtoScanMinProtocols)
	}
	// An IP protocol number is eight bits, so protoCount never exceeds 256; a
	// larger threshold would switch protocol-scan detection off while it still
	// reads as enabled.
	if c.ProtoScanMinProtocols > 256 {
		return fmt.Errorf("portscan: ProtoScanMinProtocols is %d, but there are only 256"+
			" IP protocol numbers; a larger value would silently disable protocol scan detection",
			c.ProtoScanMinProtocols)
	}
	if c.AlertsPerMinute < 1 {
		return fmt.Errorf("portscan: AlertsPerMinute must be at least 1, got %d", c.AlertsPerMinute)
	}
	if c.ReportCooldown < 0 {
		return fmt.Errorf("portscan: ReportCooldown must not be negative")
	}
	// "Enabled" must not be able to mean "running and detecting nothing": at least
	// one of the three port detectors must be on. DetectICMPSweep does not count,
	// since a sweep reports no ports a user could check.
	if c.Enabled && !c.DetectTCP && !c.DetectUDP && !c.DetectProtocolScan {
		return fmt.Errorf("portscan: Enabled is true but no detector is: set at least one of DetectTCP, DetectUDP, DetectProtocolScan")
	}
	switch c.Block.Policy {
	case BlockNever, BlockAsk, BlockAuto:
	default:
		return fmt.Errorf("portscan: unknown Block.Policy %q (want never, ask or auto)", c.Block.Policy)
	}
	if c.Block.Policy != BlockNever {
		if c.Block.Duration <= 0 {
			return fmt.Errorf("portscan: Block.Duration must be greater than 0")
		}
		// An upper bound, because this value cuts a host off from an address
		// and because it is reported to the user in a uint32 of seconds: a
		// duration past that wraps, so the interface offers "block for 31
		// minutes" while the daemon installs one lasting a century. Thirty days
		// is far beyond any operational use and well inside the field.
		if c.Block.Duration > maxBlockDuration {
			return fmt.Errorf("portscan: Block.Duration %v exceeds the maximum of %v", c.Block.Duration, maxBlockDuration)
		}
		if c.Block.MaxBlockedSources < 1 {
			return fmt.Errorf("portscan: Block.MaxBlockedSources must be at least 1, got %d", c.Block.MaxBlockedSources)
		}
		if c.Block.MaxBlockedSources > maxBlockedSourcesLimit {
			return fmt.Errorf("portscan: Block.MaxBlockedSources %d exceeds the maximum of %d", c.Block.MaxBlockedSources, maxBlockedSourcesLimit)
		}
	}
	if c.AlertsPerMinute > maxAlertsPerMinute {
		return fmt.Errorf("portscan: AlertsPerMinute %d exceeds the maximum of %d", c.AlertsPerMinute, maxAlertsPerMinute)
	}
	return nil
}

// Upper bounds on the three settings that reach outside this package -- the
// firewall, the notification channel, and the daemon's own memory -- and that
// an operator cannot easily undo by hand.
const (
	// maxBlockDuration also keeps Block.Duration inside the uint32 of seconds
	// the protocol carries.
	maxBlockDuration = 30 * 24 * time.Hour
	// maxBlockedSourcesLimit bounds the firewall set and the manager's table.
	maxBlockedSourcesLimit = 65536
	// maxAlertsPerMinute bounds how many desktop notifications one minute of
	// traffic can produce. The whole point of the limiter is that a decoy scan
	// must not become a hundred prompts.
	maxAlertsPerMinute = 600

	// The duration bounds sit where the arithmetic built on these values would
	// overflow: SlowestDetectableScan multiplies DecayInterval by a probe weight.
	maxDecayInterval = 24 * time.Hour
	maxIdleExpiry    = 30 * 24 * time.Hour
	maxStartupGrace  = 24 * time.Hour
)

// detectionHorizon is how long a scan may take to be reported and still count
// as detected, for the figures this file publishes. Without a horizon the
// answer diverges: any delay below weight*DecayInterval crosses eventually, but
// "eventually" grows without bound as the delay approaches it, and a scanner
// reported hours later has finished and left. One hour covers every nmap timing
// template but -T0.
const detectionHorizon = time.Hour

// SlowestDetectableScan reports the slowest scan the configuration detects
// within detectionHorizon: the longest delay between two probes of the given
// weight that still reaches the threshold in that time. It returns 0 if no
// scan of that weight can, including when one probe decays faster than it
// accumulates. TestSlowestFigureHoldsOnTheEngine checks the figure against the
// engine itself.
func (c *Config) SlowestDetectableScan(perProbeWeight uint32) time.Duration {
	return c.SlowestDetectableScanWithin(perProbeWeight, detectionHorizon)
}

// SlowestDetectableScanWithin is SlowestDetectableScan with the horizon named
// explicitly, for callers that want to state a different one.
func (c *Config) SlowestDetectableScanWithin(perProbeWeight uint32, horizon time.Duration) time.Duration {
	if perProbeWeight == 0 || c.DecayInterval <= 0 || horizon <= 0 || c.ScoreThreshold == 0 {
		return 0
	}
	// Above this the bucket leaks at least as fast as it fills, at any horizon.
	sup := time.Duration(perProbeWeight) * c.DecayInterval
	if sup <= 0 {
		return 0
	}

	// Binary search the largest delay whose time-to-cross fits the horizon.
	// Closed form exists but is brittle around the singularity; a search over a
	// monotone predicate is exact to the nanosecond and obviously correct.
	lo, hi := time.Duration(0), sup
	for lo < hi {
		mid := lo + (hi-lo+1)/2
		if c.timeToCross(perProbeWeight, mid) <= horizon {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	if lo == 0 || c.timeToCross(perProbeWeight, lo) > horizon {
		return 0
	}
	return lo
}

// timeToCross is how long a scan sending one probe of the given weight every
// delay takes to reach ScoreThreshold, or a duration above any horizon when it
// never does.
//
// The score after n probes is n*weight minus the whole points that have leaked
// over the elapsed (n-1)*delay, so crossing needs
//
//	n*weight - (n-1)*delay/DecayInterval >= threshold
//
// which solves for n directly. Computed in float64 because this produces a
// figure for documentation, not a decision on the packet path.
func (c *Config) timeToCross(weight uint32, delay time.Duration) time.Duration {
	const never = time.Duration(1) << 62
	leakPerProbe := float64(delay) / float64(c.DecayInterval)
	gain := float64(weight) - leakPerProbe
	if gain <= 0 {
		return never
	}
	n := (float64(c.ScoreThreshold) - leakPerProbe) / gain
	if n < 1 {
		n = 1
	}
	total := (n - 1) * float64(delay)
	if total >= float64(never) {
		return never
	}
	return time.Duration(total)
}

// ProbeWeight returns the score a single probe of the given classes adds.
// Exposed so that documentation and the coverage report can tabulate the real
// numbers instead of restating them by hand.
func ProbeWeight(port PortClass, mult uint32) uint32 {
	var pw uint32
	switch port {
	case PortSystem:
		pw = weightPortSystem
	case PortRegistered:
		pw = weightPortRegistered
	default:
		pw = weightPortDynamic
	}
	return pw * mult
}

// ICMP message types that reconnaissance uses: the three IPv4 ones are dead
// protocols nothing uses but a scanner (nmap -PP and -PM), and the ICMPv6 one
// asks a host for its names and addresses. Echo request is absent: it is the
// most ordinary packet there is and is not scored, though it counts towards the
// distinct-type total that reveals a sweep.
const (
	icmpv4Echo          uint8 = 8
	icmpv4Timestamp     uint8 = 13
	icmpv4Information   uint8 = 15
	icmpv4AddressMask   uint8 = 17
	icmpv6Echo          uint8 = 128
	icmpv6NodeInfoQuery uint8 = 139
)

// weightICMPRecon is what one of those types scores.
//
// Deliberately below ScoreThreshold: a single stray timestamp request from a
// misconfigured device must not on its own report a scan. Two of them, or one
// alongside any other probing, does.
const weightICMPRecon = 40

// Warnings reports settings that are valid but, in practice, switch detection
// off or remove a protection -- a 24-hour StartupGrace on a desktop rebooted
// daily, a DecayInterval so long the bucket never leaks. They are not refused:
// they are an operator's choice, and the daemon should not decline to start over
// a number. They are said out loud, so "detection is enabled" cannot quietly
// mean "detection sees nothing".
func (c Config) Warnings() []string {
	if !c.Enabled {
		return nil
	}
	var w []string
	if c.StartupGrace > warnStartupGrace {
		w = append(w, fmt.Sprintf("PortScan.StartupGrace is %v: TCP packets carrying ACK are"+
			" not counted for that long after every start, so an ACK or Maimon scan in that"+
			" window goes unseen, and on a machine rebooted more often than that, always.",
			c.StartupGrace))
	}
	if c.DecayInterval > warnDecayInterval {
		w = append(w, fmt.Sprintf("PortScan.DecayInterval is %v: scores barely leak away, so"+
			" ordinary traffic accumulates until it crosses the threshold. Combined with"+
			" Block.Policy \"auto\" this eventually blocks correspondents that are not"+
			" scanning.", c.DecayInterval))
	}
	if c.ScoreThreshold > warnScoreThreshold {
		w = append(w, fmt.Sprintf("PortScan.ScoreThreshold is %d: that is about %d SYNs to"+
			" closed system ports before anything is reported, which is far beyond any real scan.",
			c.ScoreThreshold, c.ScoreThreshold/ProbeWeight(PortSystem, multSynClosed)))
	}
	if c.AlertsPerMinute > warnAlertsPerMinute {
		w = append(w, fmt.Sprintf("PortScan.AlertsPerMinute is %d: the limiter exists so that"+
			" a decoy scan does not become a hundred prompts, and this setting removes"+
			" that protection.", c.AlertsPerMinute))
	}
	if c.Block.Policy == BlockAuto && !c.Block.RequireTCPEvidence {
		w = append(w, "PortScan.Block has Policy \"auto\" with RequireTCPEvidence false:"+
			" a UDP or ICMP source address costs nothing to forge and carries no"+
			" handshake, so this lets a forged address move the firewall without"+
			" anyone being asked.")
	}
	return w
}

// The thresholds above which a setting is worth saying out loud. They are not
// limits: Validate's limits are where the arithmetic stops working, these are
// where the behaviour stops being what the user probably means.
const (
	warnStartupGrace    = 10 * time.Minute
	warnDecayInterval   = 5 * time.Minute
	warnScoreThreshold  = 10000
	warnAlertsPerMinute = 20
)

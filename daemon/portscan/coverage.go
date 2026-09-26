package portscan

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Detectability is what a host-based sensor can honestly claim about a scan
// technique.
//
// These codes are a public contract, like the refusal codes of a converter:
// values are never repurposed, only added. They exist so that "which scans does
// this detect?" has an answer that is checkable rather than a paragraph of
// prose -- and so that the techniques it cannot detect are stated rather than
// omitted.
type Detectability string

// Detectability values.
const (
	// DetectFull means the technique is reliably visible to this sensor.
	DetectFull Detectability = "D_FULL"
	// DetectPartial means it is visible with a documented blind spot.
	DetectPartial Detectability = "D_PARTIAL"
	// DetectIndirect means the scan itself is not visible; only a side effect
	// is.
	DetectIndirect Detectability = "D_INDIRECT"
	// Unreachable means it is structurally invisible from the target host. The
	// reason is always recorded: this is not a to-do list.
	Unreachable Detectability = "U_UNREACHABLE"
	// OutOfScope means it is detectable in principle but deliberately not
	// covered, with the reason recorded.
	OutOfScope Detectability = "U_OUT_OF_SCOPE"
)

// Technique is one entry of the coverage taxonomy.
type Technique struct {
	// Name is how the technique is usually called.
	Name string
	// Option is the nmap flag that produces it, where one exists.
	Option string
	// Scan is whether the scan itself can be seen.
	Scan Detectability
	// Attribution is whether the address in the packets can be believed to be
	// the origin's. It differs from Scan for every indirection technique --
	// decoys, idle scan, FTP bounce, spoofed source -- and that difference is
	// the whole reason blocking is gated by policy.
	Attribution Detectability
	// Corpus is the capture in testdata/pcap exercising it, or "" when the
	// technique cannot be captured here.
	Corpus string
	// Expect is the technique the engine must name, or MethodUnknown where the
	// option legitimately produces several probe families.
	Expect ScanMethod
	// Why records the reason for the status. Required: a status with no reason
	// is an opinion.
	Why string
}

// Techniques is the taxonomy.
//
// It is data rather than prose so that a test can require every entry to have a
// reason, every capture in the corpus to belong to exactly one entry, and the
// generated coverage report to be produced from the same source as the tests
// rather than written by hand alongside them.
var Techniques = []Technique{
	{
		Name: "TCP SYN scan", Option: "-sS",
		Scan: DetectFull, Attribution: DetectFull,
		Corpus: "tcp-syn", Expect: MethodSYN,
		Why: "a bare SYN to a port where nothing listens is the nominal case",
	},
	{
		Name: "TCP connect scan", Option: "-sT",
		Scan: DetectFull, Attribution: DetectFull,
		Corpus: "tcp-connect", Expect: MethodSYN,
		Why: "connect(2) puts the same bare SYN on the wire; the difference is in the scanner, not in the packets",
	},
	{
		Name: "TCP FIN scan", Option: "-sF",
		Scan: DetectFull, Attribution: DetectFull,
		Corpus: "tcp-fin", Expect: MethodFIN,
		Why: "a FIN outside an established connection cannot be legitimate",
	},
	{
		Name: "TCP NULL scan", Option: "-sN",
		Scan: DetectFull, Attribution: DetectFull,
		Corpus: "tcp-null", Expect: MethodNULL,
		Why: "no control bits at all is not something a stack emits",
	},
	{
		Name: "TCP Xmas scan", Option: "-sX",
		Scan: DetectFull, Attribution: DetectFull,
		Corpus: "tcp-xmas", Expect: MethodXmas,
		Why: "FIN, PSH and URG together cannot open or continue a connection",
	},
	{
		Name: "TCP Maimon scan", Option: "-sM",
		Scan: DetectPartial, Attribution: DetectFull,
		Corpus: "tcp-maimon", Expect: MethodMaimon,
		Why: "FIN|ACK carries ACK, the shape of a connection's teardown, so it is treated as an ACK scan is: counted at the lowest weight, not counted in the ephemeral range, and not enough on its own to block",
	},
	{
		Name: "TCP ACK scan", Option: "-sA",
		Scan: DetectPartial, Attribution: DetectFull,
		Corpus: "tcp-ack", Expect: MethodACK,
		Why: "a lone ACK is also what a straggler from a just-closed socket looks like, so it is counted at the lowest weight; the connection table removes most of the ambiguity, which a network sensor cannot do at all",
	},
	{
		Name: "TCP window scan", Option: "-sW",
		Scan: Unreachable, Attribution: DetectFull,
		Corpus: "tcp-window", Expect: MethodACK,
		Why: "byte-identical to -sA on the wire: the two differ only in how the scanner reads the window field of the reply. Reporting anything more specific would be a fabrication, so it is reported as an ACK scan",
	},
	{
		Name: "Custom flag combinations", Option: "--scanflags",
		Scan: DetectFull, Attribution: DetectFull,
		Corpus: "tcp-custom-flags", Expect: MethodCustomFlags,
		Why: "anything that is not a legitimate combination is caught as 'not matched above' rather than by a list of known ones, so a novel combination is still caught",
	},
	{
		Name: "SYN|FIN scan", Option: "--scanflags SYNFIN",
		Scan: DetectFull, Attribution: DetectFull,
		Corpus: "tcp-synfin", Expect: MethodSYNFIN,
		Why: "a classic filter-evasion combination, named explicitly",
	},
	{
		Name: "UDP scan", Option: "-sU",
		Scan: DetectPartial, Attribution: Unreachable,
		Corpus: "udp", Expect: MethodUDP,
		Why: "legitimate multi-port UDP traffic is common (mDNS, SSDP, games, P2P) so the weight is low; and a UDP source address costs nothing to forge, so RequireTCPEvidence refuses to block on UDP-only evidence",
	},
	{
		Name: "IP protocol scan", Option: "-sO",
		Scan: DetectFull, Attribution: DetectFull,
		Corpus: "ip-protocol", Expect: MethodUnknown,
		Why: "counting distinct IP protocol numbers is cheap and unambiguous; the method is legitimately mixed because -sO also emits real TCP and UDP headers",
	},
	{
		Name: "Decoy scan", Option: "-D",
		Scan: DetectFull, Attribution: Unreachable,
		Corpus: "tcp-syn-decoy", Expect: MethodUnknown,
		Why: "the scan is fully visible but the forged sources are indistinguishable from the real one. This is the reason the default block policy asks rather than acts",
	},
	{
		Name: "OS fingerprinting", Option: "-O",
		Scan: DetectFull, Attribution: DetectFull,
		Corpus: "tcp-os-fingerprint", Expect: MethodUnknown,
		Why: "mixes a port scan with fingerprinting probes, so several probe families arrive from one source",
	},
	{
		Name: "Fragmented probes", Option: "-f / --mtu",
		Scan: DetectPartial, Attribution: DetectFull,
		Corpus: "tcp-syn-fragmented", Expect: MethodFragmentedTCP,
		Why: "the first fragment ends after the eighth byte of the TCP header, so the ports are readable and the flags are not. The scan is detected; the technique behind it is reported as indeterminate rather than guessed, because an unread flag octet reads as zero and would otherwise be reported as a NULL scan",
	},
	{
		Name: "Slow scan", Option: "-T0 / -T1",
		Scan: DetectPartial, Attribution: DetectFull,
		Corpus: "tcp-syn-slow", Expect: MethodSYN,
		Why: "a leaky bucket detects a scan whose probes arrive faster than it leaks, but how fast is not the whole answer: as the interval approaches the point where gain equals leak, the time to reach the threshold diverges. Config.SlowestDetectableScan reports the slowest scan the running configuration reports WITHIN AN HOUR, which is the figure worth quoting; slower scans are either invisible or detected long after the scanner has gone",
	},
	{
		Name: "Idle (zombie) scan", Option: "-sI",
		Scan: DetectFull, Attribution: Unreachable,
		Why: "every probe reaches us from the zombie, so the scan is plainly visible; the attacker never sends us a packet, so their address is not in anything we can observe",
	},
	{
		Name: "FTP bounce scan", Option: "-b",
		Scan: DetectFull, Attribution: Unreachable,
		Why: "the connections arrive from the FTP server. Largely obsolete, but the attribution limit is the same as the idle scan's",
	},
	{
		Name: "Spoofed source", Option: "-S",
		Scan: DetectFull, Attribution: Unreachable,
		Why: "the source address is chosen by the sender; nothing in the packets contradicts it",
	},
	{
		Name: "SCTP INIT / COOKIE ECHO scan", Option: "-sY / -sZ",
		Scan: OutOfScope, Attribution: DetectFull,
		Why: "IP protocol 132 is counted towards the protocol-scan total, but SCTP chunk parsing is not implemented: it would add a third transport parser to the kernel program for a technique that is vanishingly rare on desktops",
	},
	{
		Name: "Horizontal scan of the network", Option: "",
		Scan: Unreachable, Attribution: Unreachable,
		Why: "a sweep of one port across many hosts is, from any single host, one packet. There is nothing to count. This is a property of the vantage point, not a gap in the implementation",
	},
	{
		Name: "Single-port brute force", Option: "",
		Scan: OutOfScope, Attribution: DetectFull,
		Corpus: "benign-single-port", Expect: MethodUnknown,
		Why: "repeated attempts on one port are a credential attack or an application failing to reach a stopped service, not reconnaissance. Counting them is the mistake PortSentry and flowhawk make",
	},
	{
		Name: "IPv6 port scan", Option: "-6",
		Scan: DetectFull, Attribution: DetectFull,
		Corpus: "tcp-syn-v6", Expect: MethodSYN,
		Why: "identical to the IPv4 techniques once the target address is known; address-space size protects the network, not the host",
	},
	{
		Name: "IPv6 FIN scan", Option: "-6 -sF",
		Scan: DetectFull, Attribution: DetectFull,
		Corpus: "tcp-fin-v6", Expect: MethodFIN,
		Why: "the flag analysis is address-family independent",
	},
	{
		Name: "IPv6 Xmas scan", Option: "-6 -sX",
		Scan: DetectFull, Attribution: DetectFull,
		Corpus: "tcp-xmas-v6", Expect: MethodXmas,
		Why: "the flag analysis is address-family independent",
	},
	{
		Name: "IPv6 UDP scan", Option: "-6 -sU",
		Scan: DetectPartial, Attribution: Unreachable,
		Corpus: "udp-v6", Expect: MethodUDP,
		Why: "same weighting and same refusal to block on UDP-only evidence as IPv4",
	},
	{
		Name: "Extension-header evasion", Option: "Topera",
		Scan: DetectFull, Attribution: DetectFull,
		Why: "hiding the TCP header behind more IPv6 extension headers than the parser walks (eight, and 1024 bytes) is itself the signature: the host answers such a probe, ordinary traffic never sends one, so each packet that exhausts the walk scores like a SYN to a system port and the scan is reported as ipv6-extension-evasion. The ports themselves are not readable, and the probes are not evidence for blocking",
	},
	{
		Name: "Out-of-band enumeration", Option: "DNS / rDNS / certificate logs",
		Scan: Unreachable, Attribution: Unreachable,
		Why: "no packet reaches the host at all. Detecting it is not a network-sensor problem",
	},
}

// CoverageResult is what a replay of one corpus capture produced.
type CoverageResult struct {
	Packets  int
	Probes   int
	Detected bool
	Method   ScanMethod
	Detail   string
	Ports    uint32
	MinPort  uint16
	MaxPort  uint16
	Score    uint32
	Flags    string
	Protocol bool
}

// RenderCoverage writes the coverage report as Markdown.
//
// results maps a corpus name to what replaying it produced; entries with no
// corpus, or with no result, are still listed -- a technique that cannot be
// exercised here is exactly the kind of thing a coverage report must not omit.
func RenderCoverage(w io.Writer, cfg Config, results map[string]CoverageResult) error {
	var b strings.Builder

	b.WriteString("# Port scan detection: coverage\n\n")
	b.WriteString("Back to [Port Scan Detection](Port-Scan-Detection).\n\n")
	b.WriteString("Generated by `daemon/portscan/testdata/coverage`. Do not edit by hand:\n")
	b.WriteString("the table below is produced by replaying the capture corpus through the\n")
	b.WriteString("detection engine, so it says what the code does rather than what it is\n")
	b.WriteString("meant to do.\n\n")

	b.WriteString("## Status codes\n\n")
	b.WriteString("| Code | Meaning |\n|---|---|\n")
	for _, s := range []struct{ code, meaning string }{
		{string(DetectFull), "Reliably visible to this sensor."},
		{string(DetectPartial), "Visible, with a documented blind spot."},
		{string(DetectIndirect), "The scan itself is not visible; only a side effect is."},
		{string(Unreachable), "**Structurally invisible** from the target host. The reason is stated."},
		{string(OutOfScope), "Detectable in principle, deliberately not covered. The reason is stated."},
	} {
		fmt.Fprintf(&b, "| `%s` | %s |\n", s.code, s.meaning)
	}

	b.WriteString("\n`Scan` is whether the activity can be seen. `Attribution` is whether the\n")
	b.WriteString("address in the packets can be believed to be its origin's. The two differ\n")
	b.WriteString("for every indirection technique, and that difference is why blocking is\n")
	b.WriteString("gated by policy rather than automatic.\n\n")

	b.WriteString("## Techniques\n\n")
	b.WriteString("| Technique | Option | Scan | Attribution | Exercised by | Observed |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, t := range Techniques {
		observed := "not exercised here"
		corpus := "-"
		if t.Corpus != "" {
			corpus = "`" + t.Corpus + ".pcap`"
			if r, ok := results[t.Corpus]; ok {
				switch {
				case r.Detected && r.Protocol:
					observed = fmt.Sprintf("protocol scan, %d probes", r.Probes)
				case r.Detected:
					observed = fmt.Sprintf("`%s`, %d ports, score %d", r.Method, r.Ports, r.Score)
				default:
					observed = fmt.Sprintf("not reported (%d probes)", r.Probes)
				}
			}
		}
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | `%s` | %s | %s |\n",
			escapePipes(t.Name), escapePipes(orDash(t.Option)),
			t.Scan, t.Attribution, corpus, observed)
	}

	b.WriteString("\n## Why, in each case\n\n")
	for _, t := range Techniques {
		fmt.Fprintf(&b, "**%s**", t.Name)
		if t.Option != "" {
			fmt.Fprintf(&b, " (`%s`)", t.Option)
		}
		fmt.Fprintf(&b, ": scan `%s`, attribution `%s`.\n%s.\n\n", t.Scan, t.Attribution, t.Why)
	}

	b.WriteString("## What the running configuration implies\n\n")
	b.WriteString("These are derived from the configuration, not asserted: the slowest scan a\n")
	b.WriteString("leaky bucket can detect is a function of its threshold, its decay rate and\n")
	b.WriteString("the weight of one probe. As a scan slows towards the rate at which the\n")
	b.WriteString("bucket leaks, the time it takes to be reported grows without bound, so each\n")
	fmt.Fprintf(&b, "figure below is the slowest scan reported within %s of its first probe.\n\n", horizonWords(detectionHorizon))
	fmt.Fprintf(&b, "Score threshold %d, decay one point per %v.\n\n", cfg.ScoreThreshold, cfg.DecayInterval)
	b.WriteString("| Probe | Weight | Slowest detectable interval |\n|---|---|---|\n")
	for _, row := range []struct {
		name string
		port PortClass
		mult uint32
	}{
		{"SYN to a closed system port (< 1024)", PortSystem, multSynClosed},
		{"SYN to a closed registered port", PortRegistered, multSynClosed},
		{"SYN to a closed dynamic port", PortDynamic, multSynClosed},
		{"anomalous flags, system port", PortSystem, multAnomalousFlags},
		{"UDP to a closed dynamic port", PortDynamic, multUDP},
	} {
		weight := ProbeWeight(row.port, row.mult)
		slowest := cfg.SlowestDetectableScan(weight)
		limit := "not within " + horizonWords(detectionHorizon)
		if slowest > 0 {
			// Rounded down, and checked against the engine every 10 ms over the
			// last tenth below it (TestSlowestFigureHoldsOnTheEngine).
			limit = slowest.Truncate(time.Second).String()
		}
		fmt.Fprintf(&b, "| %s | %d | %s |\n", row.name, weight, limit)
	}

	fmt.Fprintf(&b, "\nFor reference, `nmap -T1` waits 15s between probes and `nmap -T0` waits\n")
	fmt.Fprintf(&b, "5 minutes. A scan slower than the figures above is reported late or not at\n")
	fmt.Fprintf(&b, "all. A lower threshold or a slower decay moves the figures, at the price of\n")
	fmt.Fprintf(&b, "reporting ordinary traffic; no setting makes a leaky bucket see a scan that\n")
	fmt.Fprintf(&b, "is slower than its leak.\n")

	_, err := io.WriteString(w, b.String())
	return err
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// escapePipes keeps a technique named "SYN|FIN scan" from splitting the
// Markdown table cell it is written into.
func escapePipes(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// CorpusNames returns every capture the taxonomy refers to, sorted.
func CorpusNames() []string {
	out := make([]string, 0, len(Techniques))
	for _, t := range Techniques {
		if t.Corpus != "" {
			out = append(out, t.Corpus)
		}
	}
	sort.Strings(out)
	return out
}

// horizonWords names the detection horizon the way the report's prose reads.
func horizonWords(d time.Duration) string {
	if d == time.Hour {
		return "an hour"
	}
	return d.String()
}

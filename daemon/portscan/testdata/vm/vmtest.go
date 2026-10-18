//go:build linux

// vmtest is the end-to-end verification of the parts of port scan detection
// that cannot be exercised anywhere else. It runs as PID 1 inside a throwaway
// QEMU virtual machine, where it is root and can therefore do the two things
// the development environment forbids: load an eBPF program, and let the daemon
// install real firewall rules in the initial network namespace.
//
// Three phases, each establishing something no unit test can:
//
//  1. the kernel half. The verifier accepts the program, TCX attaches it, real
//     captured nmap traffic through it produces ring buffer events, and those
//     events -- fed to the same engine the AF_PACKET path uses -- produce the
//     same verdict. This is why the eBPF program does no scoring: both sources
//     hand the engine identical probes, so checking the kernel half does not
//     require re-verifying the detection logic in a second implementation.
//
//  2. the cost. The kernel's own accounting says how long the program spends
//     per packet. The feature was asked for on the condition that it be cheap,
//     which is a claim about a number, so the number is measured here rather
//     than asserted in a comment.
//
//  3. the production chain. portscan.Setup() -- the entry point the daemon
//     actually calls -- with the eBPF source and nftables enforcement, from a
//     replayed scan through to a firewall rule in the kernel and back to
//     nothing at shutdown. This phase is what catches wiring defects that every
//     hand-assembled test misses by construction, because a hand-assembled test
//     supplies the wiring itself.
//
// Output is a series of lines on the serial console, ending with either
// VMTEST-RESULT: PASS or VMTEST-RESULT: FAIL. The harness that boots the VM
// greps for those.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/portscan"
	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// The capture corpus is generated against these addresses
	// (testdata/generate_corpus.sh). The guest must own the victim address,
	// or the replayed frames are addressed to nobody and the eBPF program
	// correctly filters every one of them.
	//
	// The scanner address is deliberately NOT assigned to any interface here:
	// the host view treats its own addresses as never blockable, so a scanner
	// that is also one of our addresses could never reach the enforcement path.
	corpusVictimAddr  = "10.77.0.1"
	corpusVictimCIDR  = "10.77.0.1/24"
	corpusScannerAddr = "10.77.0.2"

	// The IPv6 half of the same corpus (generate_corpus.sh sets VICTIM6 and
	// ATTACK6 to these).
	//
	// It was missing here, and its absence was silent: frameTargets only
	// recognised EtherType 0x0800, so every IPv6 capture replayed ZERO frames
	// and the run still reported the kernel counters it got from the four ARP
	// frames that did pass. The feature claims IPv6 support and the one test
	// that proves the kernel program works on a real kernel never exercised it.
	corpusVictimAddr6  = "fd00:77::1"
	corpusVictimCIDR6  = "fd00:77::1/64"
	corpusScannerAddr6 = "fd00:77::2"

	victimIf   = "psvm0"
	attackerIf = "psvm1"

	// costReplayRounds is how many times phase 2 replays the capture, and
	// minCostSamples the smallest number of program runs it will divide by.
	costReplayRounds = 60
	minCostSamples   = 2000
)

var (
	victim4  = netip.MustParseAddr(corpusVictimAddr)
	scanner4 = netip.MustParseAddr(corpusScannerAddr)
	victim6  = netip.MustParseAddr(corpusVictimAddr6)
	scanner6 = netip.MustParseAddr(corpusScannerAddr6)
	// victims is what a replayed frame must be addressed to, and what the
	// engine and the kernel program are told this host owns.
	victims = []netip.Addr{victim4, victim6}
	// pcapName is the capture being replayed, without directory or extension.
	pcapName = ""
	failed   = false
)

func step(format string, a ...interface{}) {
	fmt.Printf("VMTEST-STEP: "+format+"\n", a...)
}

func measure(format string, a ...interface{}) {
	fmt.Printf("VMTEST-MEASURE: "+format+"\n", a...)
}

func fail(format string, a ...interface{}) {
	failed = true
	fmt.Printf("VMTEST-FAIL: "+format+"\n", a...)
}

func main() {
	// Registered first so it runs LAST: defers are LIFO, and powering the
	// machine off before the verdict is printed loses the result entirely.
	defer powerOff()

	defer func() {
		if r := recover(); r != nil {
			fail("panic: %v", r)
		}
		if failed {
			fmt.Println("VMTEST-RESULT: FAIL")
		} else {
			fmt.Println("VMTEST-RESULT: PASS")
		}
		// Flush before the harness kills the machine.
		os.Stdout.Sync()
		time.Sleep(200 * time.Millisecond)
	}()

	mountPseudoFilesystems()

	if os.Geteuid() != 0 {
		fail("not running as root; the whole point of the VM is to be root")
		return
	}

	modulePath := envOr("PORTSCAN_MODULE_DIR", "/payload")
	pcapPath := envOr("PORTSCAN_PCAP", "/payload/tcp-syn.pcap")
	pcapName = strings.TrimSuffix(filepath.Base(pcapPath), ".pcap")

	// Load the kernel modules here rather than from the init script: the
	// busybox in this Nix store is an initrd-minimal build whose applet set
	// does not include insmod, and a shell loop that silently does nothing
	// looks exactly like a module that failed to load.
	//
	// The order is the dependency order: nf_tables needs nfnetlink, and
	// init_module(2) does no dependency resolution of its own.
	if err := loadKernelModules("/lib/modules",
		"veth", "tun", "af_packet", "nfnetlink", "nf_tables"); err != nil {
		fail("loading kernel modules: %v", err)
		return
	}

	if err := setupVeth(); err != nil {
		fail("setting up the veth pair: %v", err)
		return
	}
	step("veth pair %s <-> %s is up", victimIf, attackerIf)

	frames, err := readPcapFrames(pcapPath)
	if err != nil {
		fail("reading %s: %v", pcapPath, err)
		return
	}

	if !phaseDetection(modulePath, frames) {
		// Without a working kernel half the later phases would only report the
		// same failure again, less clearly.
		return
	}
	phaseGrace(modulePath, frames)
	phaseCost(modulePath, frames)
	phaseBudgetCapacity(modulePath)
	phaseProduction(modulePath, frames)
	phaseGoTests(modulePath)
}

// ---------------------------------------------------------------------------
// the per-source budget map's real capacity
// ---------------------------------------------------------------------------

// phaseBudgetCapacity checks that source_budgets really holds as many distinct
// sources as it declares.
//
// A map flag can quietly break that. With BPF_F_NO_COMMON_LRU, which would
// remove the contention of a shared LRU lock on the packet path, the kernel
// rounds max_entries up to a multiple of num_possible_cpus() and splits the
// preallocated elements into per-CPU lists (htab_map_alloc, then
// bpf_percpu_lru_populate with pcpu_entries = nr_elems / num_possible_cpus() + 1),
// so a map declared for 8192 sources keeps 512 per CPU on a sixteen-core
// machine. Measured here with that flag: declared 8192, 4096 retained on a
// two-CPU guest. Since a source's packets hash to one receive queue, evicting
// one's own budget entry -- which restarts it at sent = 1 and so lifts the
// per-source ceiling -- would cost a few hundred forged sources rather than a
// few thousand.
//
// It is a number the design depends on, derived from the kernel source and
// observed here rather than assumed.
func phaseBudgetCapacity(modulePath string) {
	step("phase 2b: what the per-source budget map really holds")

	coll, err := core.LoadEbpfModule(portscan.ScanModuleName, modulePath)
	if err != nil {
		fail("loading the module to inspect its maps: %v", err)
		return
	}
	defer coll.Close()

	m, ok := coll.Maps["source_budgets"]
	if !ok {
		fail("the module has no source_budgets map")
		return
	}
	declared := m.MaxEntries()

	// Fill with distinct keys and count how many are still there. Anything
	// beyond the real capacity has evicted something.
	type budget struct {
		WindowStartNs uint64
		Sent          uint32
		Dropped       uint32
	}
	const probe = 16384
	var key [16]byte
	key[10], key[11] = 0xff, 0xff // the v4-mapped form the program uses
	for i := 0; i < probe; i++ {
		binary.BigEndian.PutUint32(key[12:], uint32(0x0a000000|i))
		if err := m.Put(key, budget{WindowStartNs: 1, Sent: 1}); err != nil {
			fail("filling source_budgets at %d: %v", i, err)
			return
		}
	}
	held := 0
	for i := 0; i < probe; i++ {
		binary.BigEndian.PutUint32(key[12:], uint32(0x0a000000|i))
		var got budget
		if err := m.Lookup(key, &got); err == nil {
			held++
		}
	}

	step("source_budgets: max_entries=%d declared, %d of %d distinct sources retained on %d CPUs",
		declared, held, probe, runtime.NumCPU())
	if held == 0 {
		fail("source_budgets retained nothing at all")
		return
	}
	// A shared LRU keeps essentially all of what it declares; the kernel's own
	// local free lists mean the last few may already have been recycled, so the
	// bar is "most of it" rather than "exactly it". A per-CPU split lands at
	// declared/ncpu, which on any multiprocessor guest is far below this.
	if uint32(held) < declared*9/10 {
		fail("source_budgets holds %d of its declared %d entries on %d CPUs:"+
			" the map is being split per CPU, so evicting one's own budget entry"+
			" costs about %d forged sources instead of %d",
			held, declared, runtime.NumCPU(), held, declared)
	}
}

// ---------------------------------------------------------------------------
// phase 4: the package's own privileged tests
// ---------------------------------------------------------------------------

// phaseGoTests runs the compiled test binary of the portscan package, limited
// to the tests that need CAP_BPF.
//
// Those tests exist for CI, and a test written for an environment nobody has
// run it in is a test that has never run. The harness builds the binary outside
// and ships it in, because the guest has no Go toolchain.
func phaseGoTests(modulePath string) {
	const bin = "/bin/portscan.test"
	if _, err := os.Stat(bin); err != nil {
		step("phase 4: %s is not in the payload; skipping the package's privileged tests", bin)
		return
	}
	step("phase 4: the package's own tests that need CAP_BPF")

	// The coverage profile is written to a file and then printed, because the
	// guest has no writable storage the harness can read afterwards. Without
	// it, source_ebpf.go would be the one file whose coverage is unknown --
	// and it is precisely the file that only runs here.
	const profile = "/tmp/cover.out"
	_ = os.MkdirAll("/tmp", 0o755)

	cmd := exec.Command(bin, "-test.v", "-test.run", "TestLiveEbpf",
		"-test.coverprofile="+profile)
	cmd.Env = append(os.Environ(),
		"PORTSCAN_REQUIRE_EBPF=1",
		// The guest is thrown away after the run, so the tests may change its
		// interfaces; see netns_guard_test.go.
		"PORTSCAN_DISPOSABLE_HOST=1",
		"PORTSCAN_MODULE_DIR="+modulePath,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	if err := cmd.Run(); err != nil {
		fail("the package's privileged tests failed: %v", err)
		return
	}
	step("the package's privileged tests passed")

	if raw, err := os.ReadFile(profile); err == nil {
		fmt.Println("VMTEST-COVER-BEGIN")
		os.Stdout.Write(raw)
		fmt.Println("VMTEST-COVER-END")
	}
}

// ---------------------------------------------------------------------------
// phase 1: the kernel half
// ---------------------------------------------------------------------------

func phaseDetection(modulePath string, frames [][]byte) bool {
	step("phase 1: verifier, TCX attachment and detection (capture %q)", pcapName)

	var (
		mu     sync.Mutex
		probes int
		events []*portscan.ScanEvent
	)

	cfg := portscan.DefaultConfig()
	// The shipped default is off: enabling detection is a decision an operator
	// makes in their configuration file, not something a package upgrade does.
	cfg.Enabled = true
	cfg.StartupGrace = 0
	cfg.AlertsPerMinute = 600
	cfg.ReportCooldown = 0

	host := &vmHost{local: map[netip.Addr]bool{victim4: true, victim6: true}}
	engine, err := portscan.NewEngine(cfg, host, 0)
	if err != nil {
		fail("building the engine: %v", err)
		return false
	}

	src, err := portscan.NewEbpfSource(portscan.EbpfOptions{
		ModulesPath:        modulePath,
		Interfaces:         []string{victimIf},
		StartupGrace:       0,
		ExcludedPorts:      cfg.ExcludedPorts,
		MaxProbesPerSecond: 100000,
		LocalAddrs:         victims,
	},
		func(p *portscan.Probe) {
			mu.Lock()
			probes++
			mu.Unlock()
			if ev := engine.Process(p); ev != nil {
				mu.Lock()
				events = append(events, ev)
				mu.Unlock()
			}
		},
		func(e error) { fmt.Printf("VMTEST-SOURCE-ERR: %v\n", e) },
	)
	if err != nil {
		// This is the headline result when it fails: either the verifier
		// rejected the program, or TCX attachment did not work.
		fail("loading or attaching the eBPF module: %v", err)
		return false
	}
	defer src.Close()
	step("eBPF module loaded, verifier accepted it, attached to %s via TCX", victimIf)

	go src.Run()
	time.Sleep(300 * time.Millisecond)

	inbound := 0
	sent, err := replay(attackerIf, frames, victims, &inbound, 200*time.Microsecond)
	if err != nil {
		fail("replaying the capture: %v", err)
		return false
	}
	step("replayed %d of %d captured frames (%d were inbound to the victim)", sent, len(frames), inbound)

	// Give the ring buffer reader time to drain.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(events)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	mu.Lock()
	gotProbes, gotEvents := probes, append([]*portscan.ScanEvent(nil), events...)
	mu.Unlock()

	if stats, serr := src.Stats(); serr == nil {
		step("kernel counters: seen=%d forwarded=%d filtered=%d rate_limited=%d source_rate_limited=%d ringbuf_full=%d",
			stats["seen"], stats["forwarded"], stats["filtered"],
			stats["rate_limited"], stats["source_rate_limited"], stats["ringbuf_full"])
		if stats["ringbuf_full"] > 0 {
			fail("the ring buffer overflowed (%d records lost); detection was degraded", stats["ringbuf_full"])
		}
	}

	step("userspace received %d probes and %d scan events", gotProbes, len(gotEvents))

	if gotProbes == 0 {
		fail("the eBPF program forwarded no probe at all: it loaded but is not seeing traffic")
		return false
	}
	// The corpus carries one capture that must NOT be detected. A phase that
	// demanded at least one event would fail that negative control by
	// definition, so it would never be replayed through the kernel path. A
	// false positive on ordinary traffic is the worst thing this feature can
	// produce, which makes it the capture most worth running.
	if isBenignCapture() {
		if len(gotEvents) != 0 {
			fail("the benign capture produced %d detection(s) -- a false positive on"+
				" ordinary traffic: first was %s from %s",
				len(gotEvents), gotEvents[0].Method, gotEvents[0].Src)
			return false
		}
		step("the benign capture produced no detection, which is what it exists to check")
		return !failed
	}

	if len(gotEvents) == 0 {
		fail("real nmap SYN traffic through the eBPF path produced no detection")
		return false
	}

	ev := gotEvents[0]
	step("detected: %s from %s, %d ports [%d..%d], score=%d, flags=%s",
		ev.Method, ev.Src, ev.DistinctPorts, ev.MinPort, ev.MaxPort, ev.Score, ev.FlagsSummary)

	// Provenance is asserted for every capture: the detection must name a
	// scanner the corpus actually contains, and the link-layer address must be
	// there, since exposing the Ethernet header is the one thing TC ingress
	// gives this path over a socket filter.
	if ev.Src != scanner4 && ev.Src != scanner6 && !isDecoySource(ev.Src) {
		fail("detected source is %s, which is neither corpus scanner", ev.Src)
	}
	if !ev.HasMAC {
		fail("no source MAC: TC ingress should expose the Ethernet header")
	}
	if ev.SrcMAC == ([6]byte{}) {
		fail("source MAC is all zeroes")
	}

	// The taxonomy itself -- which capture means which technique -- is pinned
	// for the whole corpus by TestDifferentialCorpus, against the real kernel
	// parser, and re-asserting it per capture here would be that same table
	// written twice. What is asserted here instead is the headline case, for the
	// capture this phase was written around and the one CI replays by default.
	if pcapName == "tcp-syn" {
		if ev.Method != portscan.MethodSYN {
			fail("method = %v, want tcp-syn for a capture of nmap -sS", ev.Method)
		}
		if ev.DistinctPorts < 5 {
			fail("distinct ports = %d, want several", ev.DistinctPorts)
		}
		if !ev.HasTCPEvidence {
			fail("HasTCPEvidence is false for a TCP SYN scan")
		}
	}
	return !failed
}

// isBenignCapture reports whether the capture being replayed is the corpus's
// negative control: ordinary traffic that must produce no detection at all.
func isBenignCapture() bool { return strings.HasPrefix(pcapName, "benign-") }

// isDecoySource reports whether addr is one of the forged sources the decoy
// capture carries. nmap -D puts the real scanner among them, and which of them
// crosses the threshold first is a property of the capture, not of this test.
func isDecoySource(addr netip.Addr) bool {
	if !addr.Is4() || addr == victim4 {
		// Never the victim: reporting this host's own address as the scanner is
		// a defect, not a decoy, and it must not pass through this door.
		return false
	}
	a := addr.As4()
	return a[0] == 10 && a[1] == 77 && a[2] == 0
}

// ---------------------------------------------------------------------------
// phase 2: what the kernel half costs
// ---------------------------------------------------------------------------

// phaseCost measures the eBPF program with the kernel's own accounting.
//
// This is the honest way to answer "what does this cost per packet": the
// numbers come from the kernel's per-run timing of the program itself, not from
// a timer wrapped around a system call, which would mostly measure the system
// call.
func phaseCost(modulePath string, frames [][]byte) {
	step("phase 2: what the kernel half costs per packet")
	step("(measured under nested virtualisation, so these are upper bounds)")

	closer, err := portscan.EnableKernelProgramStats()
	if err != nil {
		step("kernel BPF run-time statistics are unavailable (%v); skipping the measurement", err)
		return
	}
	defer closer.Close()

	// A per-packet cost needs enough packets to divide by.
	//
	// measureOnce replays the capture costReplayRounds times, so a capture with
	// a handful of replayable frames yields a sample of a few dozen program
	// runs -- and at that size the first runs, with cold caches and a freshly
	// loaded program, are most of the total. The benign control has ONE
	// replayable frame: it measured 67 to 90 microseconds per packet against a
	// ceiling of 20, which says nothing about the program and everything about
	// dividing by sixty. Reporting no number is the honest outcome there; the
	// scan captures, which are what the cost claim is about, all carry
	// hundreds.
	replayable := 0
	for _, f := range frames {
		if len(f) >= 34 && frameTargets(f, victims) {
			replayable++
		}
	}
	if replayable*costReplayRounds < minCostSamples {
		step("only %d replayable frame(s) in this capture, so %d program runs: too few to"+
			" measure a per-packet cost, skipping", replayable, replayable*costReplayRounds)
		return
	}

	// Three configurations, because they are three different costs and only
	// reporting the most expensive one would be as misleading as only
	// reporting the cheapest.
	for _, c := range []struct {
		name        string
		perSecond   uint32
		totalPerSec uint32
		localAddrs  []netip.Addr
		what        string
	}{
		{
			name: "forwarded", perSecond: 100000, localAddrs: victims,
			what: "every probe reaches the ring buffer: the worst case, and what the first second of a scan costs",
		},
		{
			name: "rate-limited", perSecond: 256, localAddrs: victims,
			what: "the shipped per-source budget: what a sustained scan costs once the budget is spent",
		},
		{
			name: "global-bounded", perSecond: 100000, totalPerSec: 64,
			localAddrs: victims,
			what:       "the aggregate budget, the only thing that bounds a flood of forged sources",
		},
		{
			name: "filtered", perSecond: 100000, localAddrs: nil,
			what: "traffic not aimed at one of our addresses: what ordinary traffic on a busy host costs",
		},
	} {
		perRun, stats, err := measureOnce(modulePath, frames, c.perSecond, c.totalPerSec, c.localAddrs)
		if err != nil {
			fail("measuring the %s path: %v", c.name, err)
			continue
		}
		measure("%-13s %8v per packet  (%s)", c.name+":", perRun, c.what)
		measure("%-13s seen=%d forwarded=%d filtered=%d rate_limited=%d source_rate_limited=%d ringbuf_full=%d",
			"", stats["seen"], stats["forwarded"], stats["filtered"],
			stats["rate_limited"], stats["source_rate_limited"], stats["ringbuf_full"])
		if perRun > 0 {
			measure("%-13s about %.0f packets/s per core spent inside the program",
				"", float64(time.Second)/float64(perRun))
		}

		// The budgets are asserted, not only printed: they are the only bound on
		// a flood of forged sources, and nothing else in any suite ran them.
		// Replayed back to back, the capture exceeds either budget several times
		// over within its first second, so some of it must be refused.
		// Each budget has its own counter, and only the aggregate one is
		// reported as degraded detection: the per-source budget must not
		// count there.
		if budget := c.totalPerSec; c.name == "rate-limited" || c.name == "global-bounded" {
			counter, other := "rate_limited", "source_rate_limited"
			if budget == 0 {
				budget = c.perSecond
				counter, other = other, counter
			}
			offered := stats["forwarded"] + stats["rate_limited"] + stats["source_rate_limited"]
			if offered > 4*uint64(budget) && stats[counter] == 0 {
				fail("the %s budget of %d/s refused nothing out of %d probes: it is not applied",
					c.name, budget, offered)
			}
			if c.name == "rate-limited" && stats[other] != 0 {
				fail("the per-source budget's refusals were counted as the aggregate's (%s=%d)",
					other, stats[other])
			}
		}

		// A generous ceiling. The measurement is the useful part; this only
		// catches a change that turns a bounded parse into something
		// pathological.
		if perRun > 20*time.Microsecond {
			fail("the %s path spends %v per packet, which is not a small overhead", c.name, perRun)
		}
	}
}

// measureOnce loads a fresh copy of the program, replays the capture at full
// speed and returns the kernel's own per-run timing.
func measureOnce(modulePath string, frames [][]byte, perSecond, totalPerSec uint32, local []netip.Addr) (time.Duration, map[string]uint64, error) {
	src, err := portscan.NewEbpfSource(portscan.EbpfOptions{
		ModulesPath:        modulePath,
		Interfaces:         []string{victimIf},
		StartupGrace:       0,
		ExcludedPorts:      portscan.DefaultConfig().ExcludedPorts,
		MaxProbesPerSecond: perSecond,
		MaxTotalPerSecond:  totalPerSec,
		LocalAddrs:         local,
	},
		func(*portscan.Probe) {},
		func(e error) { fmt.Printf("VMTEST-SOURCE-ERR: %v\n", e) },
	)
	if err != nil {
		return 0, nil, fmt.Errorf("loading the module: %w", err)
	}
	defer src.Close()
	go src.Run()
	time.Sleep(200 * time.Millisecond)

	// Replay the capture repeatedly and back to back: the point is the cost of
	// one program run, so the sample needs to be large and the inter-frame
	// pause needs to be gone.
	const rounds = costReplayRounds
	inbound, sent := 0, 0
	for i := 0; i < rounds; i++ {
		n, err := replay(attackerIf, frames, victims, &inbound, 0)
		if err != nil {
			return 0, nil, fmt.Errorf("replaying: %w", err)
		}
		sent += n
	}
	time.Sleep(500 * time.Millisecond)

	runs, total, err := src.ProgramRuntime()
	if err != nil {
		return 0, nil, fmt.Errorf("reading the run-time statistics: %w", err)
	}
	if runs == 0 {
		return 0, nil, fmt.Errorf("the kernel recorded no program run at all after %d frames", sent)
	}
	stats, _ := src.Stats()
	return total / time.Duration(runs), stats, nil
}

// ---------------------------------------------------------------------------
// phase 3: the chain the daemon actually runs
// ---------------------------------------------------------------------------

// phaseProduction drives portscan.Setup, the entry point opensnitchd calls, and
// follows a replayed scan all the way to an nftables rule and back.
//
// It exists because every other test supplies the wiring itself. This one lets
// the production code do the wiring, so it catches what only the wiring can
// get wrong: a Setup that did not seed the kernel's local-address map, for
// instance, would make the eBPF path discard every packet while reporting
// itself as running.
func phaseProduction(modulePath string, frames [][]byte) {
	step("phase 3: portscan.Setup with the eBPF source and real nftables enforcement")

	var (
		mu      sync.Mutex
		reports []portscan.Report
	)

	cfg := portscan.DefaultConfig()
	// The shipped default is off: enabling detection is a decision an operator
	// makes in their configuration file, not something a package upgrade does.
	cfg.Enabled = true
	cfg.StartupGrace = 0
	cfg.AlertsPerMinute = 600
	cfg.ReportCooldown = 0
	cfg.Interfaces = []string{victimIf}
	cfg.Block.Policy = portscan.BlockAuto
	cfg.Block.Duration = time.Hour

	m, chosen, err := portscan.Setup(portscan.SetupOptions{
		Config:      cfg,
		Source:      portscan.SourceEbpf, // explicit: no silent fallback here
		ModulesPath: modulePath,
		Report: func(r portscan.Report) {
			mu.Lock()
			reports = append(reports, r)
			mu.Unlock()
		},
		OnError:        func(e error) { fmt.Printf("VMTEST-SETUP-ERR: %v\n", e) },
		EnableBlocking: true,
	})
	if err != nil {
		fail("portscan.Setup: %v", err)
		return
	}
	step("Setup chose the %q packet source", chosen)
	if chosen != portscan.SourceEbpf {
		fail("Setup chose %q although eBPF was requested explicitly", chosen)
	}
	if got := m.Config().Block.Policy; got != portscan.BlockAuto {
		fail("the effective block policy is %q, want %q: enforcement was silently downgraded",
			got, portscan.BlockAuto)
	}

	m.Start()

	inbound := 0
	if _, err := replay(attackerIf, frames, victims, &inbound, 200*time.Microsecond); err != nil {
		fail("replaying the capture: %v", err)
		m.Stop()
		return
	}

	deadline := time.Now().Add(5 * time.Second)
	var applied *portscan.Report
	for time.Now().Before(deadline) && applied == nil {
		mu.Lock()
		for i := range reports {
			if reports[i].Outcome == portscan.OutcomeApplied {
				applied = &reports[i]
				break
			}
		}
		mu.Unlock()
		if applied == nil {
			time.Sleep(100 * time.Millisecond)
		}
	}

	mu.Lock()
	total := len(reports)
	var outcomes []portscan.BlockOutcome
	for _, r := range reports {
		outcomes = append(outcomes, r.Outcome)
	}
	mu.Unlock()

	// What must hold depends on what the capture contains, not on which capture
	// was chosen.
	//
	// Asserting "exactly one entry, for 10.77.0.2" would hold for tcp-syn.pcap
	// and for nothing else: the decoy capture blocks three sources because it
	// HAS three, and the UDP and protocol-scan captures block none because
	// RequireTCPEvidence defaults to true and neither carries any. Every
	// capture but one would then fail the phase, so in practice the production
	// chain would only ever be proved for a single file out of twenty-one.
	//
	// Blocking on evidence that costs nothing to forge is refused by default, so
	// "no block" is the CORRECT outcome for those captures and is asserted as
	// such rather than skipped.
	if applied == nil {
		if isBenignCapture() {
			if total != 0 {
				fail("the benign capture produced %d report(s) %v through the production"+
					" chain", total, outcomes)
			}
			if blocked := m.Blocked(); len(blocked) != 0 {
				fail("the benign capture got %v blocked", blocked)
			}
			step("the benign capture reported nothing and blocked nothing")
			m.Stop()
			return
		}
		if total == 0 {
			fail("the production chain produced no report at all")
			m.Stop()
			return
		}
		if blocked := m.Blocked(); len(blocked) != 0 {
			fail("no block was applied, yet Blocked() = %v", blocked)
		}
		step("reported %d event(s) %v and applied no block, which is correct for a"+
			" capture carrying no TCP evidence (Block.RequireTCPEvidence)", total, outcomes)
	} else {
		step("the daemon path reported %s from %s and applied a block for %v",
			applied.Event.MethodDetail, applied.Event.Src, applied.BlockDuration)
	}

	members, err := kernelSetMembers()
	if err != nil {
		fail("reading the nftables sets back: %v", err)
	}
	blocked := m.Blocked()
	if applied != nil {
		// Every address the manager believes it blocked is really in the kernel,
		// and the one it reported is among them.
		inManager := map[netip.Addr]bool{}
		for _, e := range blocked {
			inManager[e.Addr] = true
			if !members[e.Addr] {
				fail("%s is listed as blocked but is not in the kernel's set", e.Addr)
			}
		}
		if !inManager[applied.Event.Src] {
			fail("%s was reported as blocked but Blocked() = %v", applied.Event.Src, blocked)
		}
		// And nothing is in the kernel that the manager does not own: a rule
		// nobody owns is a rule nobody removes.
		for a := range members {
			if !inManager[a] {
				fail("%s is in the kernel's set but the manager does not list it", a)
			}
		}
		step("%d blocked address(es) %v are in the kernel's nftables sets, and nothing else is",
			len(blocked), blocked)
	} else if len(members) != 0 {
		fail("no block was applied, yet the kernel's sets hold %v", members)
	}

	m.Stop()

	// Nothing this daemon installed may outlive it.
	if members, err := kernelSetMembers(); err != nil {
		fail("reading the nftables sets back after shutdown: %v", err)
	} else if len(members) != 0 {
		fail("%v are still blocked in the kernel after Stop: those rules now belong to nobody", members)
	} else {
		step("the block was released at shutdown; the kernel holds nothing")
	}
}

// scannerIsInKernelSet asks the kernel whether the scanner address is in the
// blocker's IPv4 set, over a connection the blocker never used.
// kernelSetMembers reads back every address the daemon's nftables sets hold,
// through a fresh netlink connection, so what is checked is what the kernel
// holds rather than what the blocker believes it sent.
//
// Both sets are read. Reading only portscan_sources_v4 would make a block
// installed for an IPv6 scanner read back as "not in the kernel set" -- and,
// if no IPv6 capture replayed a frame, nothing would notice.
func kernelSetMembers() (map[netip.Addr]bool, error) {
	out := map[netip.Addr]bool{}
	conn, err := nftables.New()
	if err != nil {
		return nil, err
	}
	defer conn.CloseLasting()

	tables, err := conn.ListTables()
	if err != nil {
		return nil, err
	}
	for _, t := range tables {
		if t.Name != "opensnitch-portscan" {
			continue
		}
		sets, err := conn.GetSets(t)
		if err != nil {
			return nil, err
		}
		for _, s := range sets {
			if s.Name != "portscan_sources_v4" && s.Name != "portscan_sources_v6" {
				continue
			}
			elems, err := conn.GetSetElements(s)
			if err != nil {
				return nil, err
			}
			for _, e := range elems {
				if a, ok := netip.AddrFromSlice(e.Key); ok {
					out[a.Unmap()] = true
				}
			}
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// guest plumbing
// ---------------------------------------------------------------------------

// vmHost accepts only the victim address, so replayed outbound frames are
// discarded exactly as they would be on a real host.
type vmHost struct{ local map[netip.Addr]bool }

func (h *vmHost) IsLocalUnicast(a netip.Addr) bool   { return h.local[a.Unmap()] }
func (h *vmHost) IsListening(uint8, uint16) bool     { return false }
func (h *vmHost) HasConnection(*portscan.Probe) bool { return false }
func (h *vmHost) IsOnLink(netip.Addr) bool           { return true }
func (h *vmHost) IsExempt(netip.Addr) bool           { return false }

func envOr(key, dflt string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return dflt
}

// setupVeth builds the pair the frames will be replayed onto.
func setupVeth() error {
	la := netlink.NewLinkAttrs()
	la.Name = victimIf
	veth := &netlink.Veth{LinkAttrs: la, PeerName: attackerIf}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("creating the pair: %w", err)
	}
	link, err := netlink.LinkByName(victimIf)
	if err != nil {
		return err
	}
	peer, err := netlink.LinkByName(attackerIf)
	if err != nil {
		return err
	}
	for _, cidr := range []string{corpusVictimCIDR, corpusVictimCIDR6} {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("addressing %s with %s: %w", victimIf, cidr, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(peer); err != nil {
		return err
	}
	time.Sleep(300 * time.Millisecond)
	return nil
}

// replay writes captured frames onto ifName with a raw packet socket, so they
// arrive on the peer exactly as they did on the wire when nmap produced them.
//
// Only frames addressed to the victim are replayed: the capture also contains
// the victim's own replies, and injecting those would be replaying our own
// outbound traffic back at ourselves.
//
// gap is the pause between frames. A short pause keeps the veth queue from
// dropping frames, which would make a genuine detection failure
// indistinguishable from lost traffic; the cost measurement passes zero,
// because there the point is to keep the program busy.
func replay(ifName string, frames [][]byte, targets []netip.Addr, inbound *int, gap time.Duration) (int, error) {
	ifi, err := net.InterfaceByName(ifName)
	if err != nil {
		return 0, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htonsLocal(unix.ETH_P_ALL)))
	if err != nil {
		return 0, fmt.Errorf("opening a packet socket: %w", err)
	}
	defer unix.Close(fd)

	sa := &unix.SockaddrLinklayer{Protocol: htonsLocal(unix.ETH_P_ALL), Ifindex: ifi.Index}
	sent := 0
	for _, f := range frames {
		if len(f) < 34 {
			continue
		}
		if !frameTargets(f, targets) {
			continue
		}
		*inbound++
		if err := unix.Sendto(fd, f, 0, sa); err != nil {
			return sent, fmt.Errorf("sending frame %d: %w", sent, err)
		}
		sent++
		if gap > 0 {
			time.Sleep(gap)
		}
	}
	return sent, nil
}

// frameTargets reports whether an Ethernet frame carries an IPv4 packet aimed
// at addr.
// frameTargets reports whether an Ethernet frame is addressed to one of the
// given addresses.
//
// Testing EtherType 0x0800 only would make every IPv6 capture replay nothing
// at all while the run still looked like it had done something.
func frameTargets(f []byte, addrs []netip.Addr) bool {
	var dst netip.Addr
	switch binary.BigEndian.Uint16(f[12:14]) {
	case 0x0800:
		if len(f) < 34 {
			return false
		}
		a, ok := netip.AddrFromSlice(f[30:34])
		if !ok {
			return false
		}
		dst = a
	case 0x86DD:
		// 14 Ethernet + 40 fixed IPv6 header; the destination is its last 16.
		if len(f) < 54 {
			return false
		}
		a, ok := netip.AddrFromSlice(f[38:54])
		if !ok {
			return false
		}
		dst = a
	default:
		return false
	}
	dst = dst.Unmap()
	for _, a := range addrs {
		if dst == a {
			return true
		}
	}
	return false
}

func htonsLocal(v uint16) uint16 { return v<<8 | v>>8 }

// readPcapFrames reads a libpcap savefile and returns the raw frames.
func readPcapFrames(path string) ([][]byte, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	if len(raw) < 24 {
		return nil, fmt.Errorf("shorter than a pcap header")
	}
	var bo binary.ByteOrder
	switch binary.LittleEndian.Uint32(raw[0:4]) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		bo = binary.LittleEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		bo = binary.BigEndian
	default:
		return nil, fmt.Errorf("unrecognised pcap magic")
	}
	if lt := bo.Uint32(raw[20:24]); lt != 1 {
		return nil, fmt.Errorf("link type %d is not Ethernet", lt)
	}
	var out [][]byte
	off := 24
	for off+16 <= len(raw) {
		n := int(bo.Uint32(raw[off+8 : off+12]))
		off += 16
		if n < 0 || off+n > len(raw) {
			break
		}
		out = append(out, raw[off:off+n])
		off += n
	}
	return out, nil
}

// loadKernelModules inserts the named modules with init_module(2), in the order
// given.
//
// The order is the caller's business because init_module(2) resolves no
// dependencies: nf_tables loaded before nfnetlink simply fails. The modules are
// decompressed by the harness that builds the initramfs, because init_module(2)
// takes a plain image. A module already built into the kernel returns EEXIST,
// which is success for our purposes, and one that is absent from the payload is
// reported rather than silently skipped.
func loadKernelModules(dir string, names ...string) error {
	for _, name := range names {
		path := filepath.Join(dir, name+".ko")
		image, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				step("kernel module %s is not in the payload; assuming it is built in", name)
				continue
			}
			return fmt.Errorf("reading %s: %w", name, err)
		}
		if err := unix.InitModule(image, ""); err != nil {
			if err == unix.EEXIST {
				step("module %s is already present", name)
				continue
			}
			return fmt.Errorf("inserting %s: %w", name, err)
		}
		step("inserted kernel module %s", name)
	}
	return nil
}

// mountPseudoFilesystems sets up what the rest of the program needs.
//
// This is done here, not in a shell init script, because the busybox available
// in this Nix store is an initrd-minimal build with almost no applets -- not
// even mount. A missing applet fails silently, and the resulting symptom is
// obscure: cilium/ebpf reports "open /proc/self/mountinfo: no such file or
// directory" while detecting BTF support, which reads like a kernel problem
// rather than an unmounted /proc.
func mountPseudoFilesystems() {
	for _, m := range []struct {
		source, target, fstype string
		optional               bool
	}{
		{"proc", "/proc", "proc", false},
		{"sysfs", "/sys", "sysfs", false},
		{"devtmpfs", "/dev", "devtmpfs", true},
		{"bpffs", "/sys/fs/bpf", "bpf", true},
	} {
		_ = os.MkdirAll(m.target, 0o755)
		if err := unix.Mount(m.source, m.target, m.fstype, 0, ""); err != nil {
			if err == unix.EBUSY {
				continue // already mounted
			}
			if !m.optional {
				fail("mounting %s on %s: %v", m.fstype, m.target, err)
			}
		}
	}

	// /dev/net/tun, so the privileged tests can build an ARPHRD_NONE device.
	//
	// devtmpfs does not create it: the node appears only once the tun module is
	// loaded, and this kernel has it built in but with no udev to make the node.
	// Without it the one test that covers interfaces with no link header -- the
	// shape a VPN presents, and the shape both packet sources were blind to --
	// skips in the only environment that can load the program at all.
	_ = os.MkdirAll("/dev/net", 0o755)
	if err := unix.Mknod("/dev/net/tun", unix.S_IFCHR|0o600, int(unix.Mkdev(10, 200))); err != nil &&
		err != unix.EEXIST {
		step("note: /dev/net/tun could not be created (%v); the tunnel tests will skip", err)
	}
}

// powerOff shuts the guest down. Running as PID 1, returning from main would
// panic the kernel and lose the buffered console output.
func powerOff() {
	os.Stdout.Sync()
	time.Sleep(500 * time.Millisecond)
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
}

// ---------------------------------------------------------------------------
// the start-up grace, in the kernel
// ---------------------------------------------------------------------------

// phaseGrace replays the capture with the program inside a one-hour start-up
// grace. Only TCP carrying ACK may be held back there: a program that held
// back everything would mean that on this path -- the preferred one -- a SYN
// sweep in the first minute after every boot never reached the engine. Every
// other phase runs with StartupGrace 0 and could not see it.
func phaseGrace(modulePath string, frames [][]byte) {
	step("phase 1b: the start-up grace holds back acknowledging TCP only (capture %q)", pcapName)
	var (
		mu              sync.Mutex
		probes, withAck int
	)
	src, err := portscan.NewEbpfSource(portscan.EbpfOptions{
		ModulesPath:        modulePath,
		Interfaces:         []string{victimIf},
		StartupGrace:       time.Hour,
		MaxProbesPerSecond: 100000,
		LocalAddrs:         victims,
	},
		func(p *portscan.Probe) {
			mu.Lock()
			defer mu.Unlock()
			probes++
			if p.IsTCP() && p.TCPFlagsValid && p.TCPFlags&portscan.TCPAck != 0 {
				withAck++
			}
		},
		func(e error) { fmt.Printf("VMTEST-SOURCE-ERR: %v\n", e) },
	)
	if err != nil {
		fail("loading the module for the grace phase: %v", err)
		return
	}
	defer src.Close()
	go src.Run()
	time.Sleep(300 * time.Millisecond)

	inbound := 0
	if _, err := replay(attackerIf, frames, victims, &inbound, 200*time.Microsecond); err != nil {
		fail("replaying the capture: %v", err)
		return
	}
	time.Sleep(time.Second)

	mu.Lock()
	gotProbes, gotAck := probes, withAck
	mu.Unlock()
	step("inside the grace: %d probes reached userspace, %d of them TCP with ACK", gotProbes, gotAck)
	if gotAck != 0 {
		fail("%d acknowledging TCP packets were forwarded inside the start-up grace", gotAck)
	}
	if !capturedOnlyAcknowledgingTCP(frames) && !isBenignCapture() && gotProbes == 0 {
		fail("nothing reached userspace inside the start-up grace: the kernel is holding" +
			" back probes that cannot be replies, and the first minute after every boot is blind")
	}
}

// capturedOnlyAcknowledgingTCP reports whether every inbound frame of the
// capture is TCP carrying ACK (-sA, -sW, -sM), which the grace rightly holds.
func capturedOnlyAcknowledgingTCP(frames [][]byte) bool {
	matched := 0
	for _, f := range frames {
		var p portscan.Probe
		if portscan.ParseEthernet(f, &p) != nil {
			continue
		}
		mine := false
		for _, v := range victims {
			mine = mine || p.Dst == v
		}
		if !mine {
			continue
		}
		matched++
		if !(p.IsTCP() && p.TCPFlagsValid && p.TCPFlags&portscan.TCPAck != 0) {
			return false
		}
	}
	return matched > 0
}

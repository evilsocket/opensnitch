//go:build linux

package portscan

import (
	"net/netip"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// Reconnaissance this sensor does NOT see.
//
// The nmap corpus answers "does the engine name the technique nmap was asked to
// use". It cannot answer "what reconnaissance exists that nmap does not
// implement", and nmap is one maintainer's tool with a slow release cycle, so
// that is a real gap in the evidence rather than a theoretical one.
//
// testdata/recon holds techniques forged by hand with scapy from RFC 7707
// (Network Reconnaissance in IPv6 Networks), from nmap's own
// targets-ipv6-multicast-* NSE scripts -- which are NSE, so no capture of them
// exists in a corpus generated from command-line options -- and from the
// rate-limit side-channel literature. forge_recon.py builds them and cites the
// source of each.
//
// This test asserts the MEASURED status of each, including the ones that are not
// detected. A test that only pinned the successes would let the coverage
// document drift away from the truth, and the point of that document is to say
// what the code does rather than what it is meant to do.
//
// Two structural reasons account for every miss below, and both are deliberate
// choices made elsewhere in the design:
//
//   - a probe sent to a multicast or broadcast destination is discarded before
//     scoring, because Engine.accept requires one of this host's own unicast
//     addresses. That is what keeps ordinary router advertisements, neighbour
//     discovery, mDNS and SSDP from being scored -- and it is also why the whole
//     IPv6 link-local discovery family, which is how hosts are actually found on
//     a link now that brute-force address scanning is impossible, is invisible;
//   - ICMP and ICMPv6 are parsed but never scored: they have no ports, so
//     classify puts them in the "other protocol" bucket, which feeds the
//     distinct-protocol counter and nothing else. A single-protocol ICMP sweep
//     therefore scores zero however many packets it sends.
type reconCase struct {
	// detected is the measured outcome today.
	detected bool
	// why explains the outcome, and for a miss, what would have to change.
	why string
}

func TestReconnaissanceBeyondNmap(t *testing.T) {
	cases := map[string]reconCase{
		"mp6-multicast-echo.pcap": {
			detected: false,
			why: "ICMPv6 echo to ff02::1, RFC 7707 s3.1 and nmap's" +
				" targets-ipv6-multicast-echo. Dropped: the destination is not one of" +
				" our unicast addresses",
		},
		"ieh-invalid-option-multicast.pcap": {
			detected: false,
			why: "unrecognised option type 0x80 in a Destination Options header to" +
				" ff02::1, RFC 7707 s3.2 and nmap's targets-ipv6-multicast-invalid-dst." +
				" It exists precisely because Windows ignores multicast echo. Dropped" +
				" on the destination",
		},
		"ieh-invalid-option-unicast.pcap": {
			detected: false,
			why: "the same probe aimed at our own address, which is what a scanner" +
				" sends once a hitlist has given it a candidate. Reaches the engine and" +
				" scores nothing: ICMPv6 has no port, so it is classed other-protocol",
		},
		"mld-query.pcap": {
			detected: false,
			why:      "MLD general query, RFC 7707 s3.3: every listener answers and reveals itself",
		},
		"llmnr-enumeration.pcap": {
			detected: false,
			why: "LLMNR name enumeration to ff02::1:3. Dropped twice over: multicast" +
				" destination, and port 5355 is in the default ExcludedPorts",
		},
		"mdns-enumeration.pcap": {
			detected: false,
			why:      "mDNS service enumeration to 224.0.0.251, same two reasons",
		},
		"broadcast-ping.pcap": {
			detected: false,
			why:      "IPv4 subnet and limited broadcast ping: not a unicast destination",
		},
		"router-solicitation.pcap": {
			detected: false,
			why:      "Router Solicitation to ff02::2, a topology probe rather than a port probe",
		},
		"rst-ratelimit-probe.pcap": {
			detected: false,
			why: "sixty SYNs to ONE port, to measure the global RST budget and use this" +
				" host as an idle-scan reflector. Port deduplication means one counted" +
				" probe. Genuinely out of scope for a PORT scan detector, but worth" +
				" knowing: the host is being used as an instrument against a third party",
		},
		"icmpv6-ratelimit-probe.pcap": {
			detected: false,
			why: "sixty ICMPv6 echo requests to our unicast address, the side channel of" +
				" arXiv 2210.13088. ONE message type, so it is still not reported -- and" +
				" deliberately: echo is the most ordinary packet on a network and" +
				" scoring it by volume would make a monitoring system look like an" +
				" attacker",
		},
		"icmp-host-sweep.pcap": {
			detected: true,
			why: "nmap -PE -PP -PM: echo, timestamp and address mask, three distinct" +
				" types. Reported as an ICMP sweep -- the count of distinct types is" +
				" what separates reconnaissance from volume",
		},
		"icmpv6-node-info-query.pcap": {
			detected: false,
			why: "RFC 4620 Node Information Query, which asks the host for its names and" +
				" addresses outright. It DOES score now -- 40 of the 100 needed -- where" +
				" it scored nothing before, but one message type is deliberately not" +
				" enough on its own: a single stray probe from a misconfigured device" +
				" must not report a scan. Two of them, or one alongside any other" +
				" probing, crosses",
		},
		"icmp-monitoring-flood.pcap": {
			detected: false,
			why: "five hundred echo requests from one source: a monitoring system, not an" +
				" attacker. This is the false positive the whole design of scoring ICMP" +
				" by distinct type exists to avoid, and it must stay silent",
		},
	}

	files, err := filepath.Glob(filepath.Join("testdata", "recon", "*.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Skip("testdata/recon holds no captures; run forge_recon.py")
	}
	sort.Strings(files)

	host := reconHost{
		v4: netip.MustParseAddr("10.77.0.1"),
		v6: netip.MustParseAddr("fd00:77::1"),
	}

	for _, path := range files {
		name := filepath.Base(path)
		want, known := cases[name]
		if !known {
			t.Errorf("%s has no recorded expectation; add one saying what it is and"+
				" whether it is seen", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			f, err := readPcap(path)
			if err != nil {
				t.Fatal(err)
			}
			probes, err := f.probesFrom(uint64(time.Hour), 1)
			if err != nil {
				t.Fatal(err)
			}
			cfg := testConfig()
			cfg.AlertsPerMinute = maxAlertsPerMinute
			cfg.ReportCooldown = 0
			cfg.StartupGrace = 0
			e, err := NewEngine(cfg, host, 0)
			if err != nil {
				t.Fatal(err)
			}
			var ev *ScanEvent
			for _, p := range probes {
				if got := e.Process(p); got != nil && ev == nil {
					ev = got
				}
			}
			st := e.Stats()
			t.Logf("%d frames, %d parsed, %d counted, %d filtered -- %s",
				len(f.Packets), len(probes), st.ProbesCounted, st.ProbesFiltered, want.why)

			if got := ev != nil; got != want.detected {
				if want.detected {
					t.Errorf("this technique used to be detected and is not any more")
				} else {
					t.Errorf("this technique is now DETECTED. That is good news, but the"+
						" coverage document and %s still say it is not -- update both,"+
						" rather than leaving the documentation claiming a gap that has"+
						" been closed", name)
				}
			}
		})
	}
}

type reconHost struct{ v4, v6 netip.Addr }

func (h reconHost) IsLocalUnicast(a netip.Addr) bool { return a == h.v4 || a == h.v6 }
func (reconHost) IsListening(uint8, uint16) bool     { return false }
func (reconHost) HasConnection(*Probe) bool          { return false }
func (reconHost) IsOnLink(netip.Addr) bool           { return true }
func (reconHost) IsExempt(netip.Addr) bool           { return false }

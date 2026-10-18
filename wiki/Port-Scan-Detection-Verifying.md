# Port scan detection: verifying it yourself

Back to [Port Scan Detection](Port-Scan-Detection).

## On your own machine, with real scans

`utils/scripts/portscan-real-condition-test.sh` checks the feature on the
machine it runs on, with real nmap scans, and sends nothing on the network. It
creates a network namespace joined to the machine by a veth pair, puts the
target address on the machine's side of the pair, runs nmap from the
namespace, and after each scan reads the daemon's log to compare what was
reported with what the [Coverage](Port-Scan-Detection-Coverage) page expects.

```sh
sudo utils/scripts/portscan-real-condition-test.sh 10.99.0.1               # every test
sudo utils/scripts/portscan-real-condition-test.sh -m quick 10.99.0.1      # a few minutes
sudo utils/scripts/portscan-real-condition-test.sh 10.99.0.1 | tee run.log # keep the output
```

| Mode (`-m`) | Tests | At the default interval |
|---|---|---|
| `full` (default) | the 23 below, IPv4 and IPv6 | about 1 h 20 |
| `ipv4` | the 18 IPv4 tests | about 1 h 05 |
| `ipv6` | the 5 IPv6 tests | about 15 minutes |
| `quick` | TCP SYN, TCP connect, Xmas and UDP in IPv4; SYN and Xmas in IPv6; the benign control | about 5 minutes |

The tests are the commands of the project's capture corpus
(`daemon/portscan/testdata/generate_corpus.sh`): `-sS`, `-sT`, `-sF`, `-sN`,
`-sX`, `-sM`, `-sA`, `-sW`, two `--scanflags` combinations, `-sU`, `-sO`, `-f`,
`-D`, `-O`, a slow `-T1` scan, IPv6 versions of `-sS`, `-sF`, `-sX` and `-sU`,
and a benign control (one connection attempt, retried) that must not be
reported; plus two that the corpus does not have, `--spoof-mac` and the same
benign control in IPv6.

Options:

- `-m`, `--mode`: `full`, `ipv4`, `ipv6` or `quick`, as above.
- `-i`, `--interface NAME`: the name of the machine's side of the veth pair, 13
  characters at most; by default a new one each run (`psd` and four hex
  digits). The scanner's side is `NAME-p`, its namespace `NAME-ns`.
- `-t`, `--interval SECONDS`: time between two tests, 180 by default and 30 in
  `quick`. Each test starts from a new source address and MAC address, since
  the daemon reports a source again only after `ReportCooldown` (5 minutes);
  the interval keeps the alerts within `AlertsPerMinute`.
- `-l`, `--log FILE`: the daemon's log, by default the more recently written of
  `/var/log/opensnitchd.log` and `/var/log/opensnitchd-dev.log`.

What to know before running it:

- **The target address** must be private (10/8, 172.16/12, 192.168/16) and
  written without leading zeros. The script refuses it, and lists the routes,
  when a route of the machine, in any table, lies inside its /24 (a smaller
  network on a real interface) or contains it at /8 or narrower (a VPN's
  `10.0.0.0/8`, a static route): the host's replies, or the blocks, would
  reach real machines. Wider routes (a default route, OpenVPN's `0.0.0.0/1`
  halves, `fc00::/7`) do not count. For the run, it adds a routing rule of
  priority 1 that looks the test's networks up in the main table, where the
  pair's routes are, and removes it at the end: a rule that sends traffic to
  a table of its own (a multi-WAN setup, a VPN exit node, one on a port or a
  firewall mark, or one added while the tests run) cannot take the replies
  elsewhere. Before any scan, it also asks the kernel where the replies
  would go, and stops unless they stay on the pair. The IPv6 tests use the ULA prefix
  `fd5c:a11e:7e57::/64`, checked the same way (`-m ipv4` skips them).
- **Nothing is left behind.** The namespace and the pair are removed at the
  end, on Ctrl-C (`| tee` included), `kill` or a closed terminal (the scan or
  pause under way is stopped at once), and on an error. An interface or namespace that already
  has the chosen name is never touched: the script asks for another name. The sources live only on this machine, so a
  block on them cuts nothing off; those blocked stay in the Port scan
  Detection tab until they expire, and can be released or deleted there.
- **The daemon must watch every interface** (`"Interfaces": []` in the
  `PortScan` section, the default), and detection must be on (`"Enabled":
  true`; it is off until configured). The daemon looks at its interfaces
  again every minute; the script waits, two minutes at most, for its log to
  say it watches the new one, and stops there, saying what to check, if it
  does not.
- **Under the `ask` policy**, each scan raises a notification. Answering it or
  letting it expire changes nothing for the tests that follow.
- It needs root, `ip` (iproute2) and `nmap`.

Each test ends with one of: *reported as expected*; *reported, under another
name* (the technique was named differently, see
[How It Works](Port-Scan-Detection-Internals) §4.7); *nothing in the log*; or,
for the benign controls, *nothing reported, as expected*. A report the alert
limiter delayed can appear in the log after its test. The scans whose probes
all carry ACK (`-sA`, `-sW`, `-sM`) or are not TCP probes (`-sU`, `-sO`) are
reported but, under the default settings, not proposed for blocking (*not
blocked: refused*): nothing in them is something only a scanner sends, and
their source address costs nothing to forge (see
[Settings](Port-Scan-Detection-Settings)). They can still be blocked from the
list, after a warning.

## Checking it yourself

```sh
cd daemon
go test ./portscan/...                      # unit and differential tests
./portscan/testdata/generate_corpus.sh      # 21 real nmap captures (needs nmap, tcpdump)
./portscan/testdata/run_live_test.sh        # a real scan, end to end
./portscan/testdata/run_nft_test.sh         # real nftables rules, in a namespace
./portscan/testdata/vm/run_vm_test.sh       # the eBPF path, in a throwaway VM
```

The last three build their own isolated environment (a user namespace or a
virtual machine), so none of them touches the machine's real firewall or network.

`run_vm_test.sh` takes a capture name and defaults to `tcp-syn`. It is worth
running over the whole corpus, which is what closes the loop on the parts no
unit test reaches:

```sh
for f in portscan/testdata/pcap/*.pcap; do
    ./portscan/testdata/vm/run_vm_test.sh "$(basename "$f" .pcap)"
done
```

Each run boots a throwaway machine, loads the real eBPF object, attaches it
through TCX, replays the capture onto a veth pair, and follows the detection
through `portscan.Setup` to a real nftables rule and back to nothing at
shutdown. The IPv6 captures exercise the IPv6 parser and the `portscan_sources_v6`
set; `benign-single-port` is the negative control and must produce no detection
at all; `udp` and `ip-protocol` must produce a report and **no** block, since
`Block.RequireTCPEvidence` defaults to true and neither carries any.

`go test ./portscan/...` includes the kernel-versus-userspace differential.
There are two independent implementations of the same packet parsing here (the
eBPF program, which is the path you get by default, and the Go parser behind the
AF_PACKET fallback), and their verdicts are supposed to be identical by
construction. Asserted without being checked, that is how a security fix ends up
applied to one of the two only: a LAN scan with `nmap -f -sS` could then score
zero on a machine where eBPF works exactly as designed.

`testdata/cparse/` compiles `ebpf_prog/opensnitch-scan.c` unmodified against
a small stand-in for libbpf and runs it as an ordinary program, frame by frame.
Both parsers answer the same two questions (what did you read, and would you
have counted it) on every frame of the nmap corpus and on a set of adversarial
ones, and must agree field by field. It needs a C compiler and the kernel's UAPI
headers; without them those tests skip and say so.

To see it work by hand, from another machine:

```sh
nmap -sS -p1-200 <this-host>
```

The scan appears as a notification and under **Rules** › **Alerts**. If you block
it, the address appears in the **Port scan Detection** tab, and in the kernel:

```sh
sudo nft list set inet opensnitch-portscan portscan_sources_v4
```

### Testing with a spoofed hardware address

`nmap --spoof-mac 0` does not test the detection one run in two. With `0`,
nmap draws all six bytes at random, so about half of the addresses it picks
have the lowest bit of the first byte set (an odd first byte, such as
`03:…` or `D9:…`): that marks a multicast address, which is not a valid
source. Switches and Linux bridges drop such frames, including nmap's ARP
request for the target. Without an ARP reply nmap has no hardware address to
send to, reports "0 hosts up" (even with `-Pn`) and sends no probe at all, so
there is nothing for the daemon to detect. On a test bench (attacker, Linux
bridge, target), `--spoof-mac 03:11:22:33:44:55` delivered nothing to the
target, not even the ARP request, while `--spoof-mac 02:11:22:33:44:55`
delivered the ARP request and all 50 SYNs.

Use a unicast address instead:

```sh
nmap --spoof-mac 02:11:22:33:44:55 -sS -p1-200 <this-host>   # locally administered
nmap --spoof-mac Dell -sS -p1-200 <this-host>                # a vendor prefix, rest random
# a different valid address on every run (bash, for $RANDOM):
nmap --spoof-mac "$(printf '02:%02x:%02x:%02x:%02x:%02x' $((RANDOM%256)) \
  $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))" \
  -sS -p1-200 <this-host>
```

The daemon does not filter on the source hardware address (the eBPF program
and the AF_PACKET fallback only check that a frame is addressed to this
host), so a scan with a valid spoofed address is detected like any other, and
its details show the spoofed address.

A valid address can still be stopped before it reaches this host:

- from a Wi-Fi client, the access point drops frames whose source is not the
  associated station's address;
- from a virtual machine, by the hypervisor's anti-spoofing: the Proxmox
  firewall's MAC filter, libvirt's `clean-traffic` filter, VMware's
  "Forged transmits: Reject", Hyper-V's MAC address spoofing setting off;
- across a router, the source hardware address is rewritten at every hop: the
  scan is detected, and its details show the last router's address, labelled
  as such.

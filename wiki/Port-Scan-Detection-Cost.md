# Port scan detection: what it costs

Back to [Port Scan Detection](Port-Scan-Detection).

## What it costs

Measured, not asserted. On an AMD Ryzen 7 PRO 2700U, with no allocation on the
packet path in any configuration:

| | per packet |
|---|---|
| eBPF, ordinary traffic not addressed to this host | ~0.5 µs |
| eBPF, past the aggregate budget | ~0.7 µs |
| eBPF, past the per-source budget | ~0.8 µs |
| eBPF, every probe forwarded (the first second of a scan) | 3–7 µs |
| AF_PACKET fallback, parse and judge in userspace | ~240 ns + a system call per packet |

Two budgets bound the kernel side, and only the second of them bounds anything
in aggregate. The per-source budget caps how much one address can push through
the ring buffer, 256 probes per second; a flood of forged addresses defeats it by
construction, since every packet then comes from an address never seen before.
The aggregate budget, applied per CPU, is the ceiling that actually exists. A
known source is held to its own budget first and only what survives it is
charged to the aggregate, so one busy peer (a large download) spends its own
budget and not everyone's.

The userspace side is sharded by source address, so a flood spreads across
independently locked partitions instead of serialising on one. Measured on four
cores: 1378 ns per probe with a single lock, 680 ns sharded. Traffic from a
*single* source still serialises (every packet mutates the same state, which no
locking arrangement changes), and that case is what the per-source kernel budget
is for.

The eBPF figures come from the kernel's own per-program accounting, measured
inside a virtual machine; they vary by 20–40% between runs and are upper bounds
on real hardware. The userspace figure is a Go benchmark and is stable.
Reproduce both with:

```sh
cd daemon
go test -run '^$' -bench . -benchmem ./portscan/   # the userspace path
./portscan/testdata/vm/run_vm_test.sh              # phase 2 prints the rest
```

The difference between the two paths is not the arithmetic (that is the same
code) but that AF_PACKET copies every packet to userspace, and eBPF forwards
only what survives the kernel-side filters.

That difference is much larger in aggregate than per packet, which is why both
paths carry the **same two budgets**: 256 probes per second per source, and
4096 in aggregate, applied in the same order. On the fallback they are applied
after the parse, which needs the source address, and bound what reaches the
engine; the fallback still copies and parses every frame that passes its
filter, at about ninety times the aggregate cost of the eBPF path. What the
aggregate budget refuses, and what the kernel drops because the daemon is not
reading fast enough, is counted and reported rather than silently dropped: said
at most once an hour for each counter, so a condition that lasts is not a
warning a minute, and again sooner if it grows tenfold. A source refused by its own
budget is counted too (`source_rate_limited`) but not reported: it costs no
other source anything, and every large download would otherwise raise a warning.
One exception, on the fallback: its per-source budgets live in a fixed table,
and a source that finds both its slots held by other active sources shares one
budget with every source in the same position. That budget is common to them,
so its refusals are reported like the aggregate's. On a machine talking to
hundreds of peers at once, a download can therefore raise that warning: a few
times in a hundred with a thousand active peers, measured.

The budgets count packets, not probes. The packets of connections this host has
open reach them too, since telling them apart is the engine's work, so a machine
exchanging heavily with many peers at once (seeding, serving a dozen clients)
can keep the aggregate spent on its own. That is degraded detection, and it is
reported as such. The fallback's kernel-side filter also
rejects broadcast and multicast outright, which on a busy segment is most of
what arrives, and it does so before the frame is copied.

Blocks are released in batches of 1024 per nftables transaction rather than one per
address. Releasing 128 of them takes 8 ms batched against 795 ms one at a time,
and because nftables commits are serialised per network namespace, the slow
version also slowed every *other* transaction on the machine, OpenSnitch's own
rule checks included, by roughly eightfold while it ran.

A detected scan is acted on by a separate goroutine, never on the packet path.
Installing a firewall rule inline cost the goroutine draining the kernel ring
buffer about 2.9 ms, during which the kernel dropped probes for want of anyone
reading them: the detector blinded itself at the moment it decided someone was
scanning. The queue between the two is bounded and drops rather than stalls,
and what it drops is reported.

The work per packet is bounded and does not grow with how long a scan has been
running, which is the flaw in several existing implementations: they walk the
list of ports already seen on every packet, so watching a scan gets more
expensive the longer it goes on.

The aggregate budget has a cost worth naming. A flood of forged addresses is
charged to it before any per-source budget exists for them, and it cannot favour
the traffic that looks like a scan: a flood above the ceiling drops the same
proportion of *every* source's probes, including those of a real scan running
alongside it. At a million packets per second on four cores
the pass rate is around 1.6%, which multiplies the time to cross the threshold by
about sixty. There has to be a ceiling (without one, a flood of forged addresses
is forwarded in full, since every packet comes from an address never seen before),
but a detector degraded that far must say so, so the daemon reports a rise in
`rate_limited` (the aggregate budget) and in `ringbuf_full` (eBPF) or
`kernel_dropped` (AF_PACKET), read once a minute and said at most once an hour
each unless they grow tenfold; a failure to read them is said as well. Detection
that is degraded without saying so is indistinguishable from an absence of
attack.

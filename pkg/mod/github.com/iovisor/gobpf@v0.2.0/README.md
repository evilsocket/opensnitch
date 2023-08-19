# gobpf

[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](http://godoc.org/github.com/iovisor/gobpf) [![CI](https://github.com/iovisor/gobpf/actions/workflows/ci.yml/badge.svg)](https://github.com/iovisor/gobpf/actions/workflows/ci.yml)

This repository provides go bindings for the [bcc framework](https://github.com/iovisor/bcc)
as well as low-level routines to load and use eBPF programs from .elf
files.

Input and contributions are very welcome.

We recommend vendoring gobpf and pinning its version as the API is regularly
changing following bcc and Linux updates and releases.

## Requirements

eBPF requires a recent Linux kernel. A good feature list can be found here:
https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md

### `github.com/iovisor/gobpf/bcc`

Install the latest released version of [libbcc](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
(either using a package manager or by building from source).

### `github.com/iovisor/gobpf/elf`

#### Building ELF Object Files

To build ELF object files for use with the elf package, you must use specific
sections (`SEC("...")`). The following are currently supported:

* `kprobe/...`
* `cgroup/skb`
* `cgroup/sock`
* `maps/...`
* `socket...`
* `tracepoint...`
* `uprobe/...`
* `uretprobe/...`
* `xdp/...`

Map definitions must correspond to `bpf_map_def` from [the elf package](https://github.com/iovisor/gobpf/blob/master/elf/include/bpf_map.h).
Otherwise, you will encounter an error like `only one map with size 280 bytes allowed per section (check bpf_map_def)`.

The [Cilium](https://github.com/cilium/cilium) BPF docs contain helpful info
for using clang/LLVM to compile programs into elf object files:
https://cilium.readthedocs.io/en/latest/bpf/#llvm

See `tests/dummy.c` for a minimal dummy and https://github.com/weaveworks/tcptracer-bpf
for a real world example.

## Examples

Sample code can be found in the `examples/` directory. Examples can be run as
follows:

```
sudo -E go run examples/bcc/perf/perf.go
```

## Tests

```
go test -tags integration -v ./...
```

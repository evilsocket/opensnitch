
### Compilation

> cgo: cannot load DWARF output from $WORK/b085//_cgo_.o: zlib: invalid header

See these comments: [#851](https://github.com/evilsocket/opensnitch/issues/851#issuecomment-1434624041) and [#851](https://github.com/evilsocket/opensnitch/issues/851#issuecomment-1434611009) , and issues: [#820](https://github.com/evilsocket/opensnitch/issues/820) [#768](https://github.com/evilsocket/opensnitch/issues/768)


### opensnitchd does not start

Note: Since v1.6.0 you can use `opensnitchd -check-requirements` to know if your system is compatible.

For all the following errors:

* The daemon needs NET_ADMIN capabilities. For example, to run it in docker you need --cap-add NET_ADMIN, or you'll get some of the described errors.
* `Error while creating queue #0: Error binding to queue: operation not permitted.` ([#323](https://github.com/evilsocket/opensnitch/issues/323))
     - Be sure that the daemon is not already running, check it out with: pgrep -a opensnitchd, output should be empty)
     - You should only have one opensnitchd binary at /usr/bin/opensnitchd . If you have others (for example in /usr/local/bin), investigate why it's there, and rename it to opensnitchd.xx for example (that will prevent from loading).
     - Having no opensnitchd process running (pgrep opensnitchd), launch it manually and see if it exits with error or not.
     - If you're executing it in a container, be sure to give the daemon NET_ADMIN capabilities.

* `Error while enabling probe descriptor for opensnitch_exec_probe: write /sys/kernel/debug/tracing/kprobe_events: no such file or directory` (the kernel does not have support for CONFIG_FTRACE, or it's not loaded)
* `iptables: Protocol wrong type for socket` (modules nf_defrag_ipv4, nf_conntrack_ipv4 not loaded)
* `Error opening Queue handle: protocol not supported` (nfnetlink module not loaded)
* `Could not open socket to kernel: Address family not supported by protocol (IPv6)`
* `Error while creating queue #0: Error unbinding existing q handler from AF_INET protocol` see [#323](https://github.com/evilsocket/opensnitch/issues/323) and [#204](https://github.com/evilsocket/opensnitch/issues/204).
   Usually caused because the `nfnetlink_queue` module is not loaded. Verify if it's loaded: `~ $ lsomd | grep nfnetlink_queue`
   Another reason could be because `ip_queue` module is loaded. If it's loaded, unload it.
* `Subscribing to GUI rpc error: code = ResourceExhausted desc = Received message larger than max (4210785 vs. 4194304)`
   Usually caused by the amount of rules. If you have 10k to 20k rules, consider grouping the rules to reduce the amount of rules.

be sure that you have NFQUEUE support in the kernel (=y or =m):

```bash
$ grep -E "(NFT|NETLINK|NFQUEUE)" /boot/config-$(uname -r)
CONFIG_NFT_QUEUE=y
CONFIG_NETFILTER_NETLINK_QUEUE=y
CONFIG_NETFILTER_XT_TARGET_NFQUEUE=y
```

and that the needed modules are loaded:

```bash
$ lsmod | grep -i nfqueue
xt_NFQUEUE             16384  4
x_tables               53248  20 xt_conntrack,nft_compat,xt_LOG,xt_multiport,xt_tcpudp,xt_addrtype,xt_CHECKSUM,xt_recent,xt_nat,ip6t_rt,xt_set,ip6_tables,ipt_REJECT,ip_tables,xt_limit,xt_hl,xt_MASQUERADE,ip6t_REJECT,xt_NFQUEUE,xt_mark
```

The following modules are also needed:

nf_defrag_ipv4.ko, nf_conntrack_ipv4.ko, nfnetlink.ko


### cannot open kprobe_events: open /sys/kernel/debug/tracing/kprobe_events: permission denied

If after enabling eBPF you see the following error (even as root, specially on Fedora):

you'll need to allow opensnitch in selinux or set it to permissive:

`# setenforce 0`

or:

```bash
~ $ sudo journalctl -ar | grep "opensnitch.*lockdown"
Aug 19 06:18:28 localhost-live audit[2443]: AVC avc:  denied  { confidentiality } for  pid=2443 comm=opensnitchd lockdown_reason=use of tracefs scontext=system_u:system_r:unconfined_service_t:s0 tcontext=system_u:system_r:unconfined_service_t:s0 tclass=lockdown permissive=0

~ $ echo "Aug 19 06:18:28 localhost-live audit[2443]: AVC avc:  denied  { confidentiality } for  pid=2443 comm=opensnitchd lockdown_reason=use of tracefs scontext=system_u:system_r:unconfined_service_t:s0 tcontext=system_u:system_r:unconfined_service_t:s0 tclass=lockdown permissive=0" > opensnitch_lockdown.txt

~ $ sudo su
~ # audit2allow -M opensnitchd < opensnitch_lockdown.txt
~ # semanage -i opensnitchd.pp
```

You can download this generic selinux policy from here: [#475 (comment)](https://github.com/evilsocket/opensnitch/issues/475#issuecomment-901838324)

Useful links:

https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security-enhanced_linux/sect-security-enhanced_linux-fixing_problems-allowing_access_audit2allow

https://danwalsh.livejournal.com/24750.html

https://learn.netdata.cloud/docs/agent/collectors/ebpf.plugin


### kprobe_events file exists

This error indicates that the network hooks are already added, you'll need to delete them manually:

```bash
$ sudo su
# > /sys/kernel/debug/tracing/kprobe_events
```

If it complains with "resource busy" or similar, restart the daemon.


### Error while loading kprobes: invalid argument

> eBPF Failed to load /etc/opensnitchd/opensnitch.o: error while loading "kprobe/tcp_v4_connect" (invalid argument):

This error may indicate that your kernel doesn't have [ftrace](https://www.kernel.org/doc/html/latest/trace/ftrace.html) support, which is needed for eBPF to work.

CONFIG_FTRACE should be **y** and the directory `/sys/kernel/debug/tracing/` must exist.

```bash
$ grep CONFIG_FTRACE /boot/config-$(uname-r)
CONFIG_FTRACE=y
```

If the output is `# CONFIG_FTRACE is not set`, your kernel is not compiled with ftrace support.

Read more: [#475](https://github.com/evilsocket/opensnitch/issues/475)


### error enabling tracepoints

> [eBPF events] error enabling tracepoint tracepoint/syscalls/sys_enter_execve: cannot read tracepoint id (...)

Your kernel lacks support for syscalls tracing. The kernel must have the following option configured:

$ grep FTRACE_SYSCALLS /boot/config-$(uname -r)
CONFIG_FTRACE_SYSCALLS=y

If the output is # CONFIG_FTRACE_SYSCALLS is not set, you need to reconfigure it or install one that has the option enabled.


### Kernel panics

Some users reported kernel panics with kernel 5.6.16 ([#297](https://github.com/evilsocket/opensnitch/issues/297)) and other kernels ([#41](https://github.com/evilsocket/opensnitch/issues/41)). deathtrip found that the culprit was a configuration of the Arch's linux-hardened kernel command line option.

Removing the following options from the kernel booting parameters solved the issue:

`slab_nomerge, slub_debug=FZP and page_alloc.shuffle=1`

On Debian with kernel 5.7.0, remove `slub_debug=FZP` if you have it configured and try again.

Note: This was caused by a bug in the libnetfilter_queue library.

# Dependencies:

**1. Rules tables:**

OpenSnitch uses iptables (the command), or nftables (the kernel module)
to detect new connections and enforce rules on traffic.

If the command iptables is not installed or it's deprecated
(`iptables -V` > iptables vx.y.z (legacy)) then nftables
(`grep NFT /boot/config-$(uname -r)`) will be used.

If neither is present then OpenSnitch will install sccessfully
but give error message X when run.

**2. Process monitoring**

OpenSnitch needs (ProcFS) the `/proc` directory tree, or
eBPF ([read more](https://github.com/evilsocket/opensnitch/wiki/monitor-method-ebpf)) (`grep /boot/config-$(uname -r)` -> CONFIG_KPROBES=y , or =m)
to monitor process behavior.

You select the process monitoring method at run-time in OpenSnitch's Preferences menu.

If your kernel is not compiled with eBPF and Kprobes support (or maybe
another process is using it) selecting eBPF as process monitor method
will fail with an error (visible on the Preferences dialog).


# Interaction with other software:

**1. You don't need to turn off or uninstall other firewalling.**
OpenSnitch doesn't turn them off, nor delete their rules. 

If iptables is used: OpenSnitch's main rules are added to the default filter table,
INPUT chain (`iptables -L INPUT`) and mangle table, OUTPUT chain (`iptables -t mangle -L OUTPUT`).

If nftables is used: OpenSnitch adds the same rules, but to its own tables for IPv4 and IPv6
families (`nft list ruleset`).

In both cases:

	- OpenSnitch only deletes its own rules, leaving intact
	the rest of rules configured by other firewalls.

	- OpenSnitch rules are checked every 30s +-.
	If they don't exist, they're added again.

**2. OpenSnitch should co-exist with VPN clients that write rules in
iptables or nftables.**


# Inbound vs. Outbound traffic

Originally, OpenSnitch was written to handle outbound traffic only.
Soon handling of inbound traffic will be supported too.

At this time, inbound rules can be added only if you're using iptables,
and must be added manually, by editing /etc/opensnitchd/system-fw.json
https://github.com/evilsocket/opensnitch/wiki/System-rules
There's no GUI (yet) to configure these rules, and the json format is
about to change to support Policies and nftables.

There's no support for nftables "system rules" yet.

In either case (iptables or nftables), this is experimental, in the sense
that the .json format will change and there won't be automatic translation
between versions.

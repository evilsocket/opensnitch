General
---

#### OpenSnitch displays too many dialogs to allow/deny connections

Yes, it does. But only the first time it is used. Once you configure which processes/connections you want to allow/deny, you won't notice that it's running. Really.

In the future, maybe we can add an option to queue events, and allow/deny them from the GUI: applying the default configured action until further interaction from the user.


#### Why Qt and not GTK?

I tried, but for very fast updates it failed bad on my configuration (failed bad = SIGSEGV), moreover I find Qt5 layout system superior and easier to use.


#### Why gRPC and not DBUS?

The UI service is able to use a TCP listener instead of a UNIX socket, that means the UI service itself can be executed on any operating system, while receiving messages from a single local daemon instance or multiple instances from remote computers in the network, therefore DBUS would have made the protocol and logic uselessly GNU/Linux specific.

Connections
---

#### Status is _Not Running_ message on the GUI

Be sure that the daemon is running: `$ pgrep opensnitchd`

If it's not running, you may need to enable and start it:

```
$ sudo systemctl enable opensnitchd
$ sudo systemctl start opensnitchd.service
```

#### No rules shown in the UI

Check that the daemon is running: `$ pgrep opensnitchd` . Status should be "Running".

Click on the Rules -> Nodes -> `<node address>` , and see if the rules are listed.

Some more info: [#988](https://github.com/evilsocket/opensnitch/issues/988#issuecomment-1634152487)

#### Why is WireGuard/Mullvad/etc not working with OpenSnitch?

The common reason is because the eBPF module is not installed or not working.

If you are using the packages from AUR, you need to install the additional package https://aur.archlinux.org/packages/opensnitch-ebpf-module

Another reason could be , that the eBPF module insertion failed or the debugfs is not mounted. In both cases, execute the following command:

`$ sudo cat /sys/kernel/debug/tracing/kprobe_event`

If the output is empty or it fails, then you can try mounting it: `# mount -t debugfs none /sys/kernel/debug` then restart opensnitch: `sudo service opensnitch restart`

If it still doesn't work, you can enable `[x] Debug invalid connections` under Preferences->Nodes.

[More info](https://github.com/evilsocket/opensnitch/tree/master/ebpf_prog)

#### Which connections does OpenSnitch intercept?

We currently (>= v1.6.0-rc.4) intercept new connections (iptables/conntrack state NEW) of TCP, UDP and UDPLITE, SCTP and ICMP protocols, to/from any port.

Kernels support
---

Your kernel needs some features to be enabled in order eBPF to work: debugfs (or tracefs), kprobes, perf events, ftrace and syscalls (bpf and ftrace).

Since version 1.6.x you can execute the following command to know if your kernel has all the expected features:

`opensnitchd -check-requirements`

[More info](https://github.com/evilsocket/opensnitch/tree/master/ebpf_prog)

#### xanmod and liquorix kernels

Unfortunately, these kernels are compiled without the mentioned features, so eBPF process monitor method won't be available on these kernels.
liquorix does have support for kprobes, but no syscalls tracing. But xanmod doesn't have support for any of the needed features.

For these kernels, the default method to intercept processes will be ProcFS (proc).

#### hardened kernels

We support most of the kernel hardening options. However some of them causes eBPF not to work. We don't know yet (18/11/2022) which is exactly the option that prevent us to work as expected.

Configuration
---

#### What does the "Debug invalid connections" configuration option mean?

When a process establishes a new connection, we first receive the connection information (src/dst IP, src/dst port, but no PID, nor process command line/path). Thus, we try to get who created the connection.

Sometimes we fail to discover the PID of the process, or the path of the PID, thus in these cases if you check this option, a pop-up will appear to allow or deny an "unknown connection".

#### What's the behaviour of daemon's default action "deny"

The daemon option "DefaultAction" "deny" will block ALL traffic (as of version 1.6.0-rc.4) that is intercepted by _iptables_ or _nftables_ and is not answered or configured by the user. If an outgoing connection timeouts while waiting for user action, then it'll apply the default action.

If you suspect that opensnitch is blocking an application and asking you to allow/deny it (for example VPN traffic), enable the option `[x] Debug invalid connections` from Preferences -> Nodes

If you need to allow this kind of traffic, you can add a rule directly to iptables/nftables:

`iptables -t mangle -I OUTPUT -p icmp -j ACCEPT`

Read more 👉 https://github.com/evilsocket/opensnitch/wiki/System-rules-legacy

Rules
---

#### In which order does opensnitch check configured rules?

Since version 1.2.0, rules are checked in alphabetical order.

They are evaluated until a rule with a Deny/Reject Action is found, or until a rule with the `[x] Priority` check marked is found.

So if you want to prioritize some rules over others:
1. Name the rule as 000-max-priority, 001-notsomax-priority, 002-less-preiority, not-priority
2. [x] Priority field checked (Action: allow)
3. OR Action: deny (not need to check the Priority field in these rules)

More info:
  - https://github.com/evilsocket/opensnitch/wiki/Rules-examples
  - https://github.com/evilsocket/opensnitch/wiki/Rules#best-practices

#### If I allow program A, and it launches another program B, will it be also allowed?

No. You only allow program A to access the net. Any other program launched by program A will be stopped until you allow or deny it.

See some examples:
 - Spotify launching wget: https://github.com/evilsocket/opensnitch/discussions/401
 - Vivaldi browser deb package trying to install from the internet additional packages: https://github.com/evilsocket/opensnitch/discussions/742

Read more about best practices: https://github.com/evilsocket/opensnitch/wiki/Rules#best-practices

#### Can a malicious program simply open another process or port and bypass an application based filter?

A process may open other subprocesses, but will it bypass defined application rules? No (see previous FAQ why ^). From the OpenSnitch perspective, it'll just be a new process opening an outbound connection without a rule defined for it, and as such, it'll ask you to allow or deny it.

See examples of malware running on GNU/Linux and how OpenSnitch detects the outbound connections:

https://github.com/evilsocket/opensnitch/discussions/791
https://github.com/evilsocket/opensnitch/discussions/743
https://github.com/evilsocket/opensnitch/discussions/742
https://github.com/evilsocket/opensnitch/discussions/564
https://github.com/evilsocket/opensnitch/discussions/1100

If you create a rule to allow `wget` or `curl` system-wide, a malicious process may use of it to download remote files, so it all depends on what rules you define:

https://github.com/evilsocket/opensnitch/wiki/Rules#best-practices

Anyway, nothing is unbreakable. If you know a way to bypass application rules, we'd love to see a detailed example! That'll help us to improve the application.

Other
---

**Do I need to turn off or uninstall other firewalling (firewalld, ufw, gufw) before installing OpenSnitch ? Will the OpenSnitch install or app turn them off automatically ?**

No, you don't need to turn off or uninstall other firewalling. OpenSnitch doesn't turn them off, nor delete their rules.

[Read more](https://github.com/evilsocket/opensnitch/wiki/Dependencies-and-how-it-works)

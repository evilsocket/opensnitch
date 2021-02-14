**OpenSnitch displays too many dialogs to allow/deny connections**

Yes, it does. But only the first time it is used. Once you configure which processes/connections you want to allow/deny, you won't notice that it's running. Really.

In the future, maybe we add an option to queue events, and allow/deny them from the GUI applying th default configured action until further interaction from the user.


**Why Qt and not GTK?**

I tried, but for very fast updates it failed bad on my configuration (failed bad = SIGSEGV), moreover I find Qt5 layout system superior and easier to use.


**Why gRPC and not DBUS?**

The UI service is able to use a TCP listener instead of a UNIX socket, that means the UI service itself can be executed on any operating system, while receiving messages from a single local daemon instance or multiple instances from remote computers in the network, therefore DBUS would have made the protocol and logic uselessly GNU/Linux specific.

**Which connections does OpenSnitch intercept?**

We currently (>= v1.0.0-rc4) only intercept new connections (iptables/conntrack state NEW) of TCP, UDP and UDPLITE protocols, to/from any port.

**What means "intercept unknown connections" configuration option**

When a process establishes a new connection, we first receive the connection information (src/dst IP, src/dst port, but no PID, nor process command line/path). Thus, we try to get who created the connection.

Sometimes we fail to discover the PID of the process, or the path of the PID, thus in these cases if you check this option, a pop-up will be appear to allow or deny an "unknown connection".

**What's the behaviour of daemon's default action "deny"**

The daemon option "default_action" "deny" will block ALL traffic (as of version 1.0.0rc10) that is intercepted by _iptables_ and is not answered or configured by the user. If an outgoing connection timeouts while waiting for user action, then it'll apply the default action.

But not only that, because as we don't intercept ICMP, IGMP or SCTP (among others), they'll also be blocked. We'll add an option to configure this behaviour in the near future.

If you need to allow this kind of traffic, you can add a rule directly to iptables/nftables:

`iptables -t mangle -I OUTPUT -p icmp -j ACCEPT`

**In which order does opensnitch check configured rules?**

~As of version 1.0.1, there's no order to check the rules, it's random per each connection.~

~See this issue for more information regarding this question: [#36](https://github.com/gustavo-iniguez-goya/opensnitch/issues/36)~

Since version 1.2.0, rules checked in alphabetical order. There's a new field to mark a rule as Important.

So if you want to prioritize some rules over others:
1. Name the rule as 000-max-priority, 001-notsomax-priority, 002-less-preiority, not-priority
2. [x] Priority field checked (Action: allow)
3. OR Action: deny (not need to check the Priority field in these rules)


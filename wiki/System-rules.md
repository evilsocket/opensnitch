Since v1.3.0-rc.1 you can configure `iptables` rules by editing the file `/etc/opensnitchd/system-fw.json`.

OpenSnitch will ensure that the rules you have configured there are not deleted from the system.

iptables
---

#### Allowing VPN traffic and other things

If you configure the daemon to deny everything that is not specifically allowed by default, many services will be blocked, [like VPNs](https://github.com/gustavo-iniguez-goya/opensnitch/issues/47).

In order to allow this type of traffic, you can add a rule like this (notice that the **Table** is **mangle**):
```
{
    "SystemRules": [
        {
            "Rule": {
                "Description": "Allow pptp VPNs",
                "Table": "mangle",
                "Chain": "OUTPUT",
                "Parameters": "-p gre",
                "Target": "ACCEPT",
                "TargetParameters": ""
            }
        }
    ]
}
```

In this case we allow **GRE traffic** (`-p gre`) to allow **PPTP** connections, or you can allow traffic point to point (`-p udp --dport 1194`). Whatever you can do with iptables.

Besides this, some services like **OpenVPN** uses **ICMP** to keep the tunnel up. Needless to say that [ICMP is very important for network communications](https://tools.ietf.org/html/rfc1191):

```
{
    "SystemRules": [
        {
            "Rule": {
                "Description": "Allow OUTPUT ICMP",
                "Table": "mangle",
                "Chain": "OUTPUT",
                "Parameters": "-p icmp",
                "Target": "ACCEPT",
                "TargetParameters": ""
            }
        }
    ]
}
```

(you can allow only _echo_ and `reply`: `-p icmp --icmp-type echo-request`)

Some more examples:
```
{
    "SystemRules": [
        {
            "Rule": {
                "Description": "",
                "Table": "mangle",
                "Chain": "OUTPUT",
                "Parameters": "-p tcp ! --syn -m conntrack --ctstate NEW",
                "Target": "DROP",
                "TargetParameters": ""
            }
        },
        {
            "Rule": {
                "Description": "",
                "Table": "filter",
                "Chain": "OUTPUT",
                "Parameters": "-m conntrack --ctstate UNTRACKED,INVALID",
                "Target": "DROP",
                "TargetParameters": ""
            }
        },
        {
            "Rule": {
                "Description": "",
                "Table": "mangle",
                "Chain": "PREROUTING",
                "Parameters": "-m conntrack --ctstate INVALID,UNTRACKED",
                "Target": "DROP",
                "TargetParameters": ""
            }
        }
    ]
}
```

The list of protocols you can allow or deny are defined in the file `/etc/protocols`

Intercepting connections from containers
---

In order to intercept connections from containers, you need to select in `Preferences->Nodes->Process monitor method: ebpf`, and add the following rule to `/etc/opensnitchd/system-fw.json`:
```
        {
            "Rule": {
                "Enabled": true,
                "Description": "",
                "Table": "mangle",
                "Chain": "FORWARD",
                "Parameters": "-m conntrack --ctstate NEW",
                "Target": "NFQUEUE",
                "TargetParameters": "--queue-num 0 --queue-bypass"
            }
        }
```

nftables
---

OpenSnitch system rules cannot be used yet with nftables as of v1.4.0, it's scheduled to be added for v1.5.0.

However if you need to use nftables you can combine OpenSnitch interception with the nftables firewall service:

1. Edit `/etc/opensnitchd/default-config.json` and set "Firewall" to "nftables".
2. Edit `/etc/nftables.conf` and add these rules:
```
#!/usr/sbin/nft -f

# docs: https://wiki.nftables.org/wiki-nftables/index.php/Simple_ruleset_for_a_server

# flush ruleset

# inet == ipv4 && ipv6

# the name of the tables and hooks is not random, OpenSnitch adds filter and mangle, and output chains
table inet filter {
    chain input {
        # block by default incoming connections
        type filter hook input priority filter; policy drop;
        
        # allow already established connections
        ct state { established, related } accept
        ct state invalid drop
        
        # allow ssh
        # tcp dport { 22 } accept
    }
}
```
3. Enable nftables service:
`$ sudo systemctl enable nftables`
`$ sudo systemctl start nftables`

---

In future versions you will be able to configure these rules from the GUI, but for now you have to add the rules to the file `/etc/opensnitchd/system-fw.json`.

If you need or want a GUI, or you'd like to have more control on the rules, maybe you should try UFW, FwBuilder and the like.


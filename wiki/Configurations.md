### Daemon configuration (>= v1.7.0)

The file _/etc/opensnitchd/default-config.json_ holds the daemon configuration:

```json
{
  "Server": {
      "Address": "unix:///tmp/osui.sock",
      "LogFile": "/var/log/opensnitchd.log"
      "Authentication": {},
      "Loggers": {}
  },
  "DefaultAction": "deny",
  "DefaultDuration": "once",
  "InterceptUnknown": true,
  "ProcMonitorMethod": "ebpf",
  "LogLevel": 1,
  "LogUTC": false,
  "LogMicro": false,
  "Firewall": "nftables",
  "FwOptions": {
        "ConfigPath": "/etc/opensnitchd/system-fw.json",
        "MonitorInterval": "15s",
        "ActionOnOverflow": "drop"
  },
  "Rules": {
        "Path": "/etc/opensnitchd/rules/",
        "EnableChecksums": true
  },
  "Ebpf": {
        "ModulesPath": "/usr/lib/opensnitchd/ebpf/",
        "EventsWorkers": 8,
        "QueueEventsSize": 0
  },
  "Internal": {
        "GCPercent": 75
  },
  "Stats": {
    "MaxEvents": 150,
    "MaxStats": 25,
    "Workers": 6
  }
}
```

Option     | Value
-----------|------
Server.Address | Unix socket (unix:///tmp/osui.sock, the "unix:///" part is mandatory) or TCP socket (192.168.1.100:50051)
_ |If the address is empty, it won't try to connect to the server (>= v1.7.1).
Server.LogFile | file to write logs to (use /dev/stdout to write logs to standard output)
Server.Authentication | https://github.com/evilsocket/opensnitch/wiki/Nodes-authentication#nodes-authentication-added-in-v161
Server.Loggers | https://github.com/evilsocket/opensnitch/wiki/SIEM-integration
DefaultAction [0] | allow, deny, reject (>= 1.6.6)
_ | Warning: _reject_ option may cause in some services (dnsmasq, sshd, tinyproxy, ...) to enter in an infinite loop. Use it **at your own risk**
~DefaultDuration~ | ~once, always, until restart, 30s, 5m, 15m, 30m, 1h~ DEPRECATED
InterceptUnknown [1] | true, false (see [1] for more information).
_ | Display popups to allow connections not associated with a process. Disabled by default.
ProcMonitorMethod | ebpf, proc, audit
LogLevel | -1 to 4 (trace, debug, info, important, warning, error)
LogUTC | print the logs in UTC format (true, false)
LogMicro | print the logs in microseconds (true, false)
Firewall | "nftables" (default) or "iptables"
Stats.MaxEvents | Max events to send to the GUI every second. If you think that you're missing some connections, increased this value.
Stats.MaxStats | Max stats per item (port, host, IP, process, etc) to keep in the backlog.
Stats.Workers | Max workers to handle the statistics.
Ebpf.ModulesPath (>= v1.6.5) | Alternative location of the eBPF modules (default /usr/lib/opensnitchd/ebpf)
Ebpf.EventsWorkers (>= v1.6.5) | Number of goroutines to handle kernel events (default: 8).
Ebpf.QueueEventsSize (>= v1.6.5) | Max number of events queued. Default 0, meaning that the events will be processed with the available goroutines. If the value is > 0 and the daemon can't handle the events fast enough, they'll be queued. Once the queue is full, queued elements are discarded.
Rules.Path (>= v1.6.5) | Alternative location of to the rules.
Rules.EnableChecksums (>= v1.7.0)| Obtain processes's checksums and allow create rules to filter by them.
FwOptions.ConfigPath (>= v1.7.0) | Alternative path to the firewall configuration (default /etc/opensnitchd/system-fw.json)
FwOptions.MonitorInterval (>= v1.7.0) | Interval time to check that interception rules are loaded. Default "15s", "0s" disables the monitor (value format in time.Duration: https://pkg.go.dev/time#ParseDuration)
Internal.GCPercent (>= v1.7.0)| Option to configure how often the daemon frees up unused memory (https://tip.golang.org/doc/gc-guide#GOGC).
Internal.FlushConnsOnStart | Option to kill established connections whenever the firewall is reloaded / started. Local connections are excluded.

If you change the configuration or the rules under _/etc/opensnitchd/rules/_, they'll be reloaded automatically. No restart is needed.

**[0] NOTE about _DefaultAction_ option**:

When the daemon connects to the GUI, the daemon will use the DefaultAction configured on the GUI.
If the GUI is not connected it'll use the daemon's DefaultAction.

If you set daemon's DefaultAction to `deny`, bear in mind that you'll need [a rule to allow network traffic on localhost](https://github.com/evilsocket/opensnitch/issues/982#issuecomment-1621452594) ([#982](https://github.com/evilsocket/opensnitch/issues/982))

**[1] NOTE about _intercept_unknown_ option**:

 It refers to the connections that are not associated with a process due to several reasons, specially when using _proc_ as monitor method.

 This option was added when OpenSnitch used to miss a lot of connections (couldn't find pid/process in /proc). As of v1.4.0rc2 version, it's safe to set it  to false, and just let it drop those "unknown" connections. It's up to you. Most of the connections intercepted by this option are those in a bad state or similar.

 There're some scenarios where this option is useful/needed though, for example when connecting to VPNs, mount NFS shares or intercepting forwarded connections from containers.

Also as some connections are originated from kernel-space, you need to enable this option in order to allow the outgoing connection.

***

### GUI

By default OpenSnitch UI listens on a local Unix socket in /tmp/osui.sock.

In some distros, /tmp is cleared out every time in a while, so you're encouraged to change it to other location.
Also, this Unix socket should only be readable by the GUI's user.

On latest v.1.6.x version, you can change it to unix:///run/user/1000/opensnitch/osui.sock

![image](https://user-images.githubusercontent.com/2742953/216812535-111ab3ce-ad32-45d5-8d54-c0111b3a2fd2.png)


**Single UI with many computers**

Use `--socket "[::]:50051"` to have the UI use TCP instead of a Unix socket and run the daemon on another computer with `-ui-socket "x.x.x.x:50051"` (where x.x.x.x is the IP of the computer running the UI service).

Remote Daemon-Only Hosts:

`# /usr/bin/opensnitchd -rules-path /etc/opensnitchd/rules -ui-socket x.x.x.x:50051`

Central GUI Host:

`$ /usr/local/bin/opensnitch-ui --socket "[::]:50051"`

Note: When using the commands above the changes will not persist across reboots. Make sure to change the configuration file accordingly.

Persistent Setup:

To keep clients connected after reboot, edit the daemon configuration file at `/etc/opensnitchd/default-config.json`. Change the `Address`
value to the IP and port of the machine running the GUI. Example: `"Address": "10.10.15.20:50051"` where the GUI server is at 10.10.15.20.

Apply the changes with `systemctl restart opensnitch` and enable the service so it starts on boot with  `systemctl enable --now opensnitch`.

On the central GUI server, run the Opensnitch GUI to allow the clients to connect with `opensnitch-ui --socket [::]:50051`.

![image](https://user-images.githubusercontent.com/2742953/82752021-9d328380-9dbb-11ea-913e-80f7b551a6c7.png)

**Configuration**

The GUI saves the changes you make every time you resize the statistics window, or when answering a connection prompt dialog. It'll also remember which tab you clicked the last time.

The size of each column or each tab will also be saved.

It is saved under _$HOME/.config/opensnitch/settings.conf_, and it's handled by the GUI.

![image](https://user-images.githubusercontent.com/2742953/82752761-aa9e3c80-9dc0-11ea-90eb-992a99f0b878.png)

***

**Clarification on how the DefaultAction option works**

- When the daemon is not connected to the GUI, it'll use the DefaultAction configured in /etc/opensnitchd/default-config.json (Default Allow)
- When the daemon is connected to the GUI, the GUI will reconfigure daemon's DefaultAction value with the one defined by the GUI (default Deny).
  This change will only be valid while it's connected to the GUI. The value defined in default-config.json is not modified.



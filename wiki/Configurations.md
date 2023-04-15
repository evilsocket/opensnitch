### Daemon configuration

The file _/etc/opensnitchd/default-config.json_ holds the daemon configuration:

```
{
  "Server": {
      "Address": "unix:///tmp/osui.sock",
      "LogFile": "/var/log/opensnitchd.log"
  }, 
  "DefaultAction":     "deny",
  "DefaultDuration":   "once",
  "InterceptUnknown":   true,
  "ProcMonitorMethod": "proc",
  "LogLevel": 1
  "Firewall": "iptables",
  "Stats": {
    "MaxEvents": 150,
    "MaxStats": 25
  }
}
```

Option | Value
-------|------
Server.Address | Unix socket (unix:///tmp/osui.sock, the "unix:///" part is mandatory) or TCP socket (192.168.1.100:50051)
Server.LogFile | file to write logs to (use /dev/stdout to write logs to standard output)
DefaultAction | allow, deny
~DefaultDuration~ | ~once, always, until restart, 30s, 5m, 15m, 30m, 1h~ DEPRECATED
InterceptUnknown | true, false
ProcMonitorMethod | ebpf, proc, audit
LogLevel | 0 to 4 (debug, info, important, warning, error)
Firewall | "nftables" or "iptables"
Stats.MaxEvents | Max events to send to the GUI every second. If you think that you're missing some connections increased this value.
Stats.MaxStats | Max stats per item (port, host, IP, process, etc) to keep in the backlog.

If you change the configuration or the rules under _/etc/opensnitchd/rules/_, they'll be reloaded. No restart is needed.

**NOTE about _intercept_unknown_ option**:
 It refers to the connections that are not associated with a process due to several reasons, specially when using _proc_ as monitor method.

 This option was added when OpenSnitch used to miss a lot of connections (couldn't find pid/process in /proc). As of v1.4.0rc2 version, it's safe to set it  to false, and just let it drop those "unknown" connections. It's up to you. Most of the connections intercepted by this option are those in a bad state or similar.

 There're some scenarios where this option is useful/needed though, for example when connecting to VPNs or mount NFS shares.
As the connections are originated from kernel-space, you need to enable this option in order to allow the outgoing connection.

***

### GUI

By default OpenSnitch UI listens on a local Unix socket in /tmp/osui.sock.

In some distros, /tmp is cleared out every time in a while, so you're encouraged to change it to other location.
Also, this Unix socket should only be readable by the GUI's user.

On latest v.1.6.x version, you can change it to unix:///run/user/1000/opensnitch/osui.sock

![image](https://user-images.githubusercontent.com/2742953/216812535-111ab3ce-ad32-45d5-8d54-c0111b3a2fd2.png)


**Single UI with many computers**

Use `--socket "[::]:50051"` to have the UI use TCP instead of a Unix socket and run the daemon on another computer with `-ui-socket "x.x.x.x:50051"` (where x.x.x.x is the IP of the computer running the UI service).

`# /usr/bin/opensnitchd -rules-path /etc/opensnitchd/rules -ui-socket 172.17.0.1:50051`

`$ /usr/local/bin/opensnitch-ui --socket "[::]:50051"`

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



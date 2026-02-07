- [Format](#format)
- [Performance / Important notes](#some-considerations)
  * [localhost connections](#localhost-connections)
- [Best practices](#best-practices)
- [For servers](#for-servers)

---

### Format

Rules are stored as JSON files inside the `-rule-path` directory (by default `/etc/opensnitchd/rules`), in its simplest form, a rule looks like this:

```json
{
   "created": "2018-04-07T14:13:27.903996051+02:00",
   "updated": "2018-04-07T14:13:27.904060088+02:00",
   "name": "deny-simple-www-google-analytics-l-google-com",
   "enabled": true,
   "precedence": false,
   "action": "deny",
   "duration": "always",
   "operator": {
     "type": "simple",
     "sensitive": false,
     "operand": "dest.host",
     "data": "www-google-analytics.l.google.com"
   }
}
```

| Field            | Description   |
| -----------------|---------------|
| created          | UTC date and time of creation. |
| update           | UTC date and time of the last update. |
| name             | The name of the rule. |
| enabled          | Enable or disable the rule. |
| precedence       | true or false. Sets if a rule take precedence over the rest (>= v1.2.0)|
| action           | Can be `deny`, `reject` or `allow`. `reject` kills the socket. |
| duration         | The duration of the rule in [Duration format](https://pkg.go.dev/time#ParseDuration). `always` is always used when the rule is written to disk. The rest of the options are temporary, until they reach the deadline: `12h`, `5h`, `1h`, `30s`, or `once` to only run the rule one time.  |
| operator.type    | `simple`, `regexp`, `network`, `lists`, `list`, `range`.|
|| `simple` is a simple `==` comparison.|
|| `regexp` matches the regexp from the `data` field against the connection |
|| `network` checks if the IP of a connection is contained within the specified network range (127.0.0.1/8) |
|| `lists` will look for matches on lists of something (domains, IPs, etc). Typically used to create [blocklists](https://github.com/evilsocket/opensnitch/wiki/block-lists)|
|| `range` (v1.9.0) will check if an Operand (`dest.port` or `source.port`) is within the given range.|
|| `list`, a combination of all of the previous types.|
| operator.data    | The data of the rule against which an outbound connection will be compared: an IP, a destination port, a command line, etc. |
| operator.operand | Property of the connection against which the rule will be compared: |
| | `true` - will always match |
| | `process.path`  - the absolute path of the executable |
| | `process.id` PID of the process|
| | `process.command` (full command line, including path and arguments). Note that cmdlines can contain or not the process name, and the path can be absolute or relative (`./cmd -x a`).|
| | `process.parent.path` (v1.7.0) check against ONE of the parent path. Include more parent paths to match the tree of a process. |
| | `provess.env.ENV_VAR_NAME` (use the value of an environment variable of the process given its name). |
| | `process.hash.md5` (v1.7.0) - verify the checksum of an executable |
| | `user.id` - UID |
| | `user.name` user name (v1.7.0). Check against a regular system username (no namespaces, containers or virtual user names).|
| | `protocol` - TCP, UDP, UDPLITE, ...|
| | `source.port` |
| | `source.ip` |
| | `source.network` |
| | `dest.ip` |
| | `dest.host` |
| | `dest.network` (v1.3.0) - you can use a network range, or the constants predefined in the file https://github.com/evilsocket/opensnitch/blob/master/daemon/data/network_aliases.json |
| | `dest.port` |
| | `iface.in` (v1.6.0) |
| | `iface.out` (v1.6.0) |
| | `lists.domains` (v1.4.0) lists of domains in hosts format [read more](https://github.com/evilsocket/opensnitch/wiki/block-lists)|
| | `lists.domains_regexp` (v1.5.0) list of domains with regular expressions (`.*\.example\.com`) [read more](https://github.com/evilsocket/opensnitch/wiki/block-lists) ⚠️! Don't use more than 300 regexps, it'll eat all the memory. |
| | `lists.ips` (v1.5.0) list of IPs [read more](https://github.com/evilsocket/opensnitch/wiki/block-lists)|
| | `lists.nets` (v1.5.0) list of network ranges [read more](https://github.com/evilsocket/opensnitch/wiki/block-lists)|
| | `lists.hash.md5` (v1.7.0) list of md5s |

### Some considerations

 All the fields you select when defining a rule will be used to match connections, for example:
 - Rule: allow -> port 443 -> Dst IP 1.1.1.1 -> Protocol TCP -> Host www.site.test
   * This rule will match connections to port 443 __AND__ IP 1.1.1.1 __AND__ protocol TCP __AND__ host www.site.test
   * connections to IP 2.2.2.2 won't match, connections to port 80 won't match, etc...

 - Rule: allow -> port 53 ->  [x] domains list -> [x] network ranges list
   * This rule will match connections to port 53 __AND__ domains in the list __AND__ IPs in the network ranges list
 - Rule: allow -> port ^(53|80|443)$ -> UID 1000 -> Path /app/bin/test -> [x] domains list
   * This rule will match connections to ports (53 __OR__ 80 __OR__ 443) __AND__ UID 1000 __AND__ Path /app/bin/test __AND__ domains in the specified.

- If you select multiple lists on the same rule, bear in mind that all the lists must match in order to apply an action:
 [Read this disccussion to learn more](https://github.com/evilsocket/opensnitch/discussions/877#discussioncomment-5247997)

Rule precedence: When a connection is attempted, OpenSnitch evaluates each of the enabled rules. The rules are sorted in the alphabetical order of rule names (since v.1.2.0). OpenSnitch goes through the list and as soon as it encounters a  Deny/Reject rule or an _Important_ ([x] Priority) rule (since v1.2.0) that matches the connection, that rule will be immediately selected as the effective rule. If no such rule is found, then the last non-Important Allow rule that matched will be selected. If no rule matched, it shows a pop-up dialogue, or applys the default action if that's not possible.

- In the following example, the Deny rule takes precedence over the Allow rules:
```
000-allow-chrome-to-specific-domains
001-allow-not-so-important-rule
001-deny-chrome
```

- In the following example, the first Allow rule takes precedence because it is set to Priority and it comes first in the alphabetical order:
```
000-allow-chrome-to-specific-domains [x] Priority
001-allow-not-so-important-rule
001-deny-chrome
```

This way you can not only prioritize critical connections (like VPNs), but also gain performance.

**More on rules performance**

As already mentioned, the order of rules is critical. If you use Firefox and prioritize Allow rules to allow Firefox's connections, web navegation will be faster.

But the type of rule also impacts the rule's performance. `regexp` and `list` types are slower than `simple` because `regexp` and `list` types check multiple parameters while simple rules check just one. And `regexp` is the slowest, because is the more complex type.

---

An example with a regular expression:

```json
{
   "created": "2018-04-07T14:13:27.903996051+02:00",
   "updated": "2018-04-07T14:13:27.904060088+02:00",
   "name": "deny-any-google-analytics",
   "enabled": true,
   "precedence": false,
   "action": "deny",
   "duration": "always",
   "operator": {
     "type": "regexp",
     "sensitive": false,
     "operand": "dest.host",
     "data": "(?i)
   }
}
```

An example whitelisting a process path:

```json
{
   "created": "2018-04-07T15:00:48.156737519+02:00",
   "updated": "2018-04-07T15:00:48.156772601+02:00",
   "name": "allow-simple-opt-google-chrome-chrome",
   "enabled": true,
   "precedence": false,
   "action": "allow",
   "duration": "always",
   "operator": {
     "type": "simple",
     "sensitive": false,
     "operand": "process.path",
     "data": "/opt/google/chrome/chrome"
   }
 }
```

Example of a complex rule using the operator _list_, saved from the GUI (Note: version v1.2.0):
```
{
  "created": "2020-02-07T14:16:20.550255152+01:00",
  "updated": "2020-02-07T14:16:20.729849966+01:00",
  "name": "deny-list-type-simple-operand-destip-data-1101-type-simple-operand-destport-data-23-type-simple-operand-userid-data-1000-type-simple-operand-processpath-data-usrbintelnetnetkit",
  "enabled": true,
  "precedence": false,
  "action": "deny",
  "duration": "always",
  "operator": {
    "type": "list",
    "operand": "list",
    "list": [
      {
        "type": "simple",
        "operand": "dest.ip",
        "sensitive": false,
        "data": "1.1.0.1",
        "list": null
      },
      {
        "type": "simple",
        "operand": "dest.port",
        "sensitive": false,
        "data": "23",
        "list": null
      },
      {
        "type": "simple",
        "operand": "user.id",
        "sensitive": false,
        "data": "1000",
        "list": null
      },
      {
        "type": "simple",
        "operand": "process.path",
        "sensitive": false,
        "data": "/usr/bin/telnet.netkit",
        "list": null
      }
    ]
  }
}
```

### localhost connections

Some applications have components that communicate in localhost. For example KDE uses `kdeinit5` and `kwin`, Xfce and others use `xbrlapi` , and GnuPG `dirmngr`.
If you change daemon's default action to `deny` these applications will stop working. For example you may notice a delay login to the Desktop Environment (See issues #982 and #965 for more information).

The solution is to allow either localhost connections, or these binaries in particular.

Here's a rule to allow localhost connections:
```json
{
  "created": "2023-07-05T10:46:47.904024069+01:00",
  "updated": "2023-07-05T10:46:47.921828104+01:00",
  "name": "000-allow-localhost",
  "enabled": true,
  "precedence": true,
  "action": "allow",
  "duration": "always",
  "operator": {
    "type": "network",
    "operand": "dest.network",
    "sensitive": false,
    "data": "127.0.0.0/8",
    "list": []
  }
}
```

If you want to restrict it further, under the `Addresses` tab you can review what binaries established localhost connections, and then add the absolute path to the rule + destination port.

### Best practices

- Allow DNS queries only to your configured DNS nameservers:

  ⚠️ DNS protocol can be used to exfiltrate information from local networks.
  * Allow `systemd-resolved`, `dnsmasq`, `dnscrypt-proxy`, etc, to connect only to your DNS nameservers + port 53  + UID.
  * Besides allowing connections to remote DNS servers (9.9.9.9 for example), you may need to allow connections to localhost IPs (127.0.0.1, etc)
  * If you already allowed these stub resolvers, the easiest way would we to delete the existing rule, let it ask you again to allow/deny it, click on the `[+]` button and then select from the pop-up `from this command line` __AND__ to IP x.x.x.x __AND___ to port xxx


- Limit what an application can do as much as possible:
  * Filter by executable + command line: You don't want to allow `curl` or `wget` system wide. Instead, allow only a particular command line, for example:

    command launched: `$ wget https://mirror.karneval.cz/pub/linux/fedora/linux/releases/34/Workstation/x86_64/iso/Fedora-Workstation-Live-x86_64-34-1.2.iso`

    Instead of allowing `from this executable: wget`, use allow `from this executable` + `from this command line`

    You can narrow it further, by allowing `from this command line` + `from this User ID` + `to this IP` + `to this port`

- Don't allow `python3`, `perl` or `ruby` binaries system-wide:
  * As explained above, filter by executable + command line + (... more parameters ...)
    If you allow `python3`for example, you'll allow ANY `python3` script, so be careful.

    https://github.com/evilsocket/opensnitch/wiki/Rules-examples#filtering-python-scripts-applicable-to-java-and-others-interpreters

- Disable unprivileged namespaces to prevent rules bypass

  If `/proc/sys/kernel/unprivileged_userns_clone` is set to 1, change it to 0. Until we obtain the checksum of a binary, it's better to set it to 0.

### For servers

 These recommendations also apply to the Linux Desktop, but are specially important on servers.
 
 Why? If someone gets access to the system, usually there're a few directories where everyone can write files: `/tmp`, `/var/tmp` or `/dev/shm`.
 Thus these directories are usually used to drop malicious files or download remote binaries to escalate privileges, mine cryptocoins, etc.

 Usually the attackers use `wget`, `curl` or `bash` to establish outbound connections ([malware examples](https://github.com/evilsocket/opensnitch/discussions/1119)). So, if you don't need these binaries, just uninstall them.

There're two approaches to secure a server with OpenSnitch:

1) restrict everything by default (`DefaultAction` set to deny/reject in the `default-config.json` file) and allow only system binaries and needed apps. Incoming connections will keep working, but NEW outbound connections will be denied.
2) allow everything by default, and deny connections from specific locations, or by binary / destination.


- If you need curl or wget and the `DefaultAction` is not `allow`, restrict their outbound connections as much as possible (this practice applies to any other binary of the server):

  ```json
  {
  "created": "2020-02-07T14:16:20.550255152+01:00",
  "updated": "2020-02-07T14:16:20.729849966+01:00",
  "name": "allow-curl-net-proxy",
  "description": "allow curl only to 10.168.10.164 on port 8081",
  "enabled": true,
  "precedence": false,
  "action": "allow",
  "duration": "always",
  "operator": {
    "type": "list",
    "operand": "list",
    "list": [
      {
        "type": "simple",
        "operand": "process.path",
        "sensitive": false,
        "data": "/usr/bin/curl",
        "list": null
      },
      {
        "type": "simple",
        "operand": "dest.ip",
        "sensitive": false,
        "data": "10.168.10.164",
        "list": null
      },
      {
        "type": "simple",
        "operand": "dest.port",
        "sensitive": false,
        "data": "8081",
        "list": null
      }
    ]
   }
  }
  ```

  Or for example you can allow everything only to the local lan, and let the rest of outbound connections be denied by the DefaultAction:
  ```json
  {
  "created": "2023-05-20T20:39:33.765468194+02:00",
  "updated": "2023-05-20T20:39:33.7655761+02:00",
  "name": "000-allow-lan",
  "description": "",
  "enabled": true,
  "precedence": true,
  "nolog": false,
  "action": "allow",
  "duration": "always",
  "operator": {
    "type": "network",
    "operand": "dest.network",
    "sensitive": false,
    "data": "LAN",
    "list": []
   }
  }
  ```

- When the `DefaultAction` is `allow`, don't allow connections opened by binaries located under certain directories: `/dev/shm`, `/tmp`, `/var/tmp` or `/memfd`:

  There're ton of examples (more common on servers than on the desktop):

  [Collection of Linux malware payloads](https://github.com/evilsocket/opensnitch/discussions/1119)

  https://github.com/timb-machine/linux-malware

  ```
  (*) Deny
  [x] From this executable: ^(/memfd|/tmp/|/var/tmp/|/dev/shm/|/var/run|/var/lock).*
  ```

  /etc/opensnitchd/rules/000-deny-tmp.json:
  ```json
  {
  "created": "2025-04-26T09:58:03.704090244+02:00",
  "updated": "2025-04-26T09:58:03.704216578+02:00",
  "name": "000-deny-tmp",
  "enabled": true,
  "precedence": true,
  "action": "reject",
  "duration": "always",
  "operator": {
    "type": "regexp",
    "operand": "process.path",
    "sensitive": false,
    "data": "^(/var/tmp|/dev|/memfd|/tmp).*",
    "list": []
    }
  }
  ```

- You can also block outbound connections to crypto mining pools and malware domains/ips with [blocklists rules](https://github.com/evilsocket/opensnitch/wiki/block-lists).

  One of the common reason to compromise servers is to mine cryptos. Denying connections to the mining pools, disrupts the operation.

  **Note** that the default policy should be deny everything unless explicitely allowed. But by creating a rule to deny specifically these directories, you can have a place where to monitor these executions.


### Rules format

Rules are stored as JSON files inside the `-rule-path` folder, in the simplest case a rule looks like this:

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
| enabled          | Use to temporarily disable and enable rules without moving their files. |
| precedence       | true or false. Sets if a rule take precedence (>= v1.2.0)|
| action           | Can be `deny` or `allow`. |
| duration         | For rules persisting on disk, this value is default to `always`. |
| operator.type    | Can be `simple`, in which case a simple `==` comparison will be performed, or `regexp` if the `data` field is a regular expression to match. |
| operator.operand | What element of the connection to compare, can be one of: |
| |* `true` (will always match) |
| |* `process.path` (the path of the executable) |
| |* `process.id` PID|
| |* `process.command` (full command line, including path and arguments)|
| |* `provess.env.ENV_VAR_NAME` (use the value of an environment variable of the process given its name)
| |* `user.id` (UID)|
| |* `protocol`|
| |* `dest.ip` |
| |* `dest.host` |
| |* `dest.network` (>= v1.3.0)|
| |* `dest.port` |
| |* `lists.domains` (>= 1.4.0) lists of domains in hosts format [read more](https://github.com/evilsocket/opensnitch/wiki/block-lists)|
| |* `lists.domains_regexp` (>= 1.5.0) list of domains with regular expressions (`.*\.example\.com`) [read more](https://github.com/evilsocket/opensnitch/wiki/block-lists)|
| |* `lists.ips` (>= 1.5.0) list of IPs [read more](https://github.com/evilsocket/opensnitch/wiki/block-lists)|
| |* `lists.nets` (>= 1.5.0) list of network ranges [read more](https://github.com/evilsocket/opensnitch/wiki/block-lists)|
| operator.data    | The data to compare the `operand` to, can be a regular expression if `type` is `regexp`, or a path to a directory with list of IPs/domains in the case of `lists`. |

### Some considerations
 
By default Deny rules take precedence over the rest of the rules. If a connection match a Deny rule, opensnitch won't continue evaluating rules.

Since v1.2.0, rules are sorted and checked in alphabetical order. You can name them this way to prioritize Deny rules, for example: 
```
000-allow-very-important-rule
001-allow-not-so-important-rule
001-deny-xxx
```
Also since v1.2.0, you can configure a rule as _Important_ ([x] Priority) to take precedence over the rest of the rules. If you set this flag and name the rule as mentoned above, you can also prioritize Allow rules.

This way you can not only prioritize critical connections (like VPNs), but also gain performance.

**More on rules performance**

As already mentioned, the order of the rule is critical. If you prioritize Firefox the web navegation will be faster.

But the type of rule also impacts the rules performance. `regexp` and `list` types are slower than `simple`, in the end, `regexp` and `list` types check multiple parameters while simple rules check just one.

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
    "data": "[{\"type\": \"simple\", \"operand\": \"dest.ip\", \"data\": \"1.1.0.1\"}, {\"type\": \"simple\", \"operand\": \"dest.port\", \"data\": \"23\"}, {\"type\": \"simple\", \"operand\": \"user.id\", \"data\": \"1000\"}, {\"type\": \"simple\", \"operand\": \"process.path\", \"data\": \"/usr/bin/telnet.netkit\"}]",
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

### Best practices

- Limit what an application can do as much as possible:
  * Filter by executable + command line: You don't want to allow curl or wget system wide. Instead allow only a particular command line, for example:
  
    command launched: `$ wget https://mirror.karneval.cz/pub/linux/fedora/linux/releases/34/Workstation/x86_64/iso/Fedora-Workstation-Live-x86_64-34-1.2.iso`
    
    Instead of allowing `from this executable: wget`, use allow `from this executable` + `from this command line`

    You can narrow it further, by allowing `from this command line` + `from this User ID` + `to this IP` + `to this port`

- Disable unprivileged namespaces to prevent rules bypass

  If /proc/sys/kernel/unprivileged_userns_clone is set to 1, change it to 0. Until we obtain the checksum of a binary, it's better to set it to 0.
  
  
  
  

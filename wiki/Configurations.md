### Daemon configuration
Some default working options can be customized in the file _/etc/opensnitchd/default-config.json_:

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
}
```
 * Address: Unix socket (unix:///tmp/osui.sock, the "unix:///" part is mandatory) or TCP socket (192.168.1.100:50051)
 * DefaultAction: allow | deny
 * DefaultDuration: once | always | until restart | 30s | 5m | 15m | 30m | 1h
 * InterceptUnknown: true | false
   - Block or allow connections whose process path has not been found.
 * ProcMonitorMethod: proc | ftrace | audit
 * LogLevel: 0 to 4 (debug, info, important, warning, error)

If you change the configuration or the rules under _/etc/opensnitchd/_, they'll be reloaded. No restart is needed.

**NOTE about _intercept_unknown_ option**: It was added when OpenSnitch used to miss a lot of connections (couldn't find pid/process in /proc). As of v1.0.0rc5 version, maybe it's safe to set it to false, and just let drop those unknown spare connections. It's up to you.

***

### GUI

By default OpenSnitch UI listen in a local Unix socket in /tmp/osui.sock.

In some distros, /tmp is cleared out every time in a while, so you're encouraged to change it to other location.

**Single UI with many computers**

Use --socket "[::]:50051" to have the UI use TCP instead of a Unix socket and run the daemon on another computer with -ui-socket "x.x.x.x:50051" (where x.x.x.x is the IP of the computer running the UI service).

`# /usr/bin/opensnitchd -rules-path /etc/opensnitchd/rules -ui-socket 172.17.0.1:50051`

`$ /usr/local/bin/opensnitch-ui --socket "[::]:50051"`

![image](https://user-images.githubusercontent.com/2742953/82752021-9d328380-9dbb-11ea-913e-80f7b551a6c7.png)

**Configuration**

The GUI saves the changes you make every time you resize the statistics window, or when answering a connection prompt dialog. It'll also remember which tab you clicked the last time.

The size of each column of each tab will also be saved.

It is saved under _$HOME/.config/opensnitch/settings.conf_, and it's handled by the GUI.

![image](https://user-images.githubusercontent.com/2742953/82752761-aa9e3c80-9dc0-11ea-90eb-992a99f0b878.png)

***


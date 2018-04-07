<p align="center">
  <img alt="opensnitch" src="https://raw.githubusercontent.com/evilsocket/opensnitch/master/ui/res/icon.png" height="160" />
  <p align="center">
    <a href="https://github.com/evilsocket/opensnitch/releases/latest"><img alt="Release" src="https://img.shields.io/github/release/evilsocket/opensnitch.svg?style=flat-square"></a>
    <a href="https://github.com/evilsocket/opensnitch/blob/master/LICENSE.md"><img alt="Software License" src="https://img.shields.io/badge/license-GPL3-brightgreen.svg?style=flat-square"></a>
    <a href="https://goreportcard.com/report/github.com/evilsocket/opensnitch/daemon"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/evilsocket/opensnitch/daemon?style=flat-square"></a>
  </p>
</p>

**OpenSnitch** is a GNU/Linux port of the Little Snitch application firewall. 

<p align="center">
  <img src="https://raw.githubusercontent.com/evilsocket/opensnitch/master/screenshot.png" alt="OpenSnitch"/>
</p>

### Daemon

The `daemon` is implemented in Go and needs to run as root in order to interact with the Netfilter packet queue, edit 
iptables rules and so on, in order to compile it you will need to install the `libpcap-dev` and `libnetfilter-queue-dev`
libraries on your system, then just:

    cd daemon
    go build .

### Qt5 UI

The user interface is a python script running as a `gRPC` server on a unix socket, to order to install its dependencies:

    cd ui
    pip install -r requirements.txt

### Running

First, you need to decide in which folder opensnitch rules will be saved, it is suggested that you just:

    mkdir -p ~/.opensnitch/rules

Now run the daemon:

    sudo /path/to/daemon -ui-socket unix:///tmp/osui.sock -rules-path ~/.opensnitch/rules

And the UI service as your user:

    python /path/to/ui/main.py --socket unix:///tmp/osui.sock

You can also use `--socket "[::]:50051"` to have the UI use TCP instead of a unix socket and run the daemon on another
computer with `-ui-socket "x.x.x.x:50051"` (where `x.x.x.x` is the IP of the computer running the UI service).

### How rules look like

Simple case:

```json
{
   "created": "2018-04-07T14:13:27.903996051+02:00",
   "updated": "2018-04-07T14:13:27.904060088+02:00",
   "name": "deny-simple-www-google-analytics-l-google-com",
   "enabled": true,
   "action": "deny",
   "duration": "always",
   "operator": {
     "type": "simple",
     "operand": "dest.host",
     "data": "www-google-analytics.l.google.com"
   }
}
```

With a regular expression:

```json
{
   "created": "2018-04-07T14:13:27.903996051+02:00",
   "updated": "2018-04-07T14:13:27.904060088+02:00",
   "name": "deny-any-google-analytics",
   "enabled": true,
   "action": "deny",
   "duration": "always",
   "operator": {
     "type": "regexp",
     "operand": "dest.host",
     "data": "(?i).*analytics.*\.google\.com"
   }
}
```

### FAQ

##### Why Qt and not GTK?

I tried, but for very fast updates it failed bad on my configuration (failed bad = SIGSEGV), moreover I find Qt5 layout system superior and easier to use.

##### Why gRPC and not DBUS?

The UI service is able to use a TCP listener instead of a UNIX socket, that means the UI service itself can be executed on any 
operating system, while receiving messages from a single local daemon instance or multiple instances from remote computers in the network,
therefore DBUS would have made the protocol and logic uselessly GNU/Linux specific.

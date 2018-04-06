<p align="center">
  <img alt="opensnitch" src="https://raw.githubusercontent.com/evilsocket/opensnitch/master/ui/res/icon.png" height="160" />
  <p align="center">
    <a href="https://github.com/evilsocket/opensnitch/releases/latest"><img alt="Release" src="https://img.shields.io/github/release/evilsocket/opensnitch.svg?style=flat-square"></a>
    <a href="https://github.com/evilsocket/opensnitch/blob/master/LICENSE.md"><img alt="Software License" src="https://img.shields.io/badge/license-GPL3-brightgreen.svg?style=flat-square"></a>
    <a href="https://goreportcard.com/report/github.com/evilsocket/opensnitch/daemon"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/evilsocket/opensnitch/daemon?style=flat-square"></a>
  </p>
</p>

**OpenSnitch** is a GNU/Linux port of the Little Snitch application firewall. 

<iframe width="100%"" src="https://www.youtube.com/embed/UjRYdusvXik?rel=0&amp;controls=0&amp;showinfo=0" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen></iframe>

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

    sudo /path/to/daemon -ui-socket-path /tmp/osui.sock -rules-path ~/.opensnitch/rules

And the UI service as your user:

    python /path/to/ui/main.py --socket /tmp/osui.sock

### FAQ

##### Why Qt and not GTK?

I tried, but for very fast updates it failed bad on my configuration (failed bad = SIGSEGV), moreover I find Qt5 layout system superior and easier to use.

##### Why gRPC and not DBUS?

At some point the UI service will also be able to use a TCP listener, at that point the UI itself can be executed on any 
operating system, while receiving messages from a single local daemon instance or multiple instances from remote computers in the network,
therefore DBUS would have made the protocol and logic uselessly GNU/Linux specific.

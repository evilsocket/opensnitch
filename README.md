# OpenSnitch

OpenSnitch is a GNU/Linux port of the Little Snitch application firewall. 

<p align="center">
  <img src="https://raw.githubusercontent.com/evilsocket/opensnitch/master/screenshot.png" alt="OpenSnitch"/>
</p>

**Warning: This is still alpha quality software, don't rely on it (yet) for your computer security.**

### Download / Setup
In order to obtain all the dependent libraries needed to build the daemon in go, you need to checkout the repository us$
You may need to update the second command if you have changed the default location of your go path.

    go get -v github.com/evilsocket/opensnitch/...
    cd ~/go/src/github.com/evilsocket/opensnitch

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

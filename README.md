<p align="center">
  <img alt="opensnitch" src="https://raw.githubusercontent.com/evilsocket/opensnitch/master/ui/opensnitch/res/icon.png" height="160" />
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

**THIS SOFTWARE IS WORK IN PROGRESS, DO NOT EXPECT IT TO BE BUG FREE AND DO NOT RELY ON IT FOR ANY TYPE OF SECURITY.**

### TL;DR

Make sure you have a correctly configured **Go >= 1.8** environment, that the `$GOPATH` environment variable is defined and then:

```bash
# install dependencies
sudo apt-get install git libnetfilter-queue-dev libpcap-dev protobuf-compiler python3-pip
go get github.com/golang/protobuf/protoc-gen-go
go get -u github.com/golang/dep/cmd/dep
cd $GOPATH/src/github.com/golang/dep
./install.sh
export PATH=$PATH:$GOPATH/bin
python3 -m pip install --user grpcio-tools
# clone the repository (ignore the message about no Go files being found)
go get github.com/evilsocket/opensnitch
cd $GOPATH/src/github.com/evilsocket/opensnitch
# compile && install
make
sudo make install
# enable opensnitchd as a systemd service and start the UI
sudo systemctl enable opensnitchd
sudo service opensnitchd start
opensnitch-ui
```

### Daemon

The `daemon` is implemented in Go and needs to run as root in order to interact with the Netfilter packet queue, edit 
iptables rules and so on, in order to compile it you will need to install the `protobuf-compiler`, `libpcap-dev` and `libnetfilter-queue-dev`
packages on your system, then just:

    cd daemon
    make

You can then install it as a systemd service by doing:

    sudo make install

The new `opensnitchd` service will log to `/var/log/opensnitchd.log`, save the rules inside `/etc/opensnitchd/rules` and connect to the default UI service socket `unix:///tmp/osui.sock`.

### UI

The user interface is a Python 3 software running as a `gRPC` server on a unix socket, to order to install its dependencies:

    cd ui
    sudo pip3 install -r requirements.txt

You will also need to install the package `python-pyqt5` for your system (if anyone finds a way to make this work from 
the `requirements.txt` file feel free to send a PR).

The UI is pip installable itself:

    sudo pip3 install .

This will install the `opensnitch-ui` command on your system (you can auto startup it by `cp opensnitch_ui.desktop ~/.config/autostart/`).
  
#### UI Configuration

By default the UI will load its configuration from `~/.opensnitch/ui-config.json` (customizable with the `--config` argument), the 
default contents of this file are:

```json
{
	"default_timeout": 15,
	"default_action": "allow",
	"default_duration": "until restart"
}
```

The `default_timeout` is the number of seconds after which the UI will take its default action, the `default_action` can be `allow` or `deny`
and the `default_duration`, which indicates for how long the default action should be taken, can be `once`, `until restart` or `always` to
persist the action as a new rule on disk.

### Running

Once you installed both the daemon and the UI, you can enable the `opensnitchd` service to run at boot time:

    sudo systemctl enable opensnitchd

And run it with:

    sudo service opensnitchd start

While the UI can be started just by executing the `opensnitch-ui` command.

#### Single UI with many computers

You can also use `--socket "[::]:50051"` to have the UI use TCP instead of a unix socket and run the daemon on another
computer with `-ui-socket "x.x.x.x:50051"` (where `x.x.x.x` is the IP of the computer running the UI service).

### Rules

Rules are stored as JSON files inside the `-rule-path` folder, in the simplest cast a rule looks like this:

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

| Field            | Description   |
| -----------------|---------------|
| created          | UTC date and time of creation. |
| update           | UTC date and time of the last update. |
| name             | The name of the rule. |
| enabled          | Use to temporarily disable and enable rules without moving their files. |
| action           | Can be `deny` or `allow`. |
| duration         | For rules persisting on disk, this value is default to `always`. |
| operator.type    | Can be `simple`, in which case a simple `==` comparison will be performed, or `regexp` if the `data` field is a regular expression to match. |
| operator.operand | What element of the connection to compare, can be one of: `true` (will always match), `process.path` (the path of the executable), `process.command` (full command line, including path and arguments), `provess.env.ENV_VAR_NAME` (use the value of an environment variable of the process given its name), `user.id`, `dest.ip`, `dest.host` or `dest.port`. |
| operator.data    | The data to compare the `operand` to, can be a regular expression if `type` is `regexp`. |

An example with a regular expression:

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
     "data": "(?i).*analytics.*\\.google\\.com"
   }
}
```

An example whitelisting a whole process:

```json
{
   "created": "2018-04-07T15:00:48.156737519+02:00",
   "updated": "2018-04-07T15:00:48.156772601+02:00",
   "name": "allow-simple-opt-google-chrome-chrome",
   "enabled": true,
   "action": "allow",
   "duration": "always",
   "operator": {
     "type": "simple",
     "operand": "process.path",
     "data": "/opt/google/chrome/chrome"
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

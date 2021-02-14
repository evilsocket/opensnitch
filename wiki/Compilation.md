### Installation from sources

(tested on Debian sid and Ubuntu 20. It may fail on other distributions.)

Make sure you have a correctly configured **Go >= 1.13** environment (it also may work with >= 1.11), that the `$GOPATH` environment variable is defined and then:

```bash
# install dependencies
sudo apt-get install git golang libnetfilter-queue-dev libpcap-dev protobuf-compiler python3-pip pyqt5-dev-tools
go get github.com/golang/protobuf/protoc-gen-go
export GOPATH=~/go #you may want to change this if your Go directory is different
export PATH=$PATH:$GOPATH/bin
python3 -m pip install --user grpcio-tools
# clone the repository (ignore the message about no Go files being found)
go get github.com/gustavo-iniguez-goya/opensnitch
cd $GOPATH/src/github.com/gustavo-iniguez-goya/opensnitch
# compile && install
make
sudo make install
# enable opensnitchd as a systemd service and start the UI
sudo systemctl enable opensnitchd
sudo service opensnitchd start
opensnitch-ui
```

**Daemon**

The `daemon` is implemented in Go and needs to run as root in order to interact with the Netfilter packet queue, edit 
iptables rules and so on, in order to compile it you will need to install the `protobuf-compiler`, `libpcap-dev` and `libnetfilter-queue-dev`
packages on your system, then just:

    cd daemon
    make

You can then install it as a systemd service by doing:

    sudo make install

The new `opensnitchd` service will log messages to `/var/log/opensnitchd.log`, save the rules under `/etc/opensnitchd/rules` and connect to the default UI service socket `unix:///tmp/osui.sock`.

As of v1.0.0-rc2 version, it has been tested on Debian >= 8, Ubuntu >= 14, Fedora >= 23, MXLinux 19, Arch, and OpenSuse 15/Tumbleweed.


***


### UI

**Note:** If you run into troubles installing the UI from the sources, either use the deb/rpm packages to resolve the dependencies or install the needed packages from your distribution package manager (especially pyqt5).

The user interface is a Python 3 software running as a `gRPC` server on a unix socket, in order to install its dependencies type the following:

    cd ui
    sudo pip3 install -r requirements.txt

**Tip 1:** If pip fails installing pyqt5, try changing the pyqt5 version in `requirements.txt` to install pyqt5==5.10 or other version that work for you.

**Tip 2:** On newer distros, you may need to upgrade pip (`pip3 install --upgrade --user pip`) [#305](https://github.com/evilsocket/opensnitch/issues/305)

The UI is pip installable itself:

    sudo pip3 install .

This will install the `opensnitch-ui` command on your system (you can auto startup it by `cp opensnitch_ui.desktop ~/.config/autostart/`).
  


***

### Running

Once you installed both the daemon and the UI, you can enable the `opensnitchd` service to run at boot time:

    sudo systemctl enable opensnitchd

And run it with:

    sudo service opensnitchd start

While the UI can be started just by executing the `opensnitch-ui` command.

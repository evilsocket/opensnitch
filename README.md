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

### Installation

Please, refer to the [documentation](https://github.com/gustavo-iniguez-goya/opensnitch/wiki) for detailed information

### FAQ

##### Why Qt and not GTK?

I tried, but for very fast updates it failed bad on my configuration (failed bad = SIGSEGV), moreover I find Qt5 layout system superior and easier to use.

##### Why gRPC and not DBUS?

The UI service is able to use a TCP listener instead of a UNIX socket, that means the UI service itself can be executed on any 
operating system, while receiving messages from a single local daemon instance or multiple instances from remote computers in the network,
therefore DBUS would have made the protocol and logic uselessly GNU/Linux specific.

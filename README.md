# OpenSnitch

OpenSnitch is a GNU/Linux port of the Little Snitch application firewall.

<p align="center">
  <img src="https://raw.githubusercontent.com/evilsocket/opensnitch/master/screenshot.png" alt="OpenSnitch"/>
</p>

**Warning: This is still alpha quality software, don't rely on it (yet) for your computer security.**

## Requirements

You'll need a GNU/Linux distribution with `iptables`, `NFQUEUE` and `ftrace` kernel support.

## Install

    sudo apt-get install build-essential python-dev python-setuptools libnetfilter-queue-dev python-qt4
    cd opensnitch
    sudo python setup.py install

## Run

    sudo opensnitch

## How Does It Work

OpenSnitch is an application level firewall, meaning then while running, it will detect and alert the user for every outgoing connection applications he's running are creating. This can be extremely **effective to detect and block unwanted connections** on your system that might be caused by a security breach, **causing data exfiltration to be much harder for an attacker**.
In order to do that, OpenSnitch relies on `NFQUEUE`, an `iptables` target/extension which allows an userland software to intercept IP packets and either `ALLOW` or `DROP` them, once started it'll install the following iptables rules:

    OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass 

This will use `conntrack` iptables extension to pass all newly created connection packets to NFQUEUE number 0 (the one OpenSnitch is listening on), and then:

    INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass

This will also redirect DNS queries to OpenSnitch, allowing the software to perform and IP -> hostname resolution without performing active DNS queries itself.

Once a new connection is detected, the software relies on the `ftrace` kernel extension in order to track which PID (therefore which process) is creating the connection.

If `ftrace` is not available for your kernel, OpenSnitch will fallback using the `/proc` filesystem, even if this method will also work, it's vulnerable to application path manipulation as [described in this issue](https://github.com/evilsocket/opensnitch/issues/12), therefore **it's highly suggested to run OpenSnitch on a ftrace enabled kernel**.

## TODOs

    grep -r TODO opensnitch | cut -d '#' -f 2 | sort -u

## License

This project is copyleft of [Simone Margaritelli](http://www.evilsocket.net/) and released under the GPL 3 license.

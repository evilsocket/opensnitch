# OpenSnitch

OpenSnitch is a GNU/Linux port of the Little Snitch application firewall.

**Warning: This is still alpha quality software, don't rely on it (yet) for your computer security.**

<center>
  <img src="https://raw.githubusercontent.com/evilsocket/opensnitch/master/screenshot.png" alt="OpenSnitch"/>
</center>

## Install

    sudo apt-get install build-essential python-dev python-setuptools libnetfilter-queue-dev python-qt4
    cd opensnitch
    sudo python setup.py install

## Run

    sudo opensnitch

## TODOs

    grep -r TODO opensnitch | cut -d '#' -f 2 | sort -u

## Known Limitations

As [pointed out in this thread](https://github.com/evilsocket/opensnitch/issues/12), OpenSnitch relies on the `/proc` filesystem in order to link a connection to a process. Being this information relatively easy to manipulate by an attacker, the path and the list of arguments shown in the UI might not match the real
context of the process.

## License

This project is copyleft of [Simone Margaritelli](http://www.evilsocket.net/) and released under the GPL 3 license.

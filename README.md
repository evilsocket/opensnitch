# OpenSnitch

OpenSnitch is a GNU/Linux port of the Little Snitch application firewall.

<p align="center">
  <img src="https://raw.githubusercontent.com/evilsocket/opensnitch/master/screenshot.png" alt="OpenSnitch"/>
</p>

**Warning: This is still alpha quality software, don't rely on it (yet) for your computer security.**

## Install

    sudo apt-get install build-essential python-dev python-setuptools libnetfilter-queue-dev python-qt4
    cd opensnitch
    sudo python setup.py install

## Run

    sudo opensnitch

## TODOs

    grep -r TODO opensnitch | cut -d '#' -f 2 | sort -u

## License

This project is copyleft of [Simone Margaritelli](http://www.evilsocket.net/) and released under the GPL 3 license.

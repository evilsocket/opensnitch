# OpenSnitch

OpenSnitch is a GNU/Linux port of the Little Snitch application firewall.

**Warning: This is still alpha quality software, don't rely on it (yet) for your computer security.**

![OpenSnitch](screenshot.png?raw=true)

## Install

    sudo apt-get install nfqueue-bindings-python
    cd opensnitch
    sudo python setup.py install

## Run

    sudo opensnitch

## TODOs

    grep -r TODO opensnitch | cut -d '#' -f 2 | sort -u

## License

This project is copyleft of [Simone Margaritelli](http://www.evilsocket.net/) and released under the GPL 3 license.

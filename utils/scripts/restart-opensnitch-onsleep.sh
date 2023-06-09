#!/bin/bash
# opensnitch - 2022-2023
#
# Due to a bug in gobpf, when coming back from suspend state, ebpf stops working.
# The temporal solution is to stop/start the daemon on suspend.
#
# Copy it to /lib/systemd/system-sleep/ with any name and exec permissions.
#
if [ "$1" == "pre" ]; then
    service opensnitchd stop
elif [ "$1" == "post" ]; then
    service opensnitchd stop
    service opensnitchd start
fi

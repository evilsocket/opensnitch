#!/bin/sh
set -e

ophome="/etc/opensnitchd"

ls -dl $ophome 1>/dev/null
echo "installed OK: $ophome"
ls -l $ophome/system-fw.json 1>/dev/null
echo "installed OK: $ophome/system-fw.json"
ls -l $ophome/default-config.json 1>/dev/null
echo "installed OK: $ophome/default-config.json"
ls -dl $ophome/rules 1>/dev/null
echo "installed OK: $ophome/rules/"

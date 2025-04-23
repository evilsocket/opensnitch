#!/usr/bin/env bash
#
# Synchronize ipasn and asnames data for use with OpenSnitch
#
# Author: Self Denial <selfdenial at pm dot me>
#
# This script downloads pre-processed asn data from
# https://github.com/lainedfles/opensnitch-asn-data
# Wget is required.
#
# Example crontab:
#
# Poll every 7 days
# 0 0 */7 * * /home/user/.config/opensnitch/ipasn_db_sync.sh 2>&1 | logger -t ipasn_db_sync.sh

# Vars
OPENSNITCH_CONF_PATH=~/.config/opensnitch
SOURCE_REPO="https://github.com/lainedfles/opensnitch-asn-data"
IPASN_FILE="ipasn_db.dat.gz"
ASNAMES_FILE="asnames.json"

# Ensure wget are available
if ! command -v "wget" &>/dev/null; then
  echo "wget not found! Please ensure that wget is in your PATH."
  exit 1
fi

# Ensure destination exists
if [ ! -e "$OPENSNITCH_CONF_PATH" ]; then
  mkdir -pv "$OPENSNITCH_CONF_PATH" || exit 1
fi
cd "$OPENSNITCH_CONF_PATH" || exit 1

# Update asnames
echo "******** Updating $ASNAMES_FILE... ********"
# Create backup
[ -f "$ASNAMES_FILE" ] && mv -vf "$ASNAMES_FILE" "$ASNAMES_FILE.last"
if wget --no-verbose --output-document="$ASNAMES_FILE" "${SOURCE_REPO}/releases/latest/download/$ASNAMES_FILE"; then
  echo "Updated asnames data"
else
  echo "Failed to update asnames data, restoring backup"
  # Restore backup upon failure
  mv -vf "$ASNAMES_FILE.last" "$ASNAMES_FILE"
fi

# Update ipasn db
echo "******** Updating $IPASN_FILE... ********"
# Create backup
[ -f "$IPASN_FILE" ] && mv -vf "$IPASN_FILE" "$IPASN_FILE.last"
if wget --no-verbose --output-document="$IPASN_FILE" "${SOURCE_REPO}/releases/latest/download/$IPASN_FILE"; then
  echo "Downloaded ipasn data"
else
    echo "Failed to download ipasn data, restoring backup"
    mv -vf "$IPASN_FILE.last" "$IPASN_FILE"
fi

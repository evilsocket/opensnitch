#!/usr/bin/env bash
#
# Update ipasn and asnames data for use with OpenSnitch
#
# Author: Self Denial <selfdenial at pm dot me>
#
# This script requires the pyasn module from: https://github.com/hadiasghari/pyasn
# Specifically, the pyasn-utils pyasn_util_asnames.py, pyasn_util_download.py,
# and pyasn_util_convert.py. These must be available with the PATH variable.
#
# Example crontab:
#
# Update every 14 days
# 0 0 */14 * * /home/user/.config/opensnitch/ipasn_db_update.sh 2>&1 | logger -t ipasn_db_update.sh

# Vars
OPENSNITCH_CONF_PATH=~/.config/opensnitch
IPASN_FILE="${OPENSNITCH_CONF_PATH}/ipasn_db.dat"
ASNAMES_FILE="${OPENSNITCH_CONF_PATH}/asnames.json"
RIBDATA_FILE="${OPENSNITCH_CONF_PATH}/rib-data.bz2"

# Ensure pyasn-utils are available
for PYASN_UTIL in pyasn_util_{asnames,convert,download}.py; do
  if ! command -v "$PYASN_UTIL" &>/dev/null; then
    echo "$PYASN_UTIL not found! Please ensure that the pyasn-utils are in your PATH."
    exit 1
  fi
done

# Ensure destination exists
if [ ! -e "$OPENSNITCH_CONF_PATH" ]; then
  mkdir -pv "$OPENSNITCH_CONF_PATH" || exit 1
fi

# Update asnames
echo "******** Updating ${ASNAMES_FILE##*/}... ********"
# Create backup
[ -f "$ASNAMES_FILE" ] && mv -vf "$ASNAMES_FILE" "$ASNAMES_FILE.last"
if pyasn_util_asnames.py -o "$ASNAMES_FILE"; then
  echo "Updated asnames data"
else
  echo "Failed to update asnames data, restoring backup"
  # Restore backup upon failure
  mv -vf "$ASNAMES_FILE.last" "$ASNAMES_FILE"
fi

# Update ipasn db
echo "******** Updating ${IPASN_FILE##*/}... ********"
# Create backup
[ -f "${IPASN_FILE}.gz" ] && mv -vf "${IPASN_FILE}.gz" "${IPASN_FILE}.gz.last"
# Clean up rib data if needed
[ -e "$RIBDATA_FILE" ] && rm -vf "$RIBDATA_FILE"
# Pull both ipv4 & ipv6
# The resulting rib files typically include a date string in the name
# use --filename to identify
if pyasn_util_download.py --latestv46 --filename "$RIBDATA_FILE"; then
  echo "Downloaded ipasn data"
  if pyasn_util_convert.py --single "$RIBDATA_FILE" "$IPASN_FILE" --compress --no-progress; then
    echo "Converted ipasn data"
  else
    echo "Failed to convert ipasn data, restoring backup"
    mv -vf "${IPASN_FILE}.gz.last" "${IPASN_FILE}.gz"
  fi
else
    echo "Failed to download ipasn data, restoring backup"
    mv -vf "${IPASN_FILE}.gz.last" "${IPASN_FILE}.gz"
fi

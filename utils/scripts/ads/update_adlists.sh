#!/bin/bash
# opensnitch - 2021
#
# https://github.com/evilsocket/opensnitch/wiki/block-lists
# 
# Add the script to a regular user's crontab:
# $ crontab -e
# 0 11,17,23 * * * /home/user/scripts/update_adlists.sh

# https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext
# https://hostfiles.frogeye.fr/multiparty-trackers-hosts.txt
# https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt
# https://adaway.org/hosts.txt
# https://www.github.developerdan.com/hosts/lists/tracking-aggressive-extended.txt
# https://raw.githubusercontent.com/Kees1958/W3C_annual_most_used_survey_blocklist/master/TOP_EU_US_Ads_Trackers_HOST
# https://curben.gitlab.io/malware-filter/urlhaus-filter-hosts.txt

# Use any directory you want to save the lists.
# If you use /etc/opensnitchd, give write permissions to blocklists/* for your user (chown -R /etc/opensnitchd/blocklists/).
# or use a directory from your user's home.
adsDir="/etc/opensnitchd/blocklists/domains/"

# If you add new urls, remember to add the corresponding filename where it'll be save on disk.
adsList=(
    "https://curben.gitlab.io/malware-filter/urlhaus-filter-hosts.txt"
    "https://raw.githubusercontent.com/Kees1958/W3C_annual_most_used_survey_blocklist/master/TOP_EU_US_Ads_Trackers_HOST"
    "https://hostfiles.frogeye.fr/multiparty-trackers-hosts.txt"
    "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt"
    "https://www.github.developerdan.com/hosts/lists/tracking-aggressive-extended.txt"
    "https://adaway.org/hosts.txt"
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintex")
adsListNames=(
    "urlhaus-filter-hosts.txt"
    "top_eu_us_ads_trackers.txt"
    "multiparty-trackers-hosts.txt"
    "firstparty-trackers-hosts.txt"
    "tracking-aggressive-extended.txt"
    "adaway-hosts.txt"
    "yoyo-adservers.txt")

function download_cname_trackers
{
    remoteSize=$(curl --silent -I https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cname_trackers.txt | awk '/content-length:/ {print $2}'|tr -d '\r')
    localSize=$(stat -c %s $adsDir/cname_trackers.txt)
    if [ ! -z $remoteSize ]; then
        if [ "$remoteSize" != "$localSize" ]; then
            > /tmp/.cname_temp
            cname_trackers=$(curl --silent https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cname_trackers.txt | awk '/^!#include/ { print $2 }')
            for tracker in $cname_trackers
            do
                curl --silent $tracker | grep "^||" | sed 's/^||\(.*\)^/0.0.0.0 \1/' >> /tmp/.cname_temp
            done
            mv /tmp/.cname_temp $adsDir/cname_trackers.txt
        else
            echo "[-] cname trackers not updated yet"
        fi
    fi
}

function download_ads_list
{
    reload=0
    for idx in ${!adsList[@]}
    do
        echo "[+] Checking list ${adsList[$idx]}, ${adsListNames[$idx]}"
        remoteSize=$(curl --silent -I ${adsList[$idx]}|awk '/content-length:/ {print $2}'|tr -d '\r')
        localSize=$(stat -c %s $adsDir/${adsListNames[$idx]})

        if [ ! -z $remoteSize ]; then
            if [ "$remoteSize" != "$localSize" ]; then
                echo "[+] downloading new ads list... ${adsList[$idx]}, $remoteSize, $localSize"
                curl --silent "${adsList[$idx]}" -o $adsDir/${adsListNames[$idx]}
                reload=1
            else
                echo "[-] ads list not updated yet:  $remoteSize, $localSize - ${adsList[$idx]}"
            fi
        else
            echo "[!] No content-length header found: ${adsList[$idx]}"
        fi
    done
}


if [ ! -d $adsDir ]; then
    mkdir -p $adsDir
fi

cd $adsDir

download_ads_list
download_cname_trackers

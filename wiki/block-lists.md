Starting from version [1.4.0rc1](https://github.com/evilsocket/opensnitch/releases/tag/v1.4.0-rc.1), you can block or allow lists of domains.

Since version [1.5.0rc1](https://github.com/evilsocket/opensnitch/releases/tag/v1.5.0-rc.1) you can also use lists of IPs, network ranges and domains with regular expressions.

Use this feature to block system-wide ads, trackers, or malware domains.
You can also use it to limit the domains to which an application can connect to, or for blocking IPs by country.


Use cases:

0. [How to add a global rule to block ads, trackers or malware domains system-wide on Linux](#how-to-add-a-global-rule-to-block-ads-trackers-or-malware-domains-system-wide-on-linux)

1. [Limiting to what domains an application can connect to](#limiting-to-what-domains-an-application-can-connect-to)


Supported list stypes
 * [Lists of domains (hosts format)](#lists-of-domains)
 * [Lists of regular expressions](#lists-of-domains-with-regular-expressions)
 * [Lists of IPs](#lists-of-ips)
 * [Lists of Nets](#lists-of-nets)
 * [Lsits of MD5s](#lists-of-md5s-added-in-v170)

[Notes](#notes)

[Troubleshooting](#troubleshooting)

[Video tutorial](#video-tutorials)

[Resources](#resources)

**Important note:** This feature may not work if your system uses `systemd-resolved` to resolve domains. Compiling `opensnitch-dns.c` [eBPF module](https://github.com/evilsocket/opensnitch/tree/master/ebpf_prog) may help to workaround this problem. If blocklists don't work, change your nameserver in `/etc/resolv.conf` to 1.1.1.1, 9.9.9.9, etc... and see if it works.

  - If you use systemd-resolved, remember to allow it connect only to your DNS nameservers (1.1.1.1, 9.9.9.9, etc), port 53.

---

How to add a global rule to block ads, trackers or malware domains system-wide on Linux:
---

1. Create a new rule: `000-block-domains`
   - Take into account that rules are checked in alphabetical order.

2. Check `[x] Enable`, `[x] Priority`, `Duration: always`, `(*) Reject`, `[x] To this list of domains`

![image](https://user-images.githubusercontent.com/2742953/222983097-3e9e4a7a-dbaa-40da-8e2c-c05c5ba71591.png)


3. Download list of domains of ads to block (choose any directory you wish):
```
~ $ sudo mkdir /media/ads-list/
~ $ sudo chown USER:USER /media/ads-list/ # replace USER with your user
~ $ wget https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt -O /media/ads-list/ads-and-tracking-extended.txt
```

**Note:** be sure that the files have an extension (.dat, .txt, .list, etc...). Don't drop files without extension into the directory

4. Visit any website, and filter by the name of the rule `000-block-domains` or double click on the rule name from the Rules tab. You can visit `block-test.developerdan.com` which is included in the above list.

![image](https://user-images.githubusercontent.com/2742953/222982955-9bb66595-e3b3-4b25-87d6-5dd0f2d89875.png)



Limiting to what domains an application can connect to:
---

We'll create 2 rules:
- one for allow connections from an app to a limited number of domains.
- another one for deny everything from that app.

1. Create 2 rules: `000-allow-app` , `001-deny-all-from-app`
2. `000-allow-app`:

![image](https://user-images.githubusercontent.com/2742953/121044328-c1d67f00-c7b5-11eb-84c6-14e3abfc94a6.png)

Inside `/media/app/` write a file (`allowlist.txt` for example) with a list of domains the app can connect to in hosts format:

```
127.0.0.1 xxx.domain.com
```

**Note:** be sure that the file has an extension (.dat, .txt, .list, etc...).

Remember that you may need to add the domain without the subdomains (`domain.com`, `xxx.domain.com`, etc)

3. `001-deny-all-from-app`:

![image](https://user-images.githubusercontent.com/2742953/121048055-b9cb0f00-c7b6-11eb-9b0e-bb59091fb123.png)

---

### Supported list types

#### Lists of domains
- It must be in hosts format:
```
# this is a comment, it's ignored
# https://www.github.developerdan.com/hosts/
0.0.0.0 www.domain.com
127.0.0.1 www.domain.com
```

---

#### Lists of domains with regular expressions
- one regular expression per line:
```
# https://raw.githubusercontent.com/mmotti/pihole-regex/master/whitelist.list
adtrack(er|ing)?[0-9]*[_.-]
^analytics?[_.-]
^pixel?[-.]
^stat(s|istics)?[0-9]*[_.-]
```

**Note**: if you add a domain without a regex to this type of list, it'll match everything for that domain: _google.com_ will match _clients6.google.com_, _docs.google.com_, etc.

**Note**: Sometimes regular expressions can be too generic, so they may block too many domains. You can go to Rules tab -> double click on the rule, and see what domains the rule has matched, and refine the list accordingly.

⚠️ **WARNING** ⚠️: This list must be small (~500 items). Using it with huge lists will lead to important performance penalty ([#866](https://github.com/evilsocket/opensnitch/issues/866)).

Here's a playground you can use to test regular expressions: https://go.dev/play/p/JzQCeNH4OH1

---

#### Lists of IPs
- One per line:

IPs
```
# https://iplists.firehol.org/
6.7.8.9
9.8.7.6
```

---

#### Lists of NETs
You can use these lists for exmple for GeoIP blocking: https://www.ipdeny.com/ipblocks/

Nets:
```
# https://iplists.firehol.org/
1.0.1.0/24
1.2.3.0/16
```

---

#### Lists of md5s (added in v1.7.0)
Use this type to allow or block list of md5s.

```json
  "operator": {
    "type": "lists",
    "operand": "lists.hash.md5",
    "sensitive": false,
    "data": "/etc/opensnitchd/md5list/",
    "list": []
  }
```

For example you can download a list of known malware in the wild from [bazaar.abuse.ch](https://bazaar.abuse.ch/export/)

```bash
~ $ wget https://bazaar.abuse.ch/export/txt/md5/full/ -O /tmp/md5list-full.zip
~ $ unzip -d /tmp/md5list-full.zip /etc/opensnitchd/md5list/
~ $ head -3 /etc/opensnitchd/md5list/full_md5.txt
################################################################
# MalwareBazaar full malware samples dump (MD5 hashes)         #
# Last updated: 2025-08-12 19:33:06 UTC                        #
```

---

#### Notes
- Lines started with # are ignored. Write comments always on a new line, not after a domain.
- The domains `local`, `localhost`, `localhost.localdomain` and `broadcasthost` are ignored.
- Whenever you save the file to disk, OpenSnitch will reload the list.
- If you select more than one type of lists on the same rule, bear in mind that the connections you intend to filter must match __ALL__ lists [read more](https://github.com/evilsocket/opensnitch/discussions/877#discussioncomment-5244901).
- OpenSnitch doesn't refresh periodically the list loaded, but you can do it with this script: [update_adlists.sh](https://raw.githubusercontent.com/evilsocket/opensnitch/master/utils/scripts/ads/update_adlists.sh)
  1. Give it execution permissions:

     `chmod +x update_adlists.sh`
  2. Edit the script, and modify the **adsDir** path to point to the directory where you want to save the lists.
  3. Add the script to your user's crontab (in this example, the script will be executed every day at 11am, 17pm and 23pm):
     ```
     $ crontab -e
     0 11,17,23 * * * /home/ga/utils/opensnitch/update_adlists.sh
     ```

### Troubleshooting

When you define a blocklist/allowlist rule, the directory choosen is monitored for changes. If you delete, add or modify a file under that directory, the lists will be reloaded. You'd see these logs in `/var/log/opensnitchd.log`:

```
[2022-03-31 23:58:19]  INF  clearing domains lists: 2 - /etc/opensnitchd/allowlists/regexp
[2022-03-31 23:58:19]  DBG  Loading regexp list: /etc/opensnitchd/allowlists/regexp/allow-re.txt, size: 72
[2022-03-31 23:58:19]  INF  2 regexps loaded, /etc/opensnitchd/allowlists/regexp/allow-re.txt
[2022-03-31 23:58:19]  INF  2 lists loaded, 2 domains, 0 duplicated
```

In order to verify why a domain matched a list, set LogLevel to DEBUG under Preferences -> Nodes, and monitor the log file /var/log/opensnitchd.log:

`tail -f /var/log/opensnitchd.log | grep "list match" -A 1`

```
[2023-03-02 00:28:26]  DBG  Regexp list match: pixel.abandonedaction.com, ^pixels?[-.]
[2023-03-02 00:28:26]  DBG  ✘ /lib/systemd/systemd-resolved -> 56143:192.168.1.103 => pixel.abandonedaction.com (172.17.0.3):53 (000-a-pihole-regexp)
```

(for regexp lists, the last part of the log is the regexp that matched the domain -> ^pixels?[-.])

This feature may not work if your system uses `systemd-resolved` to resolve domains. Compiling `opensnitch-dns.c` [eBPF module](https://github.com/evilsocket/opensnitch/tree/master/ebpf_prog) may help to workaround this problem.

If blocklists still don't work:
- allow systemd-resolved to connect **only** to port 53 and 127.0.0.1 + your DNS nameservers.
  - or stop systemd-resolved: `systemctl stop systemd-resolved`
  - and change your nameserver in `/etc/resolv.conf` to 1.1.1.1, 9.9.9.9, etc... and see if it works. A simple telnet to an entry of the list should be blocked and logged accordingly.


See this issue [#646](https://github.com/evilsocket/opensnitch/issues/646) for more information.

### Resources

Lists of ads, trackers, malware domains, etc that you can use:

https://github.com/badmojr/1Hosts

https://oisd.nl/?p=dl

https://filterlists.com/ (filter by Syntaxis: hosts)

https://www.github.developerdan.com/hosts/

https://firebog.net/

https://github.com/StevenBlack/hosts

https://pgl.yoyo.org/adservers/

https://iplists.firehol.org/

List of active malware domains:

https://urlhaus.abuse.ch/api/#hostfile

https://threatfox.abuse.ch/export/#hostfile

https://bazaar.abuse.ch/export/

Collections of Threat Intel feeds (by hash, IPs, domains, and more):

https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds

---

### Video tutorials:

https://user-images.githubusercontent.com/2742953/192171195-ba14e4cc-420a-4b85-a6c7-7f023a6a63e3.webm

https://user-images.githubusercontent.com/2742953/192171230-330adbd0-4ef8-48f8-a304-96812fd31c41.webm

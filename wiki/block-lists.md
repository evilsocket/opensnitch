Starting from version [1.4.0rc1](https://github.com/evilsocket/opensnitch/releases/tag/v1.4.0-rc.1), you can block or allow lists of domains.

Since version [1.5.0rc1](https://github.com/evilsocket/opensnitch/releases/tag/v1.5.0-rc.1) you can also use lists of IPs, network ranges and domains with regular expressions.

It can be used to block ads, trackers, malware domains or limit to what domains an application connects to.

Use cases:

0. [How to add a global rule to block malware or ads](#how-to-add-a-global-rule-to-block-ads-or-trackers)

1. [Limiting to what domains an application can connect to](#limiting-to-what-domains-an-application-can-connect-to)


[Notes](#notes)

[Troubleshooting](#troubleshooting)

[Video tutorial](#resources)

[Resources](#resources)

**Important note:** This feature may not work if your system uses `systemd-resolved` to resolve domains. Compiling `opensnitch-dns.c` [eBPF module](https://github.com/evilsocket/opensnitch/tree/master/ebpf_prog) may help to workaround this problem. If blocklists don't work, change your nameserver in `/etc/resolv.conf` to 1.1.1.1, 9.9.9.9, etc... and see if it works.

---

How to add a global rule to block ads or trackers:
---

1. Create a new rule: `000-block-domains`
2. Check `[x] Enable`, `[x] Priority`, `Duration: always`, `[x] To this list of domains`
![image](https://user-images.githubusercontent.com/2742953/115916860-addcf500-a475-11eb-86f4-af2c645aa2ba.png)


3. Download list of domains of ads to block (choose any directory you wish):
```
~ $ sudo mkdir /media/ads-list/
~ $ sudo chown USER:USER /media/ads-list/ # replace USER with your user
~ $ wget https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt -O /media/ads-list/ads-and-tracking-extended.txt
```

**Note:** be sure that the files have an extension (.dat, .txt, .list, etc...). Don't drop files without extension into the directory

4. Visit any website, and filter by the name of the rule `000-block-domains` . You can use `block-test.developerdan.com` which is included in the above list.

![image](https://user-images.githubusercontent.com/2742953/115919049-981cff00-a478-11eb-9201-360463302399.png)



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

### Notes
Lists of domains (only in version >= **v1.4.x**):
- It must be in hosts format:
```
# this is a comment, it's ignored
# https://www.github.developerdan.com/hosts/
0.0.0.0 www.domain.com
127.0.0.1 www.domain.com
```


Lists of domains with regular expressions (or not) (only in version >= **v1.5.x**):
- one regular expression per line:
```
# https://raw.githubusercontent.com/mmotti/pihole-regex/master/whitelist.list
adtrack(er|ing)?[0-9]*[_.-]
^analytics?[_.-]
^pixel?[-.]
^stat(s|istics)?[0-9]*[_.-]
```

Lists of IPs (only in version >= **v1.5.x**):
- One per line:
IPs
```
# https://iplists.firehol.org/
6.7.8.9
9.8.7.6
```

Lists of NETs (only in version >= **v1.5.x**):
Nets:
```
# https://iplists.firehol.org/
1.0.1.0/24
1.2.3.0/16
```


- Lines started with # are ignored. Write comments always on a new line, not after a domain.
- The domains `local`, `localhost`, `localhost.localdomain` and `broadcasthost` are ignored.
- Whenever you save the file to disk, OpenSnitch will reload the list.
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


This feature may not work if your system uses `systemd-resolved` to resolve domains. Compiling `opensnitch-dns.c` [eBPF module](https://github.com/evilsocket/opensnitch/tree/master/ebpf_prog) may help to workaround this problem. 

If blocklists still don't work:
- stop systemd-resolved: `systemctl stop systemd-resolved`
- change your nameserver in `/etc/resolv.conf` to 1.1.1.1, 9.9.9.9, etc... and see if it works. A simple telnet to an entry of the list should be blocked and logged accordingly.


See this issue #646 for more information.

### Resources

Video tutorials:

https://user-images.githubusercontent.com/2742953/192171195-ba14e4cc-420a-4b85-a6c7-7f023a6a63e3.webm

https://user-images.githubusercontent.com/2742953/192171230-330adbd0-4ef8-48f8-a304-96812fd31c41.webm

Lists of ads, trackers, malware domains, etc that you can use:

https://github.com/badmojr/1Hosts

https://oisd.nl/?p=dl

https://filterlists.com/ (filter by Syntaxis: hosts)

https://www.github.developerdan.com/hosts/

https://firebog.net/

https://github.com/StevenBlack/hosts

https://pgl.yoyo.org/adservers/

https://iplists.firehol.org/

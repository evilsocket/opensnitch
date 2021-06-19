Starting from version [1.4.0rc1](https://github.com/evilsocket/opensnitch/releases/tag/v1.4.0-rc.1), you can block or allow lists of domains.

It can be used to block ads, or limit to what domains an application connects to.


How to add a global rule to block ads/malware/etc:
---

1. Create a new rule: `000-block-domains`
2. Check `[x] Enable`, `[x] Priority`, `Duration: always`, `[x] To this list of domains`
![image](https://user-images.githubusercontent.com/2742953/115916860-addcf500-a475-11eb-86f4-af2c645aa2ba.png)


3. Download list of domains of ads to block (choose any directory you wish):
```
$ mkdir /media/ads-list/
$ wget https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt -O /media/ads-list/ads-and-tracking-extended.txt
```

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

Inside `/media/app/` write a file with a list of domains the app can connect to in hosts format:
```
127.0.0.1 xxx.domain.com
```

Remember that you may need to add the domain without the subdomains (`domain.com`, `xxx.domain.com`, etc)

3. `001-deny-all-from-app`:

![image](https://user-images.githubusercontent.com/2742953/121048055-b9cb0f00-c7b6-11eb-9b0e-bb59091fb123.png)

---

### Notes
- The format of the files must be in hosts format:
```
0.0.0.0 www.domain.com
127.0.0.1 www.domain.com
```
- Lines started with # are ignored. Write comments always on a new line, not after a domain.
- The domains `local`, `localhost`, `localhost.localdomain` and `broadcasthost` are ignored.
- Whenever you save the file to disk, OpenSnitch will reload the list.
- OpenSnitch doesn't refresh periodically the list loaded, but you can do it with this script: [update_adlists.sh.txt](https://github.com/evilsocket/opensnitch/files/6680314/update_adlists.sh.txt)
  1. Rename it to .sh and give it execution permissions:
  
     `mv update_adlists.sh.txt update_adlists.sh; chmod +x update_adlists.sh`
  2. Edit the script, and modify the **adsDir** path to point to the directory where you want to save the lists.
  3. Add the script to your user's crontab (in this example, the script will be executed every day at 11am, 17pm and 23pm):
     ```
     $ crontab -e
     0 11,17,23 * * * /home/ga/utils/opensnitch/update_adlists.sh
     ```

### Resources

Lists of ads, tracking, malware, etc that you can use:

https://filterlists.com/ (filter by Syntaxis: hosts)

https://www.github.developerdan.com/hosts/

https://firebog.net/

https://github.com/StevenBlack/hosts

https://pgl.yoyo.org/adservers/

Starting from version [1.4.0rc1](https://github.com/evilsocket/opensnitch/releases/tag/v1.4.0-rc.1), you can block or allow lists of domains.

It can be used to block ads, or limit to what domains an application connects to.

**How to configure it:**

1. Create a new rule: `000-block-domains`
2. Check [x] Priority, Duration: always, [x] To this list of domains
![image](https://user-images.githubusercontent.com/2742953/115916860-addcf500-a475-11eb-86f4-af2c645aa2ba.png)


3. Download list of domains of ads to block (choose any directory you wish):
```
$ mkdir /media/ads-list/
$ wget https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt -O /media/ads-list/ads-and-tracking-extended.txt
```

4. Visit any website, and filter by the name of the rule `000-block-domains` . You can use `block-test.developerdan.com` which is included in the above list.

![image](https://user-images.githubusercontent.com/2742953/115919049-981cff00-a478-11eb-9201-360463302399.png)

The format of the files must be in hosts format:
```
0.0.0.0 www.domain.com
127.0.0.1 www.domain.com
```
Lines started with # are ignored.

Some lists of ads, tracking, malware, etc you can use:

https://www.github.developerdan.com/hosts/

https://firebog.net/

https://github.com/StevenBlack/hosts

https://pgl.yoyo.org/adservers/

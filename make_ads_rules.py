import requests
import re
import ipaddress
import datetime
import os

lists = ( \
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://mirror1.malwaredomains.com/files/justdomains",
    "http://sysctl.org/cameleon/hosts",
    "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
    "https://hosts-file.net/ad_servers.txt" )

domains = {}

for url in lists:
    print "Downloading %s ..." % url
    r = requests.get(url)
    if r.status_code != 200:
        print "Error, status code %d" % r.status_code
        continue

    for line in r.text.split("\n"):
        line = line.strip()
        if line == "":
            continue

        elif line[0] == "#":
            continue

        for part in re.split(r'\s+', line):
            part = part.strip()
            if part == "":
                continue

            try:
                duh = ipaddress.ip_address(part)
            except ValueError:
                if part != "localhost":
                    domains[part] = 1

print "Got %d unique domains, saving as rules to ./rules/ ..." % len(domains)

os.system("mkdir -p rules")

idx = 0
for domain, _ in domains.iteritems():
    with open("rules/adv-%d.json" % idx, "wt") as fp:
        tpl = """
{
   "created": "%s",
   "updated": "%s",
   "name": "deny-adv-%d",
   "enabled": true,
   "action": "deny",
   "duration": "always",
   "operator": {
     "type": "simple",
     "operand": "dest.host",
     "data": "%s"
   }
}"""
        now = datetime.datetime.utcnow().isoformat("T") + "Z"
        data = tpl % ( now, now, idx, domain )
        fp.write(data)

    idx = idx + 1

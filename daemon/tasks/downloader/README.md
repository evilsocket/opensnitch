### Download task

A simple task to download files in background, at regular intervals.

This task can be used for example to update periodically the [blocklists](https://github.com/evilsocket/opensnitch/wiki/block-lists):

Configuration example:

/etc/opensnitchd/tasks/tasks.json:
```json
    {
        "tasks":[
            {
                "enabled": false,
                "name": "downloader",
                "configfile": "/etc/opensnitchd/tasks/downloader/downloader.json"
            }
        ]
    }
```

    /etc/opensnitchd/tasks/downloader/downloader.json:
```json
    {
      "name": "downloader",
      "parent": "downloader",
      "description": "",
      "data": {
          "interval": "6h",
          "timeout": "5s",
          "urls": [
              {
                  "name": "adaway",
                  "enabled": true,
                  "remote": "https://adaway.org/hosts.txt",
                  "localfile": "/etc/opensnitchd/tasks/downloader/blocklists/domains/ads-adaway-hosts.txt"
              },
              {
                  "name": "developerdan",
                  "enabled": true,
                  "remote": "https://www.github.developerdan.com/hosts/lists/tracking-aggressive-extended.txt",
                  "localfile": "/etc/opensnitchd/tasks/downloader/blocklist/domains/ads-tracking-aggressive-extended.txt"
              }
          ],
          "notify": {
              "enabled": true
          }
    }
```

You can have multiple instances of this task, by using a unique name for the downloader task (the `tasks.json` must be updated accordingly):

    /etc/opensnitchd/tasks/myupdater/myupdater.json:
```json
    {
      "name": "myupdater",
      "parent": "downloader",
      "description": "",
      "data": { ... }
    }
```

If the name of the task is changed, the `"parent": ""` field must appear, defining what is the base task.

Then when creating a new rule to block lists, just point the directory containing the lists to the directory where the Downloader is updating the lists.

For example:

/etc/opensnitchd/rules/block-domains.json

```json
(...)
  "operator": {
    "operand": "lists.domains",
    "data": "/etc/opensnitchd/tasks/downloader/blocklist/domains/",
    "type": "lists",
    "list": [],
    "sensitive": false
  },
(...)
```

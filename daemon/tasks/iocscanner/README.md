
### IOC scanner task

This task is meant to scan for Indicators Of Compromise in the system, periodically, and in background.

It supports (for now) what we call 4 tools: yara, scripts, debsums and dpkg.

These "tools" are defined in the configuration file. The field "name" defines the type of tool
that will be launched, which will have its own logic, output parsing and transformation, etc.

On the other hand, each tool launches a command, with the specified options. For example, to report
MD5 checksum changes in installed Debian packages:

```json
  "tools": [
  {
      "name": "debsums",
      "msgStart": "IOC scanner debsums started",
      "msgEnd": "IOC scanner debsums finished",
      "enabled": false,
      "cmd": ["debsums", "-c"],
      "options": {
          "reports": {
              "path": "/etc/opensnitchd/tasks/iocscanner/reports",
              "format": ""
          }
      }
  }
```

In this case the tool "debsums" will execute the command "debsums -c", parse the output,
and send the results to the GUI.


 TODO:
	[] - list and scan processes (yara, our own rules?)
         - suspicious names, suspicious paths, etc.
	[] - list/analyze cached processes (yara, our own rules?)
	[] - find hidden kmods and rootkits (LD_PRELOAD, lkm)
	[] - apply actions (kill, quarantine, stop, ...)
    [] - reuse rules format? daemon/rules/operator/
    [] - subscribe to real-time events (ebpf)
         - optionally, monitor files/directories for changes (inotify). /etc/ld.so.preload, /etc/modules, etc.
	[x] - verify the integrity of files installed by packages: `debsums -c`, `dpkg --verify`
	[x] - apply rules - (yara)
	[x] - [Partially] send notifications (GUI, SIEM).
	[x] - [decloacker] find hidden processes, files, dirs, content.
	[x] - [DONE] implement advanced scheduling

IOCScanner task configuration example to run Yara with a set of rules:

```json
~ # cat /etc/opensnitchd/tasks/iocscanner/iocscanner.json
{
    "name": "IOC-scanner",
    "data": {
        "interval": "15s",
        "schedule": [
            {
                "weekday": [0,1,2,3,4,5,6],
                "time": ["09:55:00", "20:15:20", "22:10:45", "00:07:10", "01:17:55"],
                "hour": [],
                "minute": [],
                "second": []
            }
        ],
        "tools": [
            {
                "name": "yara",
                "msgstart": "IOC scanner yara started",
                "msgend": "IOC scanner yara finished",
                "enabled": false,
                "cmd": ["/usr/bin/yara"],
                "dataDir": "/etc/opensnitchd/tasks/iocscanner/data/",
                "options": {
                    "debug": false,
                    "recursive": true,
                    "scanprocs": false,
                    "fastscan": false,
                    "maxSize": 0,
                    "maxProcessMem": 0,
                    "maxRunningTime": "1h",
                    "threads": 1,
                    "priority": 0,
                    "reports": [
                        {
                            "type": "file",
                            "path": "/etc/opensnitchd/tasks/iocscanner/reports",
                            "format": ""
                        }
                    ],
                    "dirs": [
                        "/dev/shm", "/tmp", "/var/tmp",
                        "/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly",
                        "/etc/systemd/",
                        "/etc/update-motd.d/",
                        "/etc/udev/rules.d/",
                        "/var/spool/",
                        "/etc/xdg/autostart/",
                        "/var/www/",
                        "/home/*/.config/systemd/user/",
                        "/home/*/.config/autostart/"
                    ],
                    "files": [
                        "/etc/ld.so.config",
                        "/etc/motd",
                        "/etc/rc.local",
                        "/etc/shadow", "/etc/passwd",
                        "/home/*/.bashrc",
                        "/etc/crontab"
                    ],
                    "rules": [ "/etc/opensnitchd/tasks/iocscanner/yara/unix-redflags/*.yar" ],
                    "exclusions": {
                        "dirs": [],
                        "files": []
                    },
                    "tags": [
                        "linux",
                        "exfiltration",
                        "persistance"
                    ]
                }
            }
        ]
    }
}
```

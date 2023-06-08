## GUI

[GUI known problems](https://github.com/evilsocket/opensnitch/wiki/GUI-known-problems)

## daemon

[daemon known problems](https://github.com/evilsocket/opensnitch/wiki/daemon-known-problems)

## General


### Blank window after boot up

### Desktop Environment does not boot up

If after installing OpenSnitch, or after changing the Default Action to `deny`, the Desktop Environment does not show up (after restart), try:

1. setting the `DefaultAction` back to `allow`
2. adding a rule to allow system apps.

In both cases the idea is to allow certain programs needed by KDE, Gnome, etc: dirmngr, xbrlapi, host, kdeinit5. [more info #402](https://github.com/evilsocket/opensnitch/issues/402):

Save it to `/etc/opensnitchd/rules/000-allow-system-cmds.json`
```
{
  "created": "2021-04-26T09:58:03.704090244+02:00",
  "updated": "2021-04-26T09:58:03.704216578+02:00",
  "name": "000-allow-system-cmds",
  "enabled": true,
  "precedence": true,
  "action": "allow",
  "duration": "always",
  "operator": {
    "type": "regexp",
    "operand": "process.path",
    "sensitive": false,
    "data": "^(/usr/bin/host|/usr/bin/xbrlapi|/usr/bin/dirmngr|/usr/bin/slim)",
    "list": []
  }
}
```

You can also allow all traffic to localhost (save it to `/etc/opensnitchd/rules/000-allow-localhost.json`):
```
{
  "created": "2021-04-26T09:58:03.704090244+02:00",
  "updated": "2021-04-26T09:58:03.704216578+02:00",
  "name": "000-allow-localhost",
  "enabled": true,
  "precedence": true,
  "action": "allow",
  "duration": "always",
  "operator": {
    "type": "network",
    "operand": "dest.network",
    "sensitive": false,
    "data": "127.0.0.0/8",
    "list": []
  }
}
```

***






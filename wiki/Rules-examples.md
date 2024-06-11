**Prioritize rules**
---

Rules are checked in alphabetical order, so the first step is to name the rules accordingly:

    000-allow-very-important-rule
    001-allow-not-so-important-rule

The second step is to check the box `[x] Priority` of a rule.

ℹ️ Remember:

By default the rules are evaluated until a rule with a Deny/Reject Action is found, or when a rule with the `[x] Priority` check marked.

More info:
https://github.com/evilsocket/opensnitch/wiki/Rules#some-considerations

**Block ads, tracking or malware domains globally**
---

https://github.com/evilsocket/opensnitch/wiki/block-lists

**Blocking connections from an executable, allowing only a few domains**
---

https://github.com/evilsocket/opensnitch/wiki/block-lists

**Filtering connections by multiple ports**
---

`  [x] To this port: ^(53|80|443)$`

targets ports 53 OR 80 OR 443.

`  [x] To this port: ^555[12345]$`

targets ports 5551, 5552, 5553, 5554 OR 5555.

**Filtering connections by an exact domain, and nothing else**
---

`  [x] To this host: github.com` (will match only github.com, not www.github.com, etc)

**Filtering connections by a domain and its subdomains**
---

`  [x] To this host: .*\.github.com`

**Filtering connections by an executable path**
---

`  [x] From this executable: /usr/bin/python3`

(warning: /usr/bin/python3.6/3.7/3.8/etc won't match this rule)

**Allowing or denying Appimages**
---

`  [x] From this executable: ^(/tmp/.mount_Archiv[0-9A-Za-z]+/.*)$`

**Allow common system commands**
---

  ```
  Name: 000-allow-system-cmds
  Action: Allow
  [x] Priority rule
  [x] From this executable: ^(/usr/sbin/ntpd|/lib/systemd/systemd-timesyncd|/usr/bin/xbrlapi|/usr/bin/dirmngr)$
  [x] To this port: ^(53|123)$
  [x] From this User ID: ^(0|115|118)$
  ```

**Blocking connections initiated by executables launched from /tmp*, /var/tmp or /dev/shm*
---

  ```
  Action: Deny
  [x] From this executable: ^(/tmp/|/var/tmp/|/dev/shm/).*
  ```

**Blocking connections initiated by executables with certain environment variables (LD_PRELOAD for example)*
---
Note: This feature cannot configured from the GUI yet (11/06/2024)

Block outbound connections initiated by executables with certain environment variables, like when LD_PRELOAD is used maliciously:

`~ $ LD_PRELOAD=/tmp/backdoor.so sshd 1.2.3.4 443`

```json
{
  "created": "2024-05-31T23:39:28+02:00",
  "updated": "2024-05-31T23:39:28+02:00",
  "name": "000-block-ld-preload",
  "description": "",
  "action": "reject",
  "duration": "always",
  "enabled": true,
  "precedence": true,
  "nolog": false
  "operator": {
    "operand": "process.env.LD_PRELOAD",
    "data": "^(\\.|/).*",
    "type": "regexp",
    "sensitive": false
  }
}

```

**Filtering an executable path with regexp, for example any python binary in /usr/bin/**
---

`  [x] From this executable: ^/usr/bin/python[0-9\.]*$`

**Filtering python scripts (applicable to java and others interpreters)**
---
The general recommendation is to either allow or deny by `Command line` or better, by Process path + Command line:

![image](https://user-images.githubusercontent.com/2742953/152648281-01e5797b-662d-46d2-b11c-1966feecc54c.png)

If you allow python3, you'll allow ANY python3 script, so be careful. This is also true for other interpreted languages, like Java, Ruby, Perl and others.

https://github.com/evilsocket/opensnitch/discussions/612#discussioncomment-2116878


**Filtering LAN IPs or multiple ranges**
---

`  ^(127\..*|172\..*|192.168\..*|10\..*)$`

See these issues for some discussions and more examples: [#17](https://github.com/gustavo-iniguez-goya/opensnitch/issues/17), [#31](https://github.com/gustavo-iniguez-goya/opensnitch/issues/31), [#73](https://github.com/gustavo-iniguez-goya/opensnitch/issues/73)

**Note:** Don't use "," to specify domains, IPs, etc. It's not supported. For example this won't work (it could be added if you complain loud enough):

> [x] To this host: www.example.org, www.test.me

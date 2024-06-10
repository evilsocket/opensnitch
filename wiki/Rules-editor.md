Rules can be edited from the GUI, by clicking on the name of the rule:

![image](https://user-images.githubusercontent.com/2742953/82753008-95c2a880-9dc2-11ea-8c6a-23e1ce0f3aa4.png)

![image](https://user-images.githubusercontent.com/2742953/98868147-f8425a80-246f-11eb-99b4-5d441b5d5b95.png)

(Since v1.2.0, all rules comparison are case-insensitive by the default for destination host, process path and process arguments.)


#### Parameters
field | descrption
----- | ----------
Enable | Enables or disables the rule.
Priority |  Indicates that this rule has precedence over the rest.
Case sensitive | Make the comparison case-sensitive for ALL fields.
Duration | Always writes the rule to disk.

---

Each field can be literal or a regex expression.

Some examples:

- Filtering by multiple ports:

    `[x] To this port: ^(53|80|443)$`

    targets ports 53 OR 80 OR 443.

    `[x] To this port: ^555[12345]$`

    targets ports 5551, 5552, 5553, 5554 OR 5555.

- Filtering by an exact domain, and nothing else: `[x] To this host: github.com` (will match only github.com, not www.github.com, etc)
- Filtering by a domain and its subdomains: `[x] To this host: .*\.github.com`
- Filtering an executable path:

    `[x] From this executable: /usr/bin/python3`

    (warning: /usr/bin/python3.6/3.7/3.8/etc won't match this rule)

- Allow common system commands:
  ```
  Name: 000-allow-system-cmds
  Action: Allow
  [x] Priority rule
  [x] From this executable: ^(/usr/sbin/ntpd|/lib/systemd/systemd-timesyncd|/usr/bin/xbrlapi|/usr/bin/dirmngr)$
  [x] To this port: ^(53|123)$
  [x] From this User ID: ^(0|115|118)$
  ```

- Blocking connections made by executables launched from /tmp:
    ```
    Action:                   Deny
    [x] From this executable: /tmp/.*
    ```

- Filtering an executable path with regexp, for example any python binary in /usr/bin/:

    `[x] From this executable: ^/usr/bin/python[0-9\.]*$`

     Case insensitive rules:

    `[x] From this executable: (?i:.*ping)`

     ![](https://user-images.githubusercontent.com/2742953/85209253-aa994a00-b336-11ea-87d9-a7a650510b6b.png)

- Filtering LAN IPs or multiple ranges:
     `^(127\..*|172\..*|192.168\..*|10\..*)$`

See these issues for some discussions and more examples: [#17](https://github.com/gustavo-iniguez-goya/opensnitch/issues/17), [#31](https://github.com/gustavo-iniguez-goya/opensnitch/issues/31), [#73](https://github.com/gustavo-iniguez-goya/opensnitch/issues/73)

**Note:** Don't use "," to specify domains, IPs, etc. It's not supported. For example this won't work (it could be added if you complain loud enough):

> [x] To this host: www.example.org, www.test.me

---

[Python regular expression documentation](https://docs.python.org/3.3/howto/regex.html)

[Golang regular expression documentation](https://golang.org/pkg/regexp/syntax/)

[Golang regular expression syntax](https://github.com/google/re2/wiki/Syntax)

**Note:** Golang does not support Perl syntax (like (?!...))

However you can use negated chars classes. For example, block all outgoing connections, except those to localhost:

`[x] Action: deny`

`[x] To this destination IP: [^:127.0.0.1:]`


***


Note on allowing all connections to localhost:

While it might be seem obvious to allow everything to localhost, be aware that you might want to allow only certain connections/programs:

[OpenSnitch in action](OpenSnitch-in-action)

---


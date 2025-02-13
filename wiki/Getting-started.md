After [installing opensnitch](https://github.com/evilsocket/opensnitch/wiki/Installation), notice that a new icon appeared on the systray:

![image](https://user-images.githubusercontent.com/2742953/122753129-1556cb80-d292-11eb-8a70-36a270132c56.png)


You can launch the GUI from that icon or from the system menu (Internet -> OpenSnitch)


The daemon should start intercepting connections, prompting you to allow or deny them. If you don't apply an action, after 30 seconds (configurable) it'll apply the default action configured.

![image](https://user-images.githubusercontent.com/2742953/122794725-da1dc200-d2bc-11eb-9f47-5fc3fc995db7.png)

<br/>

When you open the GUI, you'll see all the connections and processes that the daemon has intercepted. If you don't see connections being made, or anything in <kbd>Status</kbd> or <kbd>Version</kbd>, make sure you've [installed](../Installation) the daemon package as well, not just the GUI. For other GUI issues, see the [known GUI problems(../GUI-known-problems).

Double click on a row to view the details of a process, rule, host or user.

![image](https://user-images.githubusercontent.com/2742953/122794871-02a5bc00-d2bd-11eb-8e7d-8f0827e8d09c.png)

<br/>

> [!NOTE] 
> **Tip:** Configure the default action to Allow (<kbd>Preferences -> Pop-ups -> Action</kbd>, and optionally check [x] <kbd>Disable pop-ups</kbd>), let it run for a while (hours, days, weeks), and observe passively what your machine is doing.

![](https://user-images.githubusercontent.com/2742953/85337403-b294ed80-b4e0-11ea-8c65-d8251c6af25b.png)

This action has two advantages: you'll learn about your system and OpenSnitch will create the rules for you (<kbd>Rules</kbd> tab -> Temporary).

Remember to change it back to Deny.

<br/><br/>

To see and modify the rules accumulated so far, click on the OpenSnitch icon in the System Tray. A GUI listing the rules will appear. You can click on each rule and then click on the Trash Can icon to delete it. Or you can click on a rule and right-click on it to modify allow/deny or duration etc. The list may take up to 15 seconds to show the update in the GUI. Note: if you modify the action of a rule (e.g. change from deny to allow), the name of it may not change (e.g. may stay as "deny-...").

![image](https://user-images.githubusercontent.com/2742953/122754068-729f4c80-d293-11eb-8496-c1d98b393cbd.png)

<br/>

Once you know which are the common processes, IPs and hosts that your machine is connecting to, you can start creating permanent rules (Duration: always) to deny or allow them. You can also convert temporary rules to permanent by right-clicking on a temporary rule or by double-clicking on it, and then edit it.

![image](https://user-images.githubusercontent.com/2742953/122754509-0f61ea00-d294-11eb-990b-2377b0add1f3.png)

A common practice is to apply a rule of "Least privilege", i.e., block everything by default and allow only those processes or connections that you want to.

[Read more about rules.](Rules)

[Read more about blocking lists](block-lists)


![](https://user-images.githubusercontent.com/2742953/85337070-136ff600-b4e0-11ea-838a-439366c70668.png)

Notes 📔
---

Some processes are part of the GNU/Linux ecosystem, and critical to the well functioning of it. Some of these processes are:
```
/usr/bin/xbrlapi
/usr/bin/dirmngr
/usr/bin/kdeinit5
```

Some others are not critical, but as part of the system they have their function, like discovering devices or resolving domains. For example:
```
/usr/libexec/colord-sane
/usr/sbin/avahi-daemon
/usr/libexec/dleyna-server-service
/lib/systemd/systemd-timesyncd
/usr/lib/systemd/systemd-resolved
/usr/sbin/ntpd
```

Some applications launch external processes, so for example, you may be prompted to allow application A, and just right away asked to allow application B.
This is the case with Epiphany web browser, gnome-maps, snap or Spotify: https://github.com/gustavo-iniguez-goya/opensnitch/issues/134#issuecomment-772876103
```
/usr/bin/epiphany
/usr/lib/x86_64-linux-gnu/webkit2gtk-4.0/WebKitNetworkProcess
```

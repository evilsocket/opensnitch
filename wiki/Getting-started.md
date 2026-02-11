After [installing opensnitch](https://github.com/evilsocket/opensnitch/wiki/Installation), notice that a new icon appeared on the systray:

![image](https://user-images.githubusercontent.com/2742953/122753129-1556cb80-d292-11eb-8a70-36a270132c56.png)


You can launch the GUI from that icon or from the system menu (Internet -> OpenSnitch)


The daemon should start intercepting connections, prompting you to allow or deny them. If you don't apply an action, after 30 seconds (configurable) it'll apply the default action configured.

![image](https://user-images.githubusercontent.com/2742953/122794725-da1dc200-d2bc-11eb-9f47-5fc3fc995db7.png)

<br/>

When you open the GUI, you'll see all the connections and processes that the daemon has intercepted. If you don't see connections being intercepted, or anything in <kbd>Status</kbd> or <kbd>Version</kbd>, make sure you've [installed](../Installation) the daemon package as well, not just the GUI. For other GUI issues, see the [known GUI problems](../GUI-known-problems).

Double click on a row of any view to review the details of a process, rule, host or user.

<img width="957" height="558" alt="Captura de pantalla de 2026-02-11 23-58-49" src="https://github.com/user-attachments/assets/a41bf2be-db2d-4c57-acea-805805dfe088" />


<img width="956" height="555" alt="Captura de pantalla de 2026-02-11 23-48-43" src="https://github.com/user-attachments/assets/ba829001-889d-4044-b1b8-d08df717e897" />


<br/>

> [!NOTE] 
> **Tip:** Configure the default action to Allow (<kbd>Preferences -> Pop-ups -> Action</kbd>, and optionally check [x] <kbd>Disable pop-ups</kbd>), let it run for a while (hours, days, weeks), and observe passively what your machine is doing.

<img width="802" height="551" alt="Captura de pantalla de 2026-02-11 23-58-4999" src="https://github.com/user-attachments/assets/55f0a7da-18fa-498f-a0f1-643a59dd9c22" />


This action has two advantages: you'll learn about your system and OpenSnitch will create the rules for you (<kbd>Rules</kbd> tab -> Temporary).

Remember to change it back to Deny.

<br/>

To view and modify the rules accumulated so far, click on the OpenSnitch icon in the System Tray. A GUI listing the rules will appear.
You can click on each rule and then click on the Trash Can icon to delete it. Or you can click on a rule and right-click on it to modify allow/deny or duration etc. The list may take up to 15 seconds to show the update in the GUI.

Note: if you modify the action of a rule (e.g. change from deny to allow), the name of it may not change (e.g. may stay as "deny-...").

<img width="995" height="456" alt="Captura de pantalla de 2026-02-11 23-38-13" src="https://github.com/user-attachments/assets/0d20156f-24be-4a3c-9dc7-5b328d37d449" />


<br/>

Once you have identified the common processes, IP addresses and hosts that your machine is connecting to, you can start creating permanent rules (`Duration: always`) to deny or allow them. You can also convert temporary rules into permanent ones by right-clicking on a temporary rule or by double-clicking on it, and then edit it.

<img width="995" height="329" alt="Captura de pantalla de 2026-02-11 23-38-14" src="https://github.com/user-attachments/assets/23476660-ce39-4b4b-bbbc-4bfda4decc11" />



A common practice is to apply a rule of "Least privilege", i.e., block everything by default and allow only those processes or connections that you want to.

[Read more about rules.](Rules)

[Read more about blocking lists](block-lists)



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

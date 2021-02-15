After installing opensnitch, the daemon will start intercepting connections and by default it'll allow them.

![](https://user-images.githubusercontent.com/2742953/85336535-0acaf000-b4df-11ea-9d69-c7bd7b597886.png)


When you open the GUI, you'll see all the connections and processes that has intercepted, and it'll prompt you to allow or deny new outgoing connections.

![](https://user-images.githubusercontent.com/2742953/85336893-bf651180-b4df-11ea-908e-6202e989a8ae.png)


The default action is to allow outgoing connections, so you can let it run for a while (hours, days, weeks), and observe what your machine is doing.

![](https://user-images.githubusercontent.com/2742953/85336695-55e50300-b4df-11ea-86d5-b70b78fd7896.png)


Once you know which are the common processes, IPs and hosts that your machine is connecting to, you can start creating rules to deny or allow them. 

A common practice is to apply a rule of "Least privilege", i.e., block all by default and allow only those processes or connections that you want to.

[Read more about rules.](Rules)


![](https://user-images.githubusercontent.com/2742953/85337403-b294ed80-b4e0-11ea-8c65-d8251c6af25b.png)

![](https://user-images.githubusercontent.com/2742953/85337070-136ff600-b4e0-11ea-838a-439366c70668.png)


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
```

Some applications launch external processes, so for example, you may be prompted to allow application A, and just right away asked to allow application B.
This is the case with Epiphany web browser, gnome-maps or snap: https://github.com/gustavo-iniguez-goya/opensnitch/issues/134#issuecomment-772876103
```
/usr/bin/epiphany
/usr/lib/x86_64-linux-gnu/webkit2gtk-4.0/WebKitNetworkProcess
```

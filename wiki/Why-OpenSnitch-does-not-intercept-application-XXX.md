**tl;dr**
- because we don't use eBPF.

- a process is opening connections too fast (nmap for example, firefox sometimes...).

- the system has a high load and we're unable to find the process in time.

- _netlink_ does not return the connection we're querying for, thus we can't search for the PID.

- the connection does not exist in `/proc/net/tcp|udp|udplite|`...

- the Inode does not exist under `/proc/<PID>/fd/`

- the PID entry does not exist under `/proc/`

Some discussions you may want to read: [#10](https://github.com/gustavo-iniguez-goya/opensnitch/issues/10#issuecomment-608428026) and [#84](https://github.com/gustavo-iniguez-goya/opensnitch/issues/84#issuecomment-721663451)

***

In order to know what process opened a particular connection (in userspace), we need to perform at least 4 steps:

1. Intercept the connection using iptables and redirect it to us.

2. Find the socket inode of the connection (SockFS):

   2.1 Using ProcFS

   2.2 or using netlink

3. Find the PID of the connection:

   3.1 Using auditd

   3.2 or using Ftrace (kprobes)

   3.3 or using ProcFS

4. Find the application name and the command line (and (optionally) the directory from where it was executed):

   4.1 Using auditd

   4.2 Using ProcFS

# 
### 1. Intercept the connection using iptables and redirect it to us.

When a new connection is opened, 5 steps happen in the system (well, [many more](https://makelinux.github.io/kernel/map/), but for simplicity sake):
1. An application creates a socket() [[0]](#0---how-linux-creates-sockets).
2. A socket Inode is allocated [[1]](#1---Demystifying-the-Linux-Kernel-Socket-File-Systems).
3. The connection details are dumped to `ProcFS` [kernel procfs documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html?highlight=proc) [man](https://www.tldp.org/LDP/Linux-Filesystem-Hierarchy/html/proc.html).
4. The connection travels through iptables [[2]](#2---the-netfilter-framework).
5. The connection leaves the system.

When it is about to leave the system, we don't know the socket Inode nor the PID of the process who created it, thus we can't show the name of the process who created the connection to the user. What we only know is the connection details: source port/IP and destination port/IP (and usually the UID of the user who opened it).

That's why we need to find the PID using different mechanisms (asking the kernel via [netlink](#5---netlink-howto), parsing /proc, eBPF...).

We know that the path a new connection follows when it's created by a local process is as follow:

socket() -> ::route decision:: -> <IPTABLES> (RAW chain)OUTPUT -> [conntrack module] -> (MANGLE chain)OUTPUT -> ::reroute if needed:: -> (NAT table)OUTPUT -> (FILTER table)OUTPUT -> (* table)POSTROUTING <IPTABLES>

![](https://i.stack.imgur.com/YkwUi.png)

If we use a [netfilter queue](https://home.regit.org/netfilter-en/using-nfqueue-and-libnetfilter_queue/), then we can redirect every connection to a queue:

> iptables -t mangle -I OUTPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass

If we launch a process that listens on that queue, we can get the details of every NEW connection that is opened.

So, we know that a connection is about to leave the system, and now we have the source port/ip and destination/port, how do we find out the PID of the process?

**Notes:**
> In this case we only redirect NEW connections in the _mangle_ table. That means that we can access and use the information of connections statuses provided by the conntrack kernel module. [[1]](#1---Demystifying-the-Linux-Kernel-Socket-File-Systems).
>
> nanoseconds prior to this point, a socket has been created by a local process, but it may be too late to get the socket Inode (if it's written to `/proc` at all) or the application can bypass that rule by crafting a special packet with an invalid state.
>
> One thing you can play with is, to add a rule to intercept connections in the RAW table:
> > iptables -t raw -I OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass
>
> Notice that at this point of the path, we can't know if a connection is NEW, ESTABLISHED or INVALID, so every packet is forwarded to opensnitch. That means that the performance may be degraded, using too much CPU. 
>
> But on the other hand, we're intercepting connections faster and earlier than on the MANGLE table, so maybe we can get processes faster and not miss them.
>
> You can also add the following rule (notice that we exclude ESTABLISHED state):
> > iptables -t mangle -I OUTPUT -m conntrack --ctstate NEW,RELATED,INVALID,SNAT,DNAT -j NFQUEUE --queue-num 0 --queue-bypass


#
### 2. Find the socket Inode of the connection (sockfs)

In order to identify a connection we need an Inode. Basically because there's no way to get the PID directly (without using eBPF). If you realize, we're going backwards, undoing what the kernel did (sys_socket() -> sock_create() -> sock_alloc() -> sock_alloc_inode() -> <iptables>).

What we know at this point?

Socket Inodes are written to `/proc/<PID>/fd/` (and `/proc/<PID>/task/<TID>/fd/`). The files written there are symlinks (not exactly, but neverminds now), and point to the type of object it points to, for example:
```
$ ls -l /proc/1/fd/
lrwx------. 1 root root 64 mar  8 16:37 99 -> 'socket:[18403475]'
lrwx------. 1 root root 64 mar  8 16:37 99 -> 'anon_inode:[eventpoll]'
lrwx------. 1 root root 64 mar  8 16:37 99 -> 'anon_inode:[timerfd]'
```
As we see, the first link is a socket, and the number is the inode. We can search `/proc/net/` to try to know to what connection is linked to:
```
$ grep 18403475 /proc/net/*
/proc/net/unix:ffff9a16790e1800: 00000003 00000000 00000000 0001 03 18403475 /run/systemd/journal/stdout
```

In this case, it's a UNIX socket, and the connection in this case is a Path to a file in the filesystem (`/run/systemd/journal/stdout`)



So knowing that we can parse `/proc/net` for connections and inodes, when a new connection is redirected to our process, we can search for it in `/proc/net/` because we know the source port, source IP, destination port and destination IP.
```
$ cat /proc/net/tcp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 0100007F:13AD 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 18083222 1 ffff9a1677a8cec0 100 0 0 10 0
```

Parsing `/proc` is easy and very straightforward. But it has its caveats, specially with UDP connections. In many occasions, when you parse `/proc/net/udp` the connection is already gone. Not to mention, that hiding connections from ProcFS is a common practice by malware.

So, what can we do? We can use `netlink` and `sock_diag`.

What is netlink? from [man 7 netlink](http://man7.org/linux/man-pages/man7/netlink.7.html):
> Netlink is used to transfer information between the kernel and user-space processes.

What is sock_diag? from [man sock_diag](http://man7.org/linux/man-pages/man7/sock_diag.7.html):
>        The sock_diag netlink subsystem provides a mechanism for obtaining
>        information about sockets of various address families from the
>        kernel.  This subsystem can be used to obtain information about
>        individual sockets or request a list of sockets.

>        In the request, the caller can specify additional information it
>        would like to obtain about the socket, for example, memory
>        information or information specific to the address family.

When we ask the kernel for a specific socket, it responds with a struct with the following fields:
```
           struct inet_diag_msg {
               __u8    idiag_family;
               __u8    idiag_state;
               __u8    idiag_timer;
               __u8    idiag_retrans;

               struct inet_diag_sockid id;

               __u32   idiag_expires;
               __u32   idiag_rqueue;
               __u32   idiag_wqueue;
               __u32   idiag_uid;
               __u32   idiag_inode; <---
           };
```

So there it is, the inode. How do we query netlink for a particular connection? We can use the following struct with the details of the connection:

```
           struct inet_diag_sockid {
               __be16  idiag_sport;
               __be16  idiag_dport;
               __be32  idiag_src[4];
               __be32  idiag_dst[4];
               __u32   idiag_if;
               __u32   idiag_cookie[2];
           };
```

The query is something like "ok netlink, give me the Inode of the connection net_diag_sockid{ diag_sport = 45678; diag_dport = 53; idiag_dst="1.1.1.1" }", and netlink will response with that connection details.

However netlink does not always return a match (TODO: explain why), specially for UDP/broadcast connections.
In these cases we can query just for the source port of the connection, which normally will return just one entry, and in some cases (ntp) it will return several inodes for the same srcPort:srcIP<->dstIP:dstPort connection.


# 
### 3. Find the PID of the connection


Once we find the Inode, the next thing is to search for it under `/proc`, looking for it under every PID directory. pseudocode:
```
for pid in $(ls /proc)
do
  ls -l /proc/$pid/fd/ | grep 27449873
  if [ $? -eq 0 ]; then
    echo "found: $(cat /proc/$pid/cmdline)"
    break
  fi
done
```
```
lrwx------. 1 ga ga 64 mar  8 16:32 109 -> socket:[27449873]
found: /usr/bin/iceweasel
```

easy, right? It is. However, when we reach to this point, the process may have already exited, or the socket being closed. It's not accurate, and besides, many rootkits hide their activity from `/proc` (PIDs, connections, etc).

What options do we have then?
One approach is to have a list of known PIDs, this is, a list of PIDs which have opened connections. 

We listen asynchronously for PIDs which open sockets, and when a connection hits the NFQUEUE target and it's redirected to our process, we can get the Inode and search for the PID in a very small list of PIDs. That increase the chances to get the correct PID/process name.

> Another trick is by sorting /proc entries by modified time. Processes that opened a socket will be at the top.

We can also accomplish it using different methods:

#### auditd
> auditd  is the userspace component to the Linux Auditing System. It's responsible for writing audit records to the disk

[Linux Auditing System](https://github.com/linux-audit/audit-kernel):
> The Linux Audit subsystem provides a secure logging framework that is used to capture and record security relevant events. It consists of a kernel component which generates audit records based on system activity, a userspace daemon which logs these records to a local file or a remote aggregation server, and a set of userspace tools to for audit log inspection and post-processing.

We can add rules to auditd, to filter for sycalls, thus we can filter by socket/socketpair/connect/execve, etc:
> auditctl -a exit,always -F arch=b64 -S socket,connect,bind -k opensnitch

Now if you look in journalctl, you'll see a lot of auditd messages:
```
mar 08 18:37:48 ono-sendai audit[12704]: SYSCALL arch=c000003e syscall=41 success=yes exit=204 a0=a a1=2 a2=0 a3=7f02480008d0 items=0 ppid=12654 pid=12704 auid=1000 uid=1000 gid=1000 euid=1000 suid>
mar 08 18:37:48 ono-sendai audit: PROCTITLE proctitle="iceweasel"
mar 08 18:37:48 ono-sendai audit: PATH item=0 name="/run/user/1000/bus" inode=41813 dev=00:15 mode=0100400 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:var_run_t:s0 nametype=NORMAL cap_fp=0 c>
mar 08 18:37:48 ono-sendai audit: CWD cwd="/tmp"
mar 08 18:37:48 ono-sendai audit: SOCKADDR saddr=01002FF2756E2F7FF573613030302F343435627573
```

If you look close enough, you'll see that it's reporting the PID which opened the socket (pid=12704). And this is reported very fast, as soon as it happens.

Thus, we can go directly to `/proc/<PID>`, without having to iterate over all the `/proc` entries.

#### FTrace (kprobes)
Another method we can use is ftrace:

https://www.kernel.org/doc/html/latest/trace/ftrace.html

> Ftrace is an internal tracer designed to help out developers and designers of systems to find what is going on inside the kernel. It can be used for debugging or analyzing

Ftrace uses the `debugfs` file system, which is mounted at /sys/kernel/debug/. It's enabled by default, but some users disables it or some distributions do not enable it by default.

For brevity shake, I'll point you to the documentation to learn more about this world.

We can tell the kernel to log every new connection, socket, process, file, etc that is opened in the system as follow:
```
# cd /sys/kernel/debug/tracing/
# echo 'p:m security_socket_connect' > krpobe_events
# echo 1 > events/kprobes/m/enable
# cat trace_pipe
```

and the output:
```
 Chrome_ChildIOT-14550   [000] .... 119979.685064: m: (security_socket_connect+0x0/0x50)
 opensnitchd-3289        [006] .... 119980.096912: m: (security_socket_connect+0x0/0x50)

```
As you can see, as soon as a program opens a new connection (security_socket_connect), it's written to `trace_pipe` along with the PID and the common name of the process. We could also get the source port/IP and destination port/IP.

Using this method we don't have to lookup the inode of the connection, we'd just go directly to `/proc/<PID>/` to get the path of the process.

### ProcFS

***

**References:**

##### 0 - How Linux creates sockets
https://ops.tips/blog/how-linux-creates-sockets/

##### 1 - Demystifying the Linux Kernel Socket File Systems
http://www.voidcn.com/article/p-kxdmdjfh-zd.html

##### 2 - The netfilter framework
https://people.netfilter.org/pablo/docs/login.pdf

##### 3 - RAW sockets
https://sock-raw.org/papers/sock_raw

##### 4 - netlink howto
https://lwn.net/Articles/208755/

##### 5 - Linux kernel networking overview
https://linux-kernel-labs.github.io/refs/heads/master/labs/networking.html#

##### 7 - Simple UDP Server
https://kernelnewbies.org/Simple_UDP_Server

##### 8 - Disco Wall source code, an Android Firewall using NFQUEUE
https://github.com/T7o7heVV/DiscoWall

##### 9 - DiscoWall: Design And Implementation Of A Firewall For Android Phones
http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.705.2552&rep=rep1&type=pdf

##### 10 - A deep dive into iptables and netfilter architecture
https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture
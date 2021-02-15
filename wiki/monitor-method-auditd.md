In order to use auditd to get the name of a process which is opening a new connection, you have to install and configure it first.

On Debian/Ubuntu:

* apt install auditd audispd_plugins
* enable af_unix plugin `/etc/audisp/plugins.d/af_unix.conf` (active = yes)
* add a test rule: `auditctl -a always,exit -F arch=b64 -S socket,connect,execve -k test`
  * increase `/etc/audisp/audispd.conf` q_depth if there're dropped events: q_depth = 4096)
  * set `write_logs` to no if you don't need/want audit logs to be stored in the disk.

* read messages from the pipe to verify that it's working:
  `socat unix-connect:/var/run/audispd_events stdio`
   
  You'll see lot of messages like these ones:
```
mar 08 18:37:48 ono-sendai audit[12704]: SYSCALL arch=c000003e syscall=41 success=yes exit=204 a0=a a1=2 a2=0 a3=7f02480008d0 items=0 ppid=12654 pid=12704 auid=1000 uid=1000 gid=1000 euid=1000 suid>
mar 08 18:37:48 ono-sendai audit: PROCTITLE proctitle="iceweasel"
mar 08 18:37:48 ono-sendai audit: PATH item=0 name="/run/user/1000/bus" inode=41813 dev=00:15 mode=0100400 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:var_run_t:s0 nametype=NORMAL cap_fp=0 c>
mar 08 18:37:48 ono-sendai audit: CWD cwd="/tmp"
mar 08 18:37:48 ono-sendai audit: SOCKADDR saddr=01002FF2756E2F7FF573613030302F343435627573
```

**Possible errors:**

* `AuditReader: auditd error%!(EXTRA *net.OpError=read unix @->/var/run/audispd_events: use of closed network connection)`
  
   You need to restart auditd (service auditd restart)


**More information on this system:**

Audit event fields:
https://github.com/linux-audit/audit-documentation/blob/master/specs/fields/field-dictionary.csv

Record types:
https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/sec-Audit_Record_Types.html

Documentation:
https://github.com/linux-audit/audit-documentation

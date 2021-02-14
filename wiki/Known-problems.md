[GUI crash/exception/does not show up](#GUI-crash-exception-or-does-not-show-up):
* NameError: name 'unicode' is not defined
* ModuleNotFoundError: No module named 'grpc'
* Others...

[no icons on the GUI](#no-icons-on-the-GUI)

[GUI size problems on 4k monitors](#GUI-size-problems-on-4k-monitors)

[OpenSnitch icon doesn't show up on Gnome-Shell](#OpenSnitch-icon-does-not-show-up-on-gnome-shell)

[opensnitchd/daemon does not start](#opensnitchd-does-not-start):
* `Error while creating queue #0: Error binding to queue: operation not permitted.`
* `Error while enabling probe descriptor for opensnitch_exec_probe: write /sys/kernel/debug/tracing/kprobe_events: no such file or directory`
* `Error while creating queue #0: Error binding to queue: operation not permitted.`
* `Error opening Queue handle: protocol not supported`
* `Could not open socket to kernel: Address family not supported by protocol (IPv6)`
* `Error while creating queue #0: Error unbinding existing q handler from AF_INET protocol` see [#323](https://github.com/evilsocket/opensnitch/issues/323). Issue not solved, if you can provide more information open a new issue please.

[Kernel panic on >= 5.6.16 || kernel hardening incompatibilities](#kernel-panics)

***

### GUI crash/exception or does not show up

If you have installed it by double clicking on the pkgs, using a graphical installer, try to install it from command line:

> $ sudo dpkg -i `*opensnitch*deb`; sudo apt -f install

See [issue #25](https://github.com/gustavo-iniguez-goya/opensnitch/issues/25), [issue #16](https://github.com/gustavo-iniguez-goya/opensnitch/issues/16) and [issue #32](https://github.com/gustavo-iniguez-goya/opensnitch/issues/32) for additional information.

--

You have to install `unicode_slugify` and `grpcio-tools`, usually not available in many distros. You can install them using pip:

```
pip3 install unicode_slugify
pip3 install grpcio-tools
```

--

Check that you don't have a previous installation of opensnitch GUI in _/usr/lib/python3*/*/opensnitch/_ or _/usr/local/lib/python3*/*/opensnitch/_

If you have a previous installation remove it, and install the GUI again (you may have an installation of the original repo). 

If it doesn't work, report it describing the steps to reproduce it, and the exception or log. For example:
```
Traceback (most recent call last):
  File "/usr/lib/python3.8/site-packages/opensnitch/dialogs/prompt.py", line 362, in _on_apply_clicked
    self._rule.name = slugify("%s %s %s" % (self._rule.action, self._rule.operator.type, self._rule.operator.data))
  File "/usr/lib/python3.8/site-packages/slugify.py", line 24, in slugify
    unicode(
NameError: name 'unicode' is not defined
```

--

For ArchLinux/Manjaro users this worked:
> installed was from AUR python-unicode-slugify-git r43.b696c37-1

> removed it and installed python-unicode-slugify 0.1.3-1.

--

### No icons on the GUI

Be sure that you have properly set the icon theme of your Window Manager. [More information](https://github.com/gustavo-iniguez-goya/opensnitch/issues/53#issuecomment-671419790)

### GUI size problems on 4k monitors

Some users have reported issues displaying the GUI on 4k monitors. See [#43](https://github.com/gustavo-iniguez-goya/opensnitch/issues/43) for more information.

Setting these variables may help:

```
export QT_AUTO_SCREEN_SCALE_FACTOR=0
export QT_SCREEN_SCALE_FACTORS=1 (or 1.25, 1.5, 2, ...)
```

In case of multiple displays:
`export "QT_SCREEN_SCALE_FACTORS=1;1"`

--

### OpenSnitch icon does not show up on Gnome-Shell

On Gnome-Shell >= 3.16, systray icons have been removed. You have to install the extension [gnome-shell-extension-appindicator](https://extensions.gnome.org/extension/615/appindicator-support/) to get them back.

1. Download latest version - https://github.com/ubuntu/gnome-shell-extension-appindicator/releases
2. Install it with your regular user: `gnome-extensions install gnome-shell-extension-appindicator-v33.zip`

See this comment/issue for more information: [#44](https://github.com/gustavo-iniguez-goya/opensnitch/issues/44#issuecomment-654373737)

--

### opensnitchd does not start

A common error you may encounter (in the original repo):

> [2019-08-08 11:51:14]  !!!  Error while enabling probe descriptor for opensnitch_exec_probe: write /sys/kernel/debug/tracing/kprobe_events: no such file or directory

This is because opensnitch uses [ftrace](https://www.kernel.org/doc/Documentation/trace/ftrace.txt) to get running processes (PIDs). 

`ftrace` mounts a file system called _debugfs_ in /sys/kernel/debugfs, and outputs kernel events to _/sys/kernel/debugfs/tracing/trace_ and _/sys/kernel/debugfs/tracing/trace_pipe_

If for some reason those files can not be opened, opensnitch will not work. 

Some reasons because `ftrace` is not available:

* debugfs is not mounted. If it's mounted you should see a similar output:
```
  $ mount | grep debugfs
  none on /sys/kernel/debug type debugfs (rw)
  $
```

* log in syslog or journalctl: _Lockdown: opensnitchd: Use of kprobes is restricted; see man kernel_lockdown.7_

Quoting `anreiple` in issue [#235](https://github.com/evilsocket/opensnitch/issues/235):

> Since kernel 4.17 if you have UEFI Secure Boot enabled then kernel does lockdown - using kernel probes, 3rd party kernel modules (even signed), etc is restricted

Starting from version [v1.0.0-rc3](https://github.com/gustavo-iniguez-goya/opensnitch/releases/tag/v1.0.0-rc3), there's an alternative method to workaround this problem.

---

**Error while creating queue #0: Error binding to queue: operation not permitted**
> [2020-06-13 17:07:34]  !!!  Error while creating queue #0: Error binding to queue: operation not permitted.

Fixed in 1.0.0rc10. If you still see this error open a new issue and [provide the following information](https://github.com/gustavo-iniguez-goya/opensnitch/issues/18#issuecomment-643661484)

***

**Address family not supported**

[See this issue for more information](https://github.com/gustavo-iniguez-goya/opensnitch/issues/52)

***

**Error opening Queue handle: protocol not supported**
> [2020-10-09 19:11:15]  !!!  Error while creating queue #0: Error opening Queue handle: protocol not supported

Check that you have the needed iptables modules loaded: nfnetlink, nfnetlink_queue and x_tables.

`# lsmod | grep nfnetlink`

See this issue [#71](https://github.com/gustavo-iniguez-goya/opensnitch/issues/71) for more information.

***

### Kernel panics

Some users have reported kernel panics with kernel 5.6.16 ([#297](https://github.com/evilsocket/opensnitch/issues/297)) and other kernels([#41](https://github.com/gustavo-iniguez-goya/opensnitch/issues/41)). **deathtrip** found that the culprit in his/her case was a configuration of the Arch's [linux-hardened](https://www.archlinux.org/packages/extra/x86_64/linux-hardened/) kernel command line option. 

Removing the following options from the kernel booting parameters solved the issue:

`slab_nomerge, slub_debug=FZP and page_alloc.shuffle=1`

On Debian with kernel 5.7.0, remove `slub_debug=FZP` if you have it configured and try again.

**Note:** This was caused by [a bug in the libnetfilter_queue library](https://bugzilla.netfilter.org/show_bug.cgi?id=1440).
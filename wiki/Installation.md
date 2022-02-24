### Installation using the packages

(get the packages from here: https://github.com/evilsocket/opensnitch/releases)

**tl;dr: use the command line**

#### DEB
> $ sudo apt install ./opensnitch*.deb ./python3-opensnitch-ui*.deb

#### RPM
> $ sudo yum localinstall opensnitch-1*.rpm; sudo yum localinstall opensnitch-ui*.rpm 

(You can also double-click on the downloaded files)

**Remember:**

If the daemon doesn't start after installing these packages (or others from other distributions), enable and start it manually:
```
sudo systemctl enable --now opensnitch
sudo systemctl start opensnitch
```

(use `opensnitchd` if `opensnitch` doesn't work)

**Note:**

This packages are provided to you in the aim of being useful and ease the installation. They have some no-no's (like calling pip on post install scripts), and apart from that don't expect them to be bug free or lintian errors/warnings free.


***

**Errors?**

- LinuxMint <= 19: see: [#16](https://github.com/gustavo-iniguez-goya/opensnitch/issues/16) or `apt-get install g++ python3-dev python3-wheel python3-slugify`
- MXLinux <= 19.x: You need to install additional packages: `apt-get install python3-dev python3-wheel`
- Pop!_ OS: if you find that opensnitch is not behaving correctly (it slowdowns your system for some reason), reinstall it using the one-liner above from the command line. It seems that there're troubles installing it using the graphical installer `eddy`.
- Ubuntu 16.04.x: Do not install the dependencies when the installer ask you to do so. After installing the package execute: `sudo pip3 install grpcio==1.16.1 protobuf`
- /etc/opensnitchd/opensnitch.o: no such file or directory (#554) -> you need to compile the [ebpf module](https://github.com/evilsocket/opensnitch/tree/master/ebpf_prog), or install it if your distro packages it as a package (https://aur.archlinux.org/packages/opensnitch-ebpf-module/)

---

The reason for installing some dependencies using `pip` is that they are not always packaged in all distributions and all versions (`python3-grpcio` on Ubuntu is only available from >= 19.x). Moreover, Ubuntu 20.04 `python3-grpcio` (version 1.16.1) differs from official 1.16.x that causes some working problems. 

**Besides, grpc packages distributed with some distributions (python3-grpcio, OpenSuse) do not work.**

If you still don't want to install those pip packages, you'll need to install the following packages:
```
$ sudo apt install python3-grpcio python3-protobuf python3-slugify
```

* On Ubuntu you may need to add _universe_ repositories.
* If you install them using a graphical installer and fails, launch a terminal and type the above commands. See the [common errors](https://github.com/gustavo-iniguez-goya/opensnitch/wiki/Known-problems) for more information.


You can download them from the [release](https://github.com/gustavo-iniguez-goya/opensnitch/releases) section.

**Note:**
Select the right package for your architecture: `$(uname -m) == x86_64` -> opensnitch*...**amd64**.deb, `$(uname -m) == armhf` -> opensnitch*...**arhmf**.deb, etc.

***

**These packages have been (briefly) tested on:**
 * Daemon ([v1.4.0rc2](https://github.com/evilsocket/opensnitch/releases)):
   - RedHat Enterprise >= 7.0
   - CentOS 8.x
   - Fedora >= 24
   - Debian >= 8
   - LinuxMint >= 18
   - Ubuntu >= 16 (works also on 14.04, but it lacks upstart service file. **dpkg must be at least .1.17.x**)
   - OpenSuse
   - Pop!_OS
   - MX Linux 19.x
   - PureOS (Librem5)
 * UI ([v1.4.0rc2](https://github.com/evilsocket/opensnitch/releases)):
   - Debian >= 9
   - Ubuntu >= 16.x
   - Fedora >= 29
   - OpenSuse Tumbleweed 15.3
   - LinuxMint >= 18 
   - MX Linux 19.x
   - Pop!_OS
   - PureOS (Librem5)

 * Window Managers:
   - Cinnamon
   - KDE
   - Gnome Shell (no systray icon? [see this for information](Known-problems#OpenSnitch-icon-does-not-show-up-on-gnome-shell))
   - Xfce
   - i3

Note: You can install the UI from the sources, using pip3, and it'll work in some more distributions. Not in Fedora <= 29 due to lack of PyQt5 libraries.


***

### Upgrading opensnitch

Use the installation commands mentioned above. The package managers will take care of the upgrading process.
(you don't need to uninstall previous version in order to install a new one).

### Uninstalling opensnitch

These steps will remove opensnitch from your system. That includes the rules and the configuration.

**Note:** If you're installing a new version, you don't need to uninstall the old one first. Just install the new version, and it'll be upgraded.

**deb packages:**

Remove the package, keeping the configuration and rules:
- `apt remove opensnitch python3-opensnitch-ui`

Remove the packages + rules + configuration:
- `apt remove --purge opensnitch python3-opensnitch-ui`

**rpm packages**

- `yum remove opensnitch opensnitch-ui` or `zypper remove opensnitch opensnitch-ui`

If you installed pip packages:
- `pip3 uninstall grpcio grpcio-tools unicode_slugify pyinotify PyQt5`

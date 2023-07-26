As a general rule of thumb, if the GUI crashes or doesn't show up, open a terminal and type: `~ $ opensnitch-ui`

It'll display more details.

Be sure before launching it that no other `opensnitch-ui` process is running (`pgrep opensnitch-ui`).
Also check how much CPU the process `opensnitch-ui` is consuming. If it consumes 90-100% of the CPU continuously it may be this Ubuntu bug: #647


### GUI does not show up

When the GUI starts, you should have a new icon in your systray -> ![image](https://github.com/evilsocket/opensnitch/assets/2742953/406fa487-be93-425d-abab-82770e2409dc)

👉 If there's no icon, most probably your Window Manager or Desktop Environment does not support systray icons.
If you're running GNOME you need to install this extension -> https://github.com/ubuntu/gnome-shell-extension-appindicator
(check if it's available for your distribution)

See the instructions detailed below to see how enable it.

👉 On the other hand, if you're running **LinuxMint <= 21.1** or **ubuntu <= 22.10**, see if the process `opensnitch-ui` is consuming 100% of the CPU.
See this issue for more information: https://github.com/evilsocket/opensnitch/issues/647#issuecomment-1383956333

### GUI takes 10 to 20s to show up

Same problem than above, sytray icons not supported. Install the `gnome-shell-extension-appindicator`, and follow the instructions detailed below.

### OpenSnitch icon does not show up on Gnome-Shell

On Gnome-Shell >= 3.16, systray icons have been removed. You have to install the extension gnome-shell-extension-appindicator to get them back.

    Download latest version - https://github.com/ubuntu/gnome-shell-extension-appindicator/releases
    Install it with your regular user: gnome-extensions install gnome-shell-extension-appindicator-v33.zip

```bash
~ $ sudo yum install gnome-shell-extension-appindicator.noarch
# RESTART GNOME: logout or press ALT+F2 and type 'r'
~ $ gnome-extensions enable appindicatorsupport@rgcjonas.gmail.com
~ $ killall opensnitch-ui
```

See this comment/issue for more information: [#44](https://github.com/evilsocket/opensnitch/issues/44).


### Random crashes or problems on Wayland

PyQt5 doesn't seem to be fully supported on Wayland. For example the pop-ups are not correctly positioned on the screen, or the main window crashes randomly:

> The Wayland connection experienced a fatal error: Protocol error

In these cases, try launching the GUI as follow:

`~ $ QT_QPA_PLATFORM=xcb opensnitch-ui`


### Opensnicth GUI not working across reboots

If after installing OpenSnitch and reboot, the GUI does not show up upon login to your Desktop Environment, be sure that the following path exists in your $HOME:

`~ $ ls ~/.config/autostart/opensnitch_ui.desktop`

If it doesn't exist, create it:

```bash
~ $ mkdir -p ~/.config/autostart/
~ $ ln -s /usr/share/applications/opensnitch_ui.desktop ~/.config/autostart/
```

If you have installed the GUI from the repositories of a distribution, tell the maintainer of the package to create that symbolic link after installation.

see issue [#434](https://github.com/evilsocket/opensnitch/issues/434#issuecomment-859968103) for more information.


### The GUI does not change to dark style theme

It's usually a problem of the Desktop Environment. You can try to configure the theme by using `qt5ct`, or executing the following commands:

```bash
~ $ sudo apt-get install -y qt5-style-plugins
~ $ sudo cat << EOF | sudo tee  /etc/environment
QT_QPA_PLATFORMTHEME=gtk2
EOF
```

More info: [#303](https://github.com/evilsocket/opensnitch/issues/303)

Since version v1.5.1, you can change GUI theme from the Preferences -> UI -> Theme . You'll need to install qt-material: `~ $ pip3 install qt-material`


### No icons on the GUI

Be sure that you have properly set the icon theme of your Window Manager.

Launch the GUI as follow and see if the icons show up: `~ $ XDG_CURRENT_DESKTOP=GNOME opensnitch-ui`

Alternatively, install `qt5ct`, launch it an go to the "Icons Theme" tab. Select an icon theme an click on Apply.

Then launch the GUI as follow: `~ $ QT_QPA_PLATFORMTHEME=qt5ct`

If either of these methods work, add the variable to your `~/.bashrc` or `/etc/environment`.

[More information](https://github.com/evilsocket/opensnitch/discussions/998?converting=1#discussioncomment-6556549)

[old information](https://github.com/gustavo-iniguez-goya/opensnitch/issues/53#issuecomment-671419790)


### GUI crash/exception/does not show up on old distros (ubuntu 16, 18, ...)

You have to install `unicode_slugify` and `grpcio-tools`, usually not available in old distros. You can install them using pip:

```bash
$ pip3 install grpcio==1.16.1
$ pip3 install unicode_slugify
$ pip3 install protobuf==3.6
```

You may need to uninstall setuptools if it keeps failing: `~ $ pip3 uninstall setuptools`


### GUI crash/exception or does not show up

If you have installed it by double clicking on the pkgs, using a graphical installer, try to install it from command line:

> $ sudo dpkg -i `*opensnitch*deb`; sudo apt -f install

See [issue #25](https://github.com/gustavo-iniguez-goya/opensnitch/issues/25), [issue #16](https://github.com/gustavo-iniguez-goya/opensnitch/issues/16) and [issue #32](https://github.com/gustavo-iniguez-goya/opensnitch/issues/32) for additional information.


***

### TypeError: new() got an unexpected keyword argument ...

This error means that your `python3-protobuf` is not compatible with OpenSnitch. Try uninstalling or upgrading it.
If the GUI keeps failing with the same error, install protobuf using pip3: `~ $ pip3 install protobuf==3.6`

Check that you don't have a previous installation of opensnitch GUI in /usr/lib/python3*/*/opensnitch/ or /usr/local/lib/python3*/*/opensnitch/

If you have a previous installation remove it, and install the GUI again (you may have an installation of the original repo).

If it doesn't work, report it describing the steps to reproduce it, and the exception or log. For example:

```bash
Traceback (most recent call last):
  File "/usr/lib/python3.8/site-packages/opensnitch/dialogs/prompt.py", line 362, in _on_apply_clicked
    self._rule.name = slugify("%s %s %s" % (self._rule.action, self._rule.operator.type, self._rule.operator.data))
  File "/usr/lib/python3.8/site-packages/slugify.py", line 24, in slugify
    unicode(
NameError: name 'unicode' is not defined
```

For ArchLinux/Manjaro users this worked:

>    installed was from AUR python-unicode-slugify-git r43.b696c37-1
>    removed it and installed python-unicode-slugify 0.1.3-1.


### GUI size problems on 4k monitors

Some users have reported issues displaying the GUI on 4k monitors. See [#43](https://github.com/evilsocket/opensnitch/issues/43) for more information.

Setting these variables may help:
```bash
~ $ export QT_AUTO_SCREEN_SCALE_FACTOR=0
~ $ export QT_SCREEN_SCALE_FACTORS=1 (or 1.25, 1.5, 2, ...)
```

In case of multiple displays: `~ $ export "QT_SCREEN_SCALE_FACTORS=1;1"`


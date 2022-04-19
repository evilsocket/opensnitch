Events window themes
---

Starting from version v1.5.1, OpenSnitch GUI can be customized with themes. You'll need to install the package [qt-material](https://github.com/UN-GCPDS/qt-material) with pip:

`$ python3 -m pip install qt-material`

![image](https://user-images.githubusercontent.com/2742953/164109352-fa849063-ef38-4a93-ae8f-1bf58f3d593a.png)


From the Preferences dialog, click on the UI tab:

![image](https://user-images.githubusercontent.com/2742953/164109119-8b1fef02-08f9-4c8e-82bb-b467e79214c4.png)

After installing `qt-material`, restart the GUI, and you'll be able to select a theme:

![image](https://user-images.githubusercontent.com/2742953/164109477-8f73a845-26ac-450d-98b8-d43139a80e66.png)

Select a theme, and restart the GUI to apply the changes:

![image](https://user-images.githubusercontent.com/2742953/164109604-90396d85-929f-4a62-99d9-50909eb7155e.png)


How to create your own theme
---

OpenSnitch will let you select the themes shipped by default with `qt-material` and the ones located under `~/.config/opensnitch/` with extension `.xml`

For example, you can copy a theme to that directory: `$ cp .local/lib/python3.9/site-packages/qt_material/themes/dark_red.xml .config/opensnitch/my-dark-theme.xml`

The new theme should appear after restarting the GUI. Then you can open it and customize the colors.

Learn more:  https://github.com/UN-GCPDS/qt-material#custom-colors

You can customize more options than just the colors, but it's not implemented yet. Open a [new issue](https://github.com/evilsocket/opensnitch/issues/new/choose) asking for it please.

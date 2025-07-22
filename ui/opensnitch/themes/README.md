 
 The GUI appearance can be customized with the package `qt-material`:

 `~ $ pip3 install qt-material`

 Besides the default themes shipped with `qt-material`, it's possible to create
 new themes.

 The GUI search for new themes under `/usr/lib/python3*/site-packages/opensnitch/themes` and
 `/home/<user>/.config/opensnitch/themes/`.

 The name of the files define the name of theme, and must end in .xml, for example:
  - dark_white.xml -> Theme name: dark_white

 Guide to create new themes: https://qt-material.readthedocs.io/en/latest/notebooks/01-customization.html

 Example for `/home/<user>/.config/opensnitch/themes/dark_white.xml`:

 ```
<!--?xml version="1.0" encoding="UTF-8"?-->
<resources>
  <color name="primaryColor">#ffffff</color>
  <color name="primaryLightColor">#8a8a8a</color>
  <color name="secondaryColor">#232629</color>
  <color name="secondaryLightColor">#4f5b62</color>
  <color name="secondaryDarkColor">#31363b</color>
  <color name="primaryTextColor">#000000</color>
  <color name="secondaryTextColor">#d1d1d1</color>
</resources>
 ```

 If you create a new theme, feel free to open a new PR, adding the theme to this
 directory.

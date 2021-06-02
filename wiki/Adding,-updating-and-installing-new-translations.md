Read all the information relative to GUI internazionalization here:

https://github.com/evilsocket/opensnitch/tree/master/ui/i18n

Besides translating the .ts files, there're also a few more files that you can translate:

https://github.com/evilsocket/opensnitch/blob/master/ui/resources/opensnitch_ui.desktop

Fields to translate:
- Comment: Add a new line like `Comment[YOUR_LANGUAGE_CODE]=`
- GenericName: Add a new line like `GenericName[YOUR_LANGUAGE_CODE]=`

For example: `Comment[hu]=Webalkalmazási tűzfal`

(The language code will be the first part of `echo $LANG`, ex.: en_US -> en, ca_ES -> ca, etc)

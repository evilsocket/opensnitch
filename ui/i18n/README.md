
### Adding a new translation:
0. Install needed packages: `apt install qtchooser pyqt5-dev-tools`
1. mkdir `locales/<YOUR LOCALE>/`
 (echo $LANG)
2. add the path to opensnitch_i18n.pro:
```
  TRANSLATIONS += locales/es_ES/opensnitch-es_ES.ts \
                  locales/<YOUR LOCALE>/opensnitch-<YOUR LOCALE>.ts
```
3. make

### Updating translations:

1. update translations definitions:
 - pylupdate5 opensnitch_i18n.pro

2. translate a language:
 - linguist locales/es_ES/opensnitch-es_ES.ts

3. create .qm file:
 - lrelease locales/es_ES/opensnitch-es_ES.ts -qm locales/es_ES/opensnitch-es_ES.qm

or:

1. make
2. linguist locales/es_ES/opensnitch-es_ES.ts
3. make

### Installing translations (manually)

In order to test a new translation:

`mkdir -p /usr/lib/python3/dist-packages/opensnitch/i18n/<YOUR LOCALE>/`
`cp locales/<YOUR LOCALE>/opensnitch-<YOUR LOCALE>.qm /usr/lib/python3/dist-packages/opensnitch/i18n/<YOUR LOCALE>/`

Note: the destination path may vary depending on your system.

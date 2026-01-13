#TEMPLATE = app
#TARGET = ts
#INCLUDEPATH += opensnitch


# Input
SOURCES += ../opensnitch/service.py \
        ../opensnitch/notifications.py \
        ../opensnitch/firewall/rules.py \
        ../opensnitch/firewall/__init__.py \
        ../opensnitch/customwidgets/addresstablemodel.py \
        ../opensnitch/customwidgets/firewalltableview.py \
        ../opensnitch/customwidgets/main.py \
        ../opensnitch/dialogs/events/tasks/netstat.py \
        ../opensnitch/dialogs/events/tasks/nodemon.py \
        ../opensnitch/dialogs/events/base.py \
        ../opensnitch/dialogs/events/config.py \
        ../opensnitch/dialogs/events/constants.py \
        ../opensnitch/dialogs/events/dialog.py \
        ../opensnitch/dialogs/events/menu_actions.py \
        ../opensnitch/dialogs/events/menus.py \
        ../opensnitch/dialogs/events/nodes.py \
        ../opensnitch/dialogs/events/queries.py \
        ../opensnitch/dialogs/events/views.py \
        ../opensnitch/dialogs/firewall_rule/constants.py \
        ../opensnitch/dialogs/firewall_rule/dialog.py \
        ../opensnitch/dialogs/firewall_rule/notifications.py \
        ../opensnitch/dialogs/firewall_rule/rules.py \
        ../opensnitch/dialogs/firewall_rule/statements.py \
        ../opensnitch/dialogs/firewall_rule/utils.py \
        ../opensnitch/dialogs/preferences/dialog.py \
        ../opensnitch/dialogs/preferences/settings.py \
        ../opensnitch/dialogs/preferences/utils.py \
        ../opensnitch/dialogs/preferences/sections/db.py \
        ../opensnitch/dialogs/preferences/sections/nodes.py \
        ../opensnitch/dialogs/preferences/sections/ui.py \
        ../opensnitch/dialogs/prompt/__init__.py \
        ../opensnitch/dialogs/prompt/utils.py \
        ../opensnitch/dialogs/prompt/details.py \
        ../opensnitch/dialogs/prompt/checksums.py \
        ../opensnitch/dialogs/prompt/constants.py \
        ../opensnitch/dialogs/ruleseditor/constants.py \
        ../opensnitch/dialogs/ruleseditor/dialog.py \
        ../opensnitch/dialogs/ruleseditor/nodes.py \
        ../opensnitch/dialogs/ruleseditor/rules.py \
        ../opensnitch/dialogs/ruleseditor/signals.py \
        ../opensnitch/dialogs/ruleseditor/utils.py \
        ../opensnitch/dialogs/processdetails.py \
        ../opensnitch/dialogs/firewall.py \
        ../opensnitch/dialogs/conndetails.py \
        ../opensnitch/plugins/versionchecker/versionchecker.py

FORMS += ../opensnitch/res/prompt.ui \
	    ../opensnitch/res/ruleseditor.ui \
	    ../opensnitch/res/preferences.ui \
	    ../opensnitch/res/process_details.ui \
	    ../opensnitch/res/stats.ui \
	    ../opensnitch/res/firewall.ui \
	    ../opensnitch/res/firewall_rule.ui
TRANSLATIONS += locales/ar/opensnitch-ar.ts \
                locales/cs_CZ/opensnitch-cs_CZ.ts \
                locales/de_DE/opensnitch-de_DE.ts \
                locales/es_ES/opensnitch-es_ES.ts \
                locales/eu_ES/opensnitch-eu_ES.ts \
                locales/fi_FI/opensnitch-fi_FI.ts \
                locales/fr_FR/opensnitch-fr_FR.ts \
                locales/he_IL/opensnitch-he_IL.ts \
                locales/hi_IN/opensnitch-hi_IN.ts \
                locales/hu_HU/opensnitch-hu_HU.ts \
                locales/id_ID/opensnitch-id_ID.ts \
                locales/it_IT/opensnitch-it_IT.ts \
                locales/ja_JP/opensnitch-ja_JP.ts \
                locales/lt_LT/opensnitch-lt_LT.ts \
                locales/nb_NO/opensnitch-nb_NO.ts \
                locales/nl_NL/opensnitch-nl_NL.ts \
                locales/pt_BR/opensnitch-pt_BR.ts \
                locales/ro_RO/opensnitch-ro_RO.ts \
                locales/ru_RU/opensnitch-ru_RU.ts \
                locales/sq_AL/opensnitch-sq_AL.ts \
                locales/sv_SE/opensnitch-sv_SE.ts \
                locales/tr_TR/opensnitch-tr_TR.ts \
                locales/uk_UA/opensnitch-uk_UA.ts \
                locales/zh_Hans/opensnitch-zh_Hans.ts \
                locales/zh_TW/opensnitch-zh_TW.ts

TSFILES := $(TRANSLATIONS)

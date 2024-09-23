#TEMPLATE = app
#TARGET = ts
#INCLUDEPATH += opensnitch


# Input
SOURCES +=  ../opensnitch/service.py \
	    ../opensnitch/notifications.py \
	    ../opensnitch/customwidgets/addresstablemodel.py \
	    ../opensnitch/customwidgets/main.py \
	    ../opensnitch/dialogs/prompt/__init__.py \
	    ../opensnitch/dialogs/prompt/_utils.py \
	    ../opensnitch/dialogs/prompt/_details.py \
	    ../opensnitch/dialogs/prompt/_checksums.py \
	    ../opensnitch/dialogs/prompt/_constants.py \
	    ../opensnitch/dialogs/preferences.py \
	    ../opensnitch/dialogs/ruleseditor.py \
	    ../opensnitch/dialogs/processdetails.py \
	    ../opensnitch/dialogs/stats.py \
	    ../opensnitch/dialogs/firewall.py \
	    ../opensnitch/dialogs/firewall_rule.py

FORMS += ../opensnitch/res/prompt.ui \
	    ../opensnitch/res/ruleseditor.ui \
	    ../opensnitch/res/preferences.ui \
	    ../opensnitch/res/process_details.ui \
	    ../opensnitch/res/stats.ui \
	    ../opensnitch/res/firewall.ui \
	    ../opensnitch/res/firewall_rule.ui
TRANSLATIONS += locales/de_DE/opensnitch-de_DE.ts \
                locales/es_ES/opensnitch-es_ES.ts \
                locales/eu_ES/opensnitch-eu_ES.ts \
                locales/fi_FI/opensnitch-fi_FI.ts \
                locales/fr_FR/opensnitch-fr_FR.ts \
                locales/hu_HU/opensnitch-hu_HU.ts \
                locales/id_ID/opensnitch-id_ID.ts \
                locales/ja_JP/opensnitch-ja_JP.ts \
                locales/lt_LT/opensnitch-lt_LT.ts \
                locales/nb_NO/opensnitch-nb_NO.ts \
                locales/nl_NL/opensnitch-nl_NL.ts \
                locales/pt_BR/opensnitch-pt_BR.ts \
                locales/ro_RO/opensnitch-ro_RO.ts \
                locales/ru_RU/opensnitch-ru_RU.ts \
                locales/tr_TR/opensnitch-tr_TR.ts \
                locales/zh_TW/opensnitch-zh_TW.ts

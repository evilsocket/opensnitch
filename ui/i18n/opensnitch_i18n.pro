#TEMPLATE = app
#TARGET = ts
#INCLUDEPATH += opensnitch


# Input
SOURCES +=  ../opensnitch/service.py \
	    ../opensnitch/notifications.py \
	    ../opensnitch/customwidgets/addresstablemodel.py \
	    ../opensnitch/customwidgets/main.py \
	    ../opensnitch/dialogs/prompt.py \
	    ../opensnitch/dialogs/preferences.py \
	    ../opensnitch/dialogs/ruleseditor.py \
	    ../opensnitch/dialogs/processdetails.py \
	    ../opensnitch/dialogs/stats.py

FORMS += ../opensnitch/res/prompt.ui \
	    ../opensnitch/res/ruleseditor.ui \
	    ../opensnitch/res/preferences.ui \
	    ../opensnitch/res/process_details.ui \
	    ../opensnitch/res/stats.ui
TRANSLATIONS += locales/de_DE/opensnitch-de_DE.ts \
                locales/es_ES/opensnitch-es_ES.ts \
                locales/eu_ES/opensnitch-eu_ES.ts \
                locales/fr_FR/opensnitch-fr_FR.ts \
                locales/hi_IN/opensnitch-hi_IN.ts \
                locales/hu_HU/opensnitch-hu_HU.ts \
                locales/id_ID/opensnitch-id_ID.ts \
                locales/it_IT/opensnitch-it_IT.ts \
                locales/ja_JP/opensnitch-ja_JP.ts \
                locales/lt_LT/opensnitch-lt_LT.ts \
                locales/nb_NO/opensnitch-nb_NO.ts \
                locales/pt_BR/opensnitch-pt_BR.ts \
                locales/ro_RO/opensnitch-ro_RO.ts \
                locales/ru_RU/opensnitch-ru_RU.ts \
                locales/tr_TR/opensnitch-tr_TR.ts

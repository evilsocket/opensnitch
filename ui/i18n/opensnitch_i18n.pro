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
                locales/hu_HU/opensnitch-hu_HU.ts \
                locales/ja_JP/opensnitch-ja_JP.ts \
                locales/pt_BR/opensnitch-pt_BR.ts \
                locales/ro_RO/opensnitch-ro_RO.ts \
                locales/fr_FR/opensnitch-fr_FR.ts

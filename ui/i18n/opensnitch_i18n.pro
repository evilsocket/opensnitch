#TEMPLATE = app
#TARGET = ts
#INCLUDEPATH += opensnitch


# Input
SOURCES +=  ../opensnitch/service.py \
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
TRANSLATIONS += locales/es_ES/opensnitch-es_ES.ts \
                locales/eu_ES/opensnitch-eu_ES.ts \
                locales/de_DE/opensnitch-de_DE.ts \
                locales/pt_BR/opensnitch-pt_BR.ts

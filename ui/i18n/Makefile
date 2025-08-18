include ./opensnitch_i18n.pro

#TSFILES contains all *.ts files in locales/ and its subfolders 
#TSFILES := $(shell find locales/ -type f -name '*.ts')

#QMFILES contains all *.qm files in locales/ and its subfolders 
QMFILES := $(shell find locales/ -type f -name '*.qm')
#if QMFILES is empty, we set it to phony target to run unconditionally
ifeq ($(QMFILES),)
QMFILES := "qmfiles"
endif

all: $(TSFILES) $(QMFILES)

#if any file from SOURCES or FORMS is older than any file from $(TSFILES)  
#or if opensnitch_i18n.pro was manually modified

# pylupdate6 does not support parsing .pro files anymore
$(TSFILES): $(SOURCES) $(FORMS)
	for t in $(TSFILES); do \
		pylupdate6 --ts $$t $(SOURCES) $(FORMS); \
	done

#if any of the *.ts files are older that any of the *.qm files
#QMFILES may also be a phony target (when no *.qm exist yet) which will always run
$(QMFILES):$(TSFILES)
	@./generate_i18n.sh
	for lang in $$(ls locales/); do \
		if [ ! -d ../opensnitch/i18n/$$lang ]; then mkdir -p ../opensnitch/i18n/$$lang ; fi ; \
		cp locales/$$lang/opensnitch-$$lang.qm ../opensnitch/i18n/$$lang/ ; \
	done

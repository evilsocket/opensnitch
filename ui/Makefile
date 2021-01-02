all: opensnitch/resources_rc.py

install:
	@pip3 install --upgrade .

opensnitch/resources_rc.py: translations deps
	@pyrcc5 -o opensnitch/resources_rc.py opensnitch/res/resources.qrc

translations:
	@cd i18n ; make
	for lang in $$(ls i18n/locales/); do \
		if [ ! -d opensnitch/i18n/$$lang ]; then mkdir -p opensnitch/i18n/$$lang ; fi ; \
		cp i18n/locales/$$lang/opensnitch-$$lang.qm opensnitch/i18n/$$lang/ ; \
	done

deps:
	@pip3 install -r requirements.txt

clean:
	@rm -rf *.pyc
	@rm -rf opensnitch/resources_rc.py

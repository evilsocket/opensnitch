all: opensnitch/resources_rc.py

install:
	@pip3 install --upgrade .

opensnitch/resources_rc.py: translations deps
	@pyrcc5 -o opensnitch/resources_rc.py opensnitch/res/resources.qrc
	sed -i 's/^import ui_pb2/from . import ui_pb2/' opensnitch/ui_pb2*

translations:
	@$(MAKE) -C i18n
	
deps:
	@pip3 install -r requirements.txt

clean:
	@rm -rf *.pyc
	@rm -rf opensnitch/resources_rc.py

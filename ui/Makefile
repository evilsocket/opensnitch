all: opensnitch/resources_rc.py

install:
	@pip3 install --upgrade .

opensnitch/resources_rc.py: translations deps
	@pyrcc5 -o opensnitch/resources_rc.py opensnitch/res/resources.qrc
	@find opensnitch/proto/ -name 'ui_pb2_grpc.py' -exec sed -i 's/^import ui_pb2/from . import ui_pb2/' {} \;

translations:
	@cd i18n ; make
	
deps:
	@pip3 install -r requirements.txt

clean:
	@rm -rf *.pyc
	@rm -rf opensnitch/resources_rc.py

all: opensnitch/resources_rc.py

install:
	@pip3 install --user .

opensnitch/resources_rc.py: deps
	@pyrcc5 -o opensnitch/resources_rc.py opensnitch/res/resources.qrc

deps:
	@pip3 install --user -r requirements.txt

clean:
	@rm -rf *.pyc
	@rm -rf opensnitch/resources_rc.py

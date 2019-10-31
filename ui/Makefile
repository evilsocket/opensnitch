all: opensnitch/resources_rc.py

install:
	@pip3 install --upgrade .

opensnitch/resources_rc.py: deps
	@pyrcc5 -o opensnitch/resources_rc.py opensnitch/res/resources.qrc

deps:
	@sudo pip3 install -r requirements.txt

clean:
	@rm -rf *.pyc
	@rm -rf opensnitch/resources_rc.py

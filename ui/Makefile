all: resources_rc.py

install:
	@pip install .

resources_rc.py:
	@pyrcc5 -o resources_rc.py res/resources.qrc

deps:
	@sudo pip install -r requirements.txt

clean:
	@rm -rf *.pyc
	@rm -rf resources_rc.py

all: resources_rc.py

resources_rc.py:
	@pyrcc5 -o resources_rc.py res/resources.qrc

deps:
	@pip install -r requirements.txt

clean:
	@rm -rf *.pyc
	@rm -rf resources_rc.py

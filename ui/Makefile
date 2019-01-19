all: wheel

.PHONY: install
install: wheel
	@pip3 install dist/opensnitch_ui*.whl

opensnitch/res/resources_rc.qrc: opensnitch/resources_rc.py vbuildtools
	@vbuildtools/bin/pyrcc5 -o opensnitch/resources_rc.py opensnitch/res/resources.qrc

vbuildtools:
	python3 -m venv vbuildtools
	# install build dependencies ; runtime dependencies go in setup.py
	vbuildtools/bin/pip install pyqt5 wheel

.PHONY: wheel
wheel: vbuildtools
	vbuildtools/bin/python setup.py bdist_wheel

.PHONY: clean
clean:
	@rm -rf *.pyc vbuildtools
	@rm -rf opensnitch/resources_rc.py


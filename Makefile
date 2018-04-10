all: protocol daemon/daemon ui/resources_rc.py

protocol:
	@cd proto && make

daemon/daemon:
	@cd daemon && make

ui/resources_rc.py:
	@cd ui && make

deps:
	@cd daemon && make deps
	@cd ui && make deps

clean:
	@rm -rf rules
	@cd daemon && make clean
	@cd proto && make clean

test: 
	clear 
	make clean
	clear
	mkdir rules
	make 
	clear
	cd ui && sudo pip install --upgrade . && cd ..
	opensnitch-ui --socket unix:///tmp/osui.sock &
	sudo ./daemon/daemon -ui-socket unix:///tmp/osui.sock

adblocker:
	clear 
	make clean
	clear
	make 
	clear
	python make_ads_rules.py
	clear
	cd ui && sudo pip install --upgrade . && cd ..
	opensnitch-ui --socket unix:///tmp/osui.sock &
	sudo ./daemon/daemon -ui-socket unix:///tmp/osui.sock



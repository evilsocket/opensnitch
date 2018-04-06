all: protocol daemon/daemon ui/resources_rc.py

protocol:
	@cd proto && make

daemon/daemon:
	@cd daemon && make

ui/resources_rc.py:
	@cd ui && make

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
	python ui/main.py --socket unix:///tmp/osui.sock &
	sudo ./daemon/daemon -ui-socket unix:///tmp/osui.sock

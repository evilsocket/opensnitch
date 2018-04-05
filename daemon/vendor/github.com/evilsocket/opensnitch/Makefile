all: protocol daemon/daemon

protocol:
	@cd proto && make

daemon/daemon:
	@cd daemon && make

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
	xterm -e "python ui/main.py ; read" & 
	sudo ./daemon/daemon

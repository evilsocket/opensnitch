all: protocol daemon/daemon

protocol:
	@cd ui.proto && make

daemon/daemon:
	@cd daemon && make

clean:
	@cd rules && rm -rf user.rule*.json
	@cd daemon && make clean
	@cd ui.proto && make clean

test:
	clear 
	make clean
	clear
	make 
	clear
	xterm -e "python ui/main.py" & 
	sudo ./daemon/daemon

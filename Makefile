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
	python ui/main.py &
	sudo ./daemon/daemon

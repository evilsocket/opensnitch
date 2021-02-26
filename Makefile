all: protocol opensnitch_daemon gui

install:
	@cd daemon && make install	
	@cd ui && make install

protocol:
	@cd proto && make

opensnitch_daemon:
	@cd daemon && make

gui:
	@cd ui && make

clean:
	@cd daemon && make clean
	@cd proto && make clean
	@cd ui && make clean

run:
	cd ui && pip3 install --upgrade . && cd ..
	opensnitch-ui --socket unix:///tmp/osui.sock &
	./daemon/opensnitchd -rules-path /etc/opensnitchd/rules -ui-socket unix:///tmp/osui.sock -cpu-profile cpu.profile -mem-profile mem.profile

test: 
	clear 
	make clean
	clear
	mkdir -p rules
	make 
	clear
	make run

adblocker:
	clear 
	make clean
	clear
	make 
	clear
	python make_ads_rules.py
	clear
	cd ui && pip3 install --upgrade . && cd ..
	opensnitch-ui --socket unix:///tmp/osui.sock &
	./daemon/opensnitchd -rules-path /etc/opensnitchd/rules -ui-socket unix:///tmp/osui.sock



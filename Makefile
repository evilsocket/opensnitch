all: protocol daemon/opensnitchd ui/resources_rc.py

install:
	@cd daemon && make install	
	@cd ui && make install

protocol:
	@cd proto && make

daemon/opensnitchd:
	@cd daemon && make

ui/resources_rc.py:
	@cd ui && make

deps:
	@cd daemon && make deps
	@cd ui && make deps

clean:
	@cd daemon && make clean
	@cd proto && make clean

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



all: protocol opensnitch_daemon gui

install:
	@$(MAKE) -C daemon install
	@$(MAKE) -C ui install

protocol:
	@$(MAKE) -C proto

opensnitch_daemon:
	@$(MAKE) -C daemon

gui:
	@$(MAKE) -C ui

clean:
	@$(MAKE) -C daemon clean
	@$(MAKE) -C proto clean
	@$(MAKE) -C ui clean

run:
	cd ui && pip3 install --upgrade . && cd ..
	opensnitch-ui --socket unix:///tmp/osui.sock &
	./daemon/opensnitchd -rules-path /etc/opensnitchd/rules -ui-socket unix:///tmp/osui.sock -cpu-profile cpu.profile -mem-profile mem.profile

test: 
	clear 
	$(MAKE) clean
	clear
	mkdir -p rules
	$(MAKE)
	clear
	$(MAKE) run

adblocker:
	clear 
	$(MAKE) clean
	clear
	$(MAKE)
	clear
	python make_ads_rules.py
	clear
	cd ui && pip3 install --upgrade . && cd ..
	opensnitch-ui --socket unix:///tmp/osui.sock &
	./daemon/opensnitchd -rules-path /etc/opensnitchd/rules -ui-socket unix:///tmp/osui.sock



all: protocol osd osui

protocol:
	@cd ui.proto && make

osd:
	@cd daemon && make && mv daemon ../osd

osui:
	@cd ui.test.service && make && mv ui.test.service ../ui

clean:
	@cd ui.proto && make clean
	@cd daemon && make clean
	@cd ui.test.service && make clean
	@rm -rf osd

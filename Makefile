all: protocol osd osui

protocol:
	@cd ui.proto && make

osd:
	@cd daemon && make && mv daemon ../osd

osui:
	@cd ui.gtk && make && mv ui.gtk ../ui

clean:
	@cd daemon && make clean
	@cd ui.proto && make clean
	@cd ui.gtk && make clean
	@rm -rf osd ui

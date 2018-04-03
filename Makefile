all: protocol osd osgui

protocol:
	@cd ui.proto && make

osd:
	@cd daemon && make && mv daemon ../osd

osgui:
	@cd ui.gtk && make && mv ui.gtk ../osgui

clean:
	@cd rules && rm -rf user.rule*.json
	@cd daemon && make clean
	@cd ui.proto && make clean
	@cd ui.gtk && make clean
	@rm -rf osd osgui

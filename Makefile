all: protocol osd

protocol:
	@cd ui.proto && make

osd:
	@cd daemon && make && mv daemon ../osd

clean:
	@cd rules && rm -rf user.rule*.json
	@cd daemon && make clean
	@cd ui.proto && make clean
	@rm -rf osd

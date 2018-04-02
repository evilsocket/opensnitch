all: protocol osd

protocol:
	@cd ui.proto && make

osd:
	@cd daemon && make && mv daemon ../osd

clean:
	@cd ui.proto && make clean
	@cd daemon && make clean
	@rm -rf osd

all: osd

osd:
	go build -o osd github.com/evilsocket/opensnitch/daemon

clean:
	rm -rf osd ui

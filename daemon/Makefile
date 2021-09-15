#SRC contains all *.go *.c *.h files in daemon/ and its subfolders 
SRC := $(shell find . -type f -name '*.go' -o -name '*.h' -o -name '*.c')

all: opensnitchd

install:
	@mkdir -p /etc/opensnitchd/rules
	@cp opensnitchd /usr/local/bin/
	@cp opensnitchd.service /etc/systemd/system/
	@cp default-config.json /etc/opensnitchd/
	@cp system-fw.json /etc/opensnitchd/
	@systemctl daemon-reload

opensnitchd: $(SRC)
	@go get
	@go build -o opensnitchd . 

clean:
	@rm -rf opensnitchd



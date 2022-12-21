#SRC contains all *.go *.c *.h files in daemon/ and its subfolders 
SRC := $(shell find . -type f -name '*.go' -o -name '*.h' -o -name '*.c')
PREFIX?=/usr/local

all: opensnitchd

install:
	@mkdir -p $(DESTDIR)/etc/opensnitchd/rules
	@cp opensnitchd $(DESTDIR)$(PREFIX)/bin/
	@cp opensnitchd.service $(DESTDIR)/etc/systemd/system/
	@cp default-config.json $(DESTDIR)/etc/opensnitchd/
	@cp system-fw.json $(DESTDIR)/etc/opensnitchd/
	@systemctl daemon-reload

opensnitchd: $(SRC)
	@go get
	@go build -o opensnitchd . 

clean:
	@rm -rf opensnitchd



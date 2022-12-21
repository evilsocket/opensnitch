#SRC contains all *.go *.c *.h files in daemon/ and its subfolders 
SRC := $(shell find . -type f -name '*.go' -o -name '*.h' -o -name '*.c')
PREFIX?=/usr/local

all: opensnitchd

install:
	@mkdir -p $(DESTDIR)/etc/opensnitchd/rules
	@install -Dm755 opensnitchd \
		-t $(DESTDIR)$(PREFIX)/bin/
	@install -Dm644 opensnitchd.service \
		-t $(DESTDIR)/etc/systemd/system/
	@install -Dm644 default-config.json \
		-t $(DESTDIR)/etc/opensnitchd/
	@install -Dm644 system-fw.json \
		-t $(DESTDIR)/etc/opensnitchd/
	@systemctl daemon-reload

opensnitchd: $(SRC)
	@go get
	@go build -o opensnitchd . 

clean:
	@rm -rf opensnitchd



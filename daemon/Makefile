#SRC contains all *.go *.c *.h files in daemon/ and its subfolders 
SRC := $(shell find . -type f -name '*.go' -o -name '*.h' -o -name '*.c')
PREFIX?=/usr/local

all: opensnitchd

install:
	@mkdir -p $(DESTDIR)/etc/opensnitchd/rules
	@mkdir -p $(DESTDIR)/etc/opensnitchd/tasks
	@install -Dm755 opensnitchd \
		-t $(DESTDIR)$(PREFIX)/bin/
	@install -Dm644 data/init/opensnitchd.service \
		-t $(DESTDIR)/etc/systemd/system/
	@install -Dm644 data/default-config.json \
		-t $(DESTDIR)/etc/opensnitchd/
	@install -Dm644 data/system-fw.json \
		-t $(DESTDIR)/etc/opensnitchd/
	@install -Dm644 data/network_aliases.json \
		-t $(DESTDIR)/etc/opensnitchd/
	@install -Dm600 data/rules/* $(DESTDIR)/etc/opensnitchd/rules/
	@install -Dm600 data/tasks/tasks.json $(DESTDIR)/etc/opensnitchd/tasks/
	@systemctl daemon-reload

opensnitchd: $(SRC)
	@go get
	@go build -o opensnitchd . 

clean:
	@rm -rf opensnitchd



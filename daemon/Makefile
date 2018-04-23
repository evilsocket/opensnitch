all: opensnitchd

install:
	@mkdir -p /etc/opensnitchd/rules
	@cp opensnitchd /usr/local/bin/
	@cp opensnitchd.service /etc/systemd/system/
	@systemctl daemon-reload

deps: 
	@dep ensure

opensnitchd: deps
	@go build -o opensnitchd . 

clean:
	@rm -rf opensnitchd



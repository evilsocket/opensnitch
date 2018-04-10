all: opensnitchd

install:
	@mkdir -p /etc/opensnitchd/rules
	@cp opensnitchd /usr/local/bin/
	@cp opensnitchd.service /etc/systemd/system/
	@systemctl daemon-reload

deps: 
	@glide up

opensnitchd:
	@go build -o opensnitchd . 

clean:
	@rm -rf opensnitchd



all: opensnitchd

install:
	@mkdir -p /etc/opensnitchd/rules
	@cp opensnitchd /usr/local/bin/
	@cp opensnitchd.service /etc/systemd/system/
	@cp default-config.json /etc/opensnitchd/
	@systemctl daemon-reload

opensnitchd:
	@go build -o opensnitchd . 

clean:
	@rm -rf opensnitchd



module github.com/evilsocket/opensnitch/daemon

go 1.14

require (
	github.com/evilsocket/ftrace v1.2.0
	github.com/fsnotify/fsnotify v1.4.7
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/golang/protobuf v1.5.0
	github.com/google/gopacket v1.1.14
	github.com/google/nftables v0.0.0-20210514154851-a285acebcad3
	github.com/iovisor/gobpf v0.2.0
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	golang.org/x/net v0.0.0-20190311183353-d8887717615a
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208 // indirect
	golang.org/x/sys v0.0.0-20190606203320-7fc4e5ec1444 // indirect
	golang.org/x/text v0.3.0 // indirect
	google.golang.org/grpc v1.27.0
	google.golang.org/protobuf v1.26.0
)

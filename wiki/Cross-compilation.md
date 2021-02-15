### Cross compiling the daemon for other architectures (arm)

The following steps are for compile OpenSnitch on _Debian testing_ for armhf. You may run into incompabilities on other distros (like Debian sid).

```
$ sudo dpkg --add-architecture armhf
$ sudo apt update
$ sudo apt install libnetfilter-queue-dev:armhf libmnl-dev:armhf 
$ sudo apt install gcc-8-arm-linux-gnueabihf gcc-8-arm-linux-gnueabihf-base gcc-8-plugin-dev-arm-linux-gnueabi gcc-arm-linux-gnueabi

$ export CC=arm-linux-gnueabi-gcc
$ export CGO_LDFLAGS="-L/usr/lib/arm-linux-gnueabihf/"
$ GOOS=linux GOARM=7 GOARCH=arm CGO_ENABLED=1 PKG_CONFIG_PATH="/usr/lib/arm-linux-gnueabihf/pkgconfig/"  go build -o opensnitchd-arm -x .
```

**arm64**

Discussion regarding running the daemon on arm64: [#18](https://github.com/gustavo-iniguez-goya/opensnitch/issues/18)

```
$ sudo dpkg --add-architecture arm64
$ sudo apt update
$ sudo apt install libnetfilter-queue-dev:arm64 libmnl-dev:arm64
$ apt install gccgo-aarch64-linux-gnu 
$ export CC=aarch64-linux-gnu-gcc
$ export CGO_LDFLAGS="-L/usr/lib/aarch64-linux-gnu/"
$ GOOS=linux GOARCH=arm64 CGO_ENABLED=1 PKG_CONFIG_PATH="/usr/lib/aarch64-linux-gnu/pkgconfig/"  go build -o opensnitchd-arm64 .
```

***
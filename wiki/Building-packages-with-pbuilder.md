Using pbuilder is a fancy way of creating deb packages.

You just need to download the .dsc file:

> $ wget https://github.com/gustavo-iniguez-goya/opensnitch/releases/download/v1.0.0rc10/opensnitch_1.0.0rc10-1.dsc

Create the chroot environment:
```
$ sudo apt install qemu-static
$ sudo pbuilder create --architecture armhf --distribution sid --debootstrap qemu-debootstrap --basetgz /var/cache/pbuilder/sid-armhf.tgz
```

build the package using the pbuilder chroot:

> $ sudo pbuilder build --architecture armhf --basetgz /var/cache/pbuilder/sid-armhf.tgz --buildresult /tmp/rc10/pkgs opensnitch_1.0.0rc9-1.dsc

You can repeat the process for arm64, amd64, i386, etc..., and other distributions:
```
--distribution sid
--architecture armhf
```
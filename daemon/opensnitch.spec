Name:           opensnitch
Version:        1.5.1
Release:        1%{?dist}
Summary:        OpenSnitch is a GNU/Linux application firewall

License:        GPLv3+
URL:            https://github.com/evilsocket/%{name}
Source0:        https://github.com/evilsocket/%{name}/releases/download/v%{version}/%{name}_%{version}.orig.tar.gz
#BuildArch:     x86_64

#BuildRequires:  godep
Requires(post): info
Requires(preun): info

%description
Whenever a program makes a connection, it'll prompt the user to allow or deny
it.

The user can decide if block the outgoing connection based on properties of
the connection: by port, by uid, by dst ip, by program or a combination
of them.

These rules can last forever, until the app restart or just one time.

The GUI allows the user to view live outgoing connections, as well as search
by process, user, host or port.

%prep
rm -rf %{buildroot}

%setup

%build
mkdir -p go/src/github.com/evilsocket
ln -s $(pwd) go/src/github.com/evilsocket/opensnitch
export GOPATH=$(pwd)/go
cd go/src/github.com/evilsocket/opensnitch/
make protocol
cd go/src/github.com/evilsocket/opensnitch/daemon/
go mod vendor
go build -o opensnitchd .

%install
mkdir -p %{buildroot}/usr/bin/ %{buildroot}/usr/lib/systemd/system/ %{buildroot}/etc/opensnitchd/rules %{buildroot}/etc/logrotate.d
sed -i 's/\/usr\/local/\/usr/' daemon/opensnitchd.service
install -m 755 daemon/opensnitchd %{buildroot}/usr/bin/opensnitchd
install -m 644 daemon/opensnitchd.service %{buildroot}/usr/lib/systemd/system/opensnitch.service
install -m 644 debian/opensnitch.logrotate %{buildroot}/etc/logrotate.d/opensnitch

B=""
if [ -f /etc/opensnitchd/default-config.json ]; then
    B="-b"
fi
install -m 644 -b $B daemon/default-config.json %{buildroot}/etc/opensnitchd/default-config.json

B=""
if [ -f /etc/opensnitchd/system-fw.json ]; then
    B="-b"
fi
install -m 644 -b $B daemon/system-fw.json %{buildroot}/etc/opensnitchd/system-fw.json

install -m 644 ebpf_prog/opensnitch.o %{buildroot}/etc/opensnitchd/opensnitch.o

# upgrade, uninstall
%preun
systemctl stop opensnitch.service || true

%post
if [ $1 -eq 1 ]; then
    systemctl enable opensnitch.service
fi
systemctl start opensnitch.service

# uninstall,upgrade
%postun
if [ $1 -eq 0 ]; then
    systemctl disable opensnitch.service
fi
if [ $1 -eq 0 -a -f /etc/logrotate.d/opensnitch ]; then
    rm /etc/logrotate.d/opensnitch
fi

# postun is the last step after reinstalling
if [ $1 -eq 1 ]; then
    systemctl start opensnitch.service
fi

%clean
rm -rf %{buildroot}

%files
%{_bindir}/opensnitchd
/usr/lib/systemd/system/opensnitch.service
%{_sysconfdir}/opensnitchd/default-config.json
%{_sysconfdir}/opensnitchd/system-fw.json
%{_sysconfdir}/opensnitchd/opensnitch.o
%{_sysconfdir}/logrotate.d/opensnitch

%define name opensnitch-ui
%define version 1.6.3
%define unmangled_version 1.6.3
%define release 1
%define __python python3
%define desktop_file opensnitch_ui.desktop

Summary: Prompt service and UI for the OpenSnitch interactive application firewall.
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: GPL-3.0
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: OpenSnitch project
Packager: Gustavo Iñiguez Goya <gooffy1@gmail.com>
Url: https://github.com/evilsocket/opensnitch
Requires: python3, python3-pip, (netcfg or setup), (python3-pyinotify or python3-inotify), python3-qt5, python3-notify2
Recommends: (python3-slugify or python3-python-slugify), python3-protobuf >= 3.0, python3-grpcio >= 1.10.0, (qgnomeplatform-qt5 or QGnomePlatform-qt5)

# avoid to depend on a particular python version
%global __requires_exclude ^python\\(abi\\) = 3\\..$

%description
GUI for the opensnitch application firewall
opensnitch-ui is a GUI for opensnitch written in Python.
It allows the user to view live outgoing connections, as well as search
to make connections.
.
The user can decide if block the outgoing connection based on properties of
the connection: by port, by uid, by dst ip, by program or a combination
of them.
.
These rules can last forever, until the app restart or just one time.

%prep
%setup -n %{name}-%{unmangled_version} -n %{name}-%{unmangled_version}

%post

if [ $1 -ge 1 ]; then
    deskfile=/etc/xdg/autostart/opensnitch_ui.desktop
    if [ -d /etc/xdg/autostart -a ! -h  $deskfile -a ! -f $deskfile ]; then
        ln -s /usr/share/applications/opensnitch_ui.desktop /etc/xdg/autostart/
    fi

    gtk-update-icon-cache /usr/share/icons/hicolor/ || true
fi

%postun
if [ $1 -eq 0 ]; then
    # deprecated: kept for uninstalling old (<= v1.6.4) autostart files
    for i in $(ls /home)
    do
        if grep /home/$i /etc/passwd &>/dev/null; then
            path=/home/$i/.config/autostart/%{desktop_file}
            if [ -h $path -o -f $path ]; then
                rm -f $path
            else
                echo "[INFO] No desktop file for this user: $path"
            fi
        fi
    done

    deskfile=/etc/xdg/autostart/opensnitch_ui.desktop
    if [ -h $deskfile -o -f $deskfile ]; then
        rm -f $deskfile
    fi

    pkill -15 opensnitch-ui 2>/dev/null || true
fi


%build
cd i18n; make; cd ..
cp -r i18n/locales/ opensnitch/i18n
pyrcc5 -o opensnitch/resources_rc.py opensnitch/res/resources.qrc
sed -i 's/^import ui_pb2/from . import ui_pb2/' opensnitch/ui_pb2*
python3 setup.py build

%install
python3 setup.py install --install-lib=/usr/lib/python3/dist-packages/ --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --prefix=/usr --record=INSTALLED_FILES --install-scripts=/usr/bin

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)

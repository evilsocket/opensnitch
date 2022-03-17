%define name opensnitch-ui
%define version 1.5.1
%define unmangled_version 1.5.1
%define release 1
%define __python python3
%define desktop_file opensnitch_ui.desktop

Summary: Prompt service and UI for the opensnitch application firewall.
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: GPL-3.0
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: Simone "evilsocket" Margaritelli <evilsocket@protonmail.com>
Url: https://github.com/evilsocket/opensnitch
Requires: python3, python3-pip, (python3-pyinotify or python3-inotify), python3-qt5, python3-notify2
Recommends: (python3-slugify or python3-python-slugify), python3-protobuf >= 3.0

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
    for i in $(ls /home)
    do
        if grep /home/$i /etc/passwd &>/dev/null; then
            path=/home/$i/.config/autostart/
            if [ ! -d $path ]; then
                mkdir -p $path
            fi
            if [ -f /usr/share/applications/%{desktop_file} ];then
                ln -s /usr/share/applications/%{desktop_file} $path 2>/dev/null || true
            else
                echo "No desktop file: %{desktop_file}"
            fi
        fi
    done

    gtk-update-icon-cache /usr/share/icons/hicolor/ || true
fi

if [ $1 -eq 1 ]; then
    echo -e "\n You need to install 2 more packages:
        unicode_slugify and grpcio-tools.
    
        pip3 install grpcio-tools
        pip3 install unicode_slugify
    "
fi

%postun
if [ $1 -eq 0 ]; then
    for i in $(ls /home)
    do
        if grep /home/$i /etc/passwd &>/dev/null; then
            path=/home/$i/.config/autostart/%{desktop_file}
            if [ -h $path -o -f $path ]; then
                rm -f $path
            else
                echo "No desktop file for this user: $path"
            fi
        fi
    done

    pkill -15 opensnitch-ui 2>/dev/null || true
    
    echo ""
    echo "  Remember to uninstall grpcio-tools and unicode_slugify if you don't"
    echo "  need them anymore:"
    echo "  pip3 uninstall unicode_slugify"
    echo "  pip3 uninstall grpcio-tools"
    echo ""
fi


%build
cd i18n; make; cd ..
cp -r i18n/locales/ opensnitch/i18n
pyrcc5 -o opensnitch/resources_rc.py opensnitch/res/resources.qrc
sed -i 's/^import ui_pb2/from . import ui_pb2/' opensnitch/ui_pb2*
python3 setup.py build

%install
python3 setup.py install --install-lib=/usr/lib/python3/dist-packages/ --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --prefix=/usr --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)

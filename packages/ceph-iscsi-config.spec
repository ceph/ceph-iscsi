Name:           ceph-iscsi-config
Version:        0.5
Release:        1%{?dist}
Summary:        Python package providing modules for ceph iscsi gateway configuration management

License:        GPLv3
URL:            https://github.com/pcuzner/ceph-iscsi-config
Source0:        https://github.com/pcuzner/ceph-iscsi-config/archive/%{version}/%{name}-%{version}.tar.gz

BuildArch:  noarch

Requires:  python-rados
Requires:  python-rbd
Requires:  python-netaddr
Requires:  python-netifaces
Requires:  python-rtslib

BuildRequires:  python-devel
BuildRequires:  python-setuptools

%description
Python package providing the modules used to handle the configuration of an iSCSI
gateway, backed by ceph/kRBD. The modules are consumed by custom Ansible modules
and may also be used independently to manage the configuration once the environment
is installed.

%prep
%setup -q

%build
%{__python2} setup.py build

%install
%{__python2} setup.py install -O1 --skip-build --root %{buildroot}


%files
%doc LICENSE
%doc README
%{python2_sitelib}/*

%changelog
* Tue Sep 27 2016 Paul Cuzner <pcuzner@redhat.com> - 0.5-1
- initial rpm build


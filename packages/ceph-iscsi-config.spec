Name:           ceph-iscsi-config
Version:        0.6
Release:        2%{?dist}
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
* Tue Oct 04 2016 Paul Cuzner <pcuzner@redhat.com> - 0.6.2
- modified the way that lunid's get assigned within the lio definition in the gateway module

* Mon Oct 03 2016 Paul Cuzner <pcuzner@redhat.com> - 0.6.1
- update LUN module to use a pool/image key, and include more meta data on the disk object
- moved generic rados query functions to the common.utils module
- updated the client module to handle rbd names in pool/image format

* Tue Sep 27 2016 Paul Cuzner <pcuzner@redhat.com> - 0.5-1
- initial rpm build


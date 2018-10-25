Name:           ceph-iscsi-config
Version:        2.7
Release:        1%{?dist}
Summary:        Python package providing modules for ceph iscsi gateway configuration management

License:        GPLv3
URL:            https://github.com/ceph/ceph-iscsi-config
Source0:        https://github.com/ceph/ceph-iscsi-config/archive/%{version}/%{name}-%{version}.tar.gz

BuildArch:  noarch

Requires:  python-rados >= 10.2.2
Requires:  python-rbd >= 10.2.2
Requires:  python-netaddr >= 0.7.5
Requires:  python-netifaces >= 0.10.4
Requires:  python-rtslib >= 2.1.fb67
Requires:  rpm-python >= 4.11
Requires:  python-crypto >= 2.6
Requires:  python-flask >= 0.10.1

BuildRequires:  python-devel
BuildRequires:  python-setuptools
BuildRequires:  systemd

%description
Python package providing the modules used to handle the configuration of an
iSCSI gateway, backed by ceph/RBD. The rpm installs configuration management
logic (ceph_iscsi_config modules) and an rbd-target-gw systemd service.

The configuration management modules may be are consumed by custom Ansible
playbooks, and API server available from a separate rpm.

The rbd-target-gw service is responsible for startup and shutdown actions,
replacing the 'target' service used in standalone LIO implementations. In addition,
rbd-target-gw also provides a prometheus exporter for gateway LIO performance
statistics, supporting monitoring and visualisation tools like Grafana.

%prep
%setup -q

%build
%{__python2} setup.py build

%install
%{__python2} setup.py install -O1 --skip-build --root %{buildroot}  --install-scripts %{_bindir}
mkdir -p %{buildroot}%{_unitdir}
install -m 0644 .%{_unitdir}/rbd-target-gw.service %{buildroot}%{_unitdir}


%post
/bin/systemctl --system daemon-reload &> /dev/null || :
/bin/systemctl --system enable rbd-target-gw &> /dev/null || :

%files
%doc LICENSE
%doc README
%doc iscsi-gateway.cfg_sample
%{python2_sitelib}/*
%{_bindir}/rbd-target-gw
%{_unitdir}/rbd-target-gw.service

%changelog


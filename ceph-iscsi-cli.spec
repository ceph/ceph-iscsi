Name:		ceph-iscsi-cli
Version:	2.8
Release:	1%{?dist}
Summary:	CLI configuration tool to manage multiple iSCSI gateways
Group:		Applications/System
License:	GPLv3

URL:		https://github.com/ceph/ceph-iscsi-cli
Source0:	https://github.com/ceph/%{name}/archive/%{version}/%{name}-%{version}.tar.gz
BuildArch:  noarch

BuildRequires: python2-devel
BuildRequires: python-setuptools
BuildRequires: systemd

Requires: python-rtslib >= 2.1.fb67
Requires: ceph-iscsi-config >= 2.6
Requires: python-requests >= 2.6
Requires: python-configshell >= 1.1
Requires: python-flask >= 0.10.1
Requires: pyOpenSSL >= 0.13

%description
This package provides a CLI interface similar to the targetcli tool used to
interact with the kernel LIO subsystem. The rpm installs two components; a CLI
shell (based on configshell) and an API service called rbd-target-api.

The CLI orchestrates iscsi configuration changes through the API service
running on EACH gateway node. The API service uses the same configuration
settings file '/etc/ceph/iscsi-gateway.cfg' as the rbd-target-gw service.

You should ensure that the 'cfg' file is consistent across gateways for
predictable behaviour.

%prep
%setup -q 

%build
CFLAGS="$RPM_OPT_FLAGS" %{__python} setup.py build


%install
%{__python} setup.py install --skip-build --root %{buildroot} --install-scripts %{_bindir}
mkdir -p %{buildroot}%{_unitdir}
install -m 0644 .%{_unitdir}/rbd-target-api.service %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_mandir}/man8
install -m 0644 gwcli.8 %{buildroot}%{_mandir}/man8/
gzip %{buildroot}%{_mandir}/man8/gwcli.8
mkdir -p %{buildroot}%{_sysconfdir}/systemd/system/rbd-target-gw.service.d
install -m 0644 .%{_sysconfdir}/systemd/system/rbd-target-gw.service.d/dependencies.conf %{buildroot}%{_sysconfdir}/systemd/system/rbd-target-gw.service.d/

%post
/bin/systemctl --system daemon-reload &> /dev/null || :
/bin/systemctl --system enable rbd-target-api &> /dev/null || :

%postun
/bin/systemctl --system daemon-reload &> /dev/null || :

%files
%doc README
%doc LICENSE
%{_bindir}/gwcli
%{_bindir}/rbd-target-api
%{_unitdir}/rbd-target-api.service
%{_sysconfdir}/systemd/system/rbd-target-gw.service.d
%{python2_sitelib}/*
%{_mandir}/man8/gwcli.8.gz

%changelog


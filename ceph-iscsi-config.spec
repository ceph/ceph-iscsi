Name:           ceph-iscsi-config
Version:        1.4
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
BuildRequires:  systemd

%description
Python package providing the modules used to handle the configuration of an
iSCSI gateway, backed by ceph/kRBD. The modules are consumed by custom Ansible
modules and may also be used independently to manage the configuration once the
environment is installed.

%prep
%setup -q

%build
%{__python2} setup.py build

%install
%{__python2} setup.py install -O1 --skip-build --root %{buildroot}
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}/usr/bin
install -m 0644 .%{_unitdir}/rbd-target-gw.service %{buildroot}%{_unitdir}
install -m 0755 usr/bin/rbd-target-gw %{buildroot}/usr/bin

%post
/bin/systemctl --system daemon-reload &> /dev/null || :
/bin/systemctl --system enable rbd-target-gw &> /dev/null || :

%files
%doc LICENSE
%doc README
%{python2_sitelib}/*
%{_bindir}/rbd-target-gw
%{_unitdir}/rbd-target-gw.service

%changelog
* Thu Oct 27 2016 Paul Cuzner <pcuzner@redhat.com> - 1.4-1
- fix - ensure large config objects are read correctly (rhbz 1387297)
- provide support for the same image name across mulitple rados pools (rhbz 1387952)
- add lun id to config object preventing potential data corruptions (rhbz 1387953)
- add create/update datestamps to config object metadata
- resolve rbd-target-gw reload/restart issues (rhbz 1388703)
- add lun remove capability

* Fri Oct 21 2016 Paul Cuzner <pcuzner@redhat.com> - 1.3-1
- fix disk size not showing correctly in targetcli following a resize (BZ 1386149)
- use of fqdn in the LUN request (BZ 1386939)
- rbd-target-gw - ensure tpgs are disabled on service shutdown
- config.gateway - create alua group per tpg
- config.client - reduce timeouts for faster path failover
- use global settings config file across modules (BZ 1386617)
- resize dm device following rbd size request (BZ 1386149)
- allow host names to use FQDN on LUN request (BZ 1386939)

* Sat Oct 15 2016 Paul Cuzner <pcuzner@redhat.com> - 1.2-1
- fix for BZ 1384858 - admin updated hosts file but did not add an ip to gateway_ip_list
- fix unblacklisting process in rbd-target-gw
- correct ALUA binding issue
- added a version number to the rados configuration object
- fix i/o delays when using non-optimised paths with ALUA

* Wed Oct 12 2016 Paul Cuzner <pcuzner@redhat.com> - 1.1-1
- spec file updated - patch from ktdreyer
- alua module reformatting in line with PEP 8
- gateway object can now defer adding portal IP to the active TPG
- rbd-target-gw now defers port IP allocation until nodeACLs are applied
- deferring IP allocation at boot time, prevents windows connectivity issues

* Tue Oct 11 2016 Paul Cuzner <pcuzner@redhat.com> - 1.0-3
- Minor patches to the rbd-target-gw script from Mike Christie

* Mon Oct 10 2016 Paul Cuzner <pcuzner@redhat.com> - 1.0-1
- Included initial patch from Mike Christie for alua portal group support

* Thu Oct 06 2016 Paul Cuzner <pcuzner@redhat.com> - 0.8-1
- fixed tpg creation on existing gateways when a new gateway(s) is added to the configuration
- removed rpm packages from the source archive

* Wed Oct 05 2016 Paul Cuzner <pcuzner@redhat.com> - 0.7-1
- added rbd-target-gw daemon (started at boot)

* Tue Oct 04 2016 Paul Cuzner <pcuzner@redhat.com> - 0.6-2
- more meta data added to the gateway dict

* Mon Oct 03 2016 Paul Cuzner <pcuzner@redhat.com> - 0.6-1
- update LUN module to use a pool/image key, and include more meta data on the disk object
- moved generic rados query functions to the common.utils module
- updated the client module to handle rbd names in pool/image format

* Tue Sep 27 2016 Paul Cuzner <pcuzner@redhat.com> - 0.5-1
- initial rpm build


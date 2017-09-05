Name:           ceph-iscsi-config
Version:        2.3
Release:        2%{?dist}
Summary:        Python package providing modules for ceph iscsi gateway configuration management

License:        GPLv3
URL:            https://github.com/pcuzner/ceph-iscsi-config
Source0:        https://github.com/pcuzner/ceph-iscsi-config/archive/%{version}/%{name}-%{version}.tar.gz

BuildArch:  noarch

Requires:  python-rados >= 10.2.2
Requires:  python-rbd >= 10.2.2
Requires:  python-netaddr >= 0.7.5
Requires:  python-netifaces >= 0.10.4
Requires:  python-rtslib >= 2.1
Requires:  rpm-python >= 4.11
Requires:  python-crypto >= 2.6

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
replacing the 'target' service used in standalone LIO implementations.

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
* Mon Sep 04 2017 Paul Cuzner <pcuzner@redhat.com> - 2.3-2
- host group management updates

* Tue Aug 15 2017 Jason Dillaman <dillaman@redhat.com> - 2.3-1
- group: additional debug msgs added and validation logic changed
- settings : fix missing default value api_ssl_verify
- test_group: simple script testing add/update and removal of a host group
- group: updated to handle updates to the group definition
- utils: add a simple class to show list items that are added/removed
- client:bypass setup_luns if the client is under group_name control
- group.py: initial commit introducing host group management
- common: update config handling to allow new sections to be added to the config

* Fri Jan 12 2017 Paul Cuzner <pcuzner@redhat.com> - 2.2-1
- remove redundant environment variable in settings
- provide a sample cfg file in /usr/share/doc
- fixes: alua cmd timeouts and service dependency (removing old multipathd)

* Fri Jan 12 2017 Paul Cuzner <pcuzner@redhat.com> - 2.1-1
- added dependency for rpm-python
- dropped support for krbd/device-mapper configuration
- adopted TCMU based LIO configuration using librbd
- config file name changed to iscsi-gateway.cfg (from *.conf)
- fix: prevent image_lists with duplicate rbd images from being acted upon
- if pub/priv keys are in /etc/ceph, passwords will be encrypted in the config object

* Thu Jan 05 2017 Paul Cuzner <pcuzner@redhat.com> - 2.0-1
- daemon now watches the config object for changes, and reloads (for API)

* Fri Nov 04 2016 Paul Cuzner <pcuzner@redhat.com> - 1.5-1
- fix - catch config errors at rbd-target-gw startup
- config.lun - trap unwanted rbd map stderr messages
- rbd-target-gw - bypass shutdown if the gateway is not in the configuration (rhbz 1390022)
- config.client - fix handling of invalid client iqn (rhbz 1390023)
- rbd-target-gw - fix behaviour when daemon started prematurely (rhbz 1390022)
- config.common - resolve invalid json backtrace during config read (rhbz 1387297)

* Thu Oct 27 2016 Paul Cuzner <pcuzner@redhat.com> - 1.4-1
- fix - ensure large config objects are read correctly (rhbz 1387297)
- provide support for the same image name across mulitple rados pools (rhbz 1387952)
- add lun id to config object preventing potential data corruptions (rhbz 1387953)
- add create/update datestamps to config object metadata
- resolve rbd-target-gw reload/restart issues (rhbz 1388703)
- add lun remove capability
- fix rbd-target-gw to drop LIO configuration on a systemctl stop request

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


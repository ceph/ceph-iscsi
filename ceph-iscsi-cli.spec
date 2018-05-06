Name:		ceph-iscsi-cli
Version:	2.7
Release:	1%{?dist}
Summary:	CLI configuration tool to manage multiple iSCSI gateways
Group:		Applications/System
License:	GPLv3

URL:		https://github.com/pcuzner/ceph-iscsi-cli
Source0:	https://github.com/pcuzner/%{name}/archive/%{version}/%{name}-%{version}.tar.gz
BuildArch:  noarch

BuildRequires: python2-devel
BuildRequires: python-setuptools
BuildRequires: systemd

Requires: python-rtslib >= 2.1
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
* Sat May 5 2018 Jason Dillaman <dillaman@redhat.com> 2.7-1
- Cleanup handling for max_data_area_mb override (25 minutes ago) <Jason Dillaman>
- gwcli: accept optional "ring_buffer_size" when creating LUNs (9 days ago) <Venky Shankar>
- rbd-target-api: disable LUN deactivate call if session logged-in (35 hours ago) <Jason Dillaman>
- gwcli: fixed hostgroup member/disk form parameter naming (5 days ago) <Jason Dillaman>
- gwcli: added snapshot create/rollback/delete command (5 days ago) <Jason Dillaman>
- gwcli: add snapshot listing to disk info command (5 days ago) <Jason Dillaman>
- rbd-target-api: add disksnap endpoint for managing snapshots (5 days ago) <Jason Dillaman>
- rbd-target-api: added activate/deactivate modes to the disk endpoint (5 days ago) <Jason Dillaman>
- Relax OS distro check to support CentOS and RHEL >=7.4 (5 weeks ago) <Jason Dillaman>
- position correction of function gateways.remove(local_host) (7 weeks ago) <Gangbiao>
- Prevent ValueError for kernels with multiple dashes (7 weeks ago) <Alexander Bauer>

* Mon Jan 22 2018 Jason Dillaman <dillaman@redhat.com> 2.6-1
- new release
- rbd-target-api: fix create gateway issue
- rbd-target-api: adjust minimum supported kernel version
- storage: use multi-threading when fetching the size of rbd images
- gateway: store the scan_threads in the UI root object
- gwcli: add -t option to control parallelism during rbd scans
- client: updated to include ip addr and alias for an info command
- get_disks API adds 'config=yes' parameter support
- rbd-target-api add detail examples for all APIs
- Fix hostgroup params and keep code the same with the doc's descripttions
- Fix for disk doc message
- gateway: Throw the error message more clearly
- Fix for poolnames containing '-' chars
- client auth comments and help doc update
- rbd-target-api: remove useless internal_text
- gateway - catch export requests made when the config is empty
- Enforce the minimum gateways setting
- Properly construct seed gateway list
- Prevent creation of more than 256 disks
- client auth logic updated to further validate username/password chap strings
- updated APIRequest Logic to handle connection failures
- Validate client IQN for create and delete UI actions
- Wrap JSON response decoding with exception handling
- Corrected health check summary scrap logic for Luminous
- storage: add further validation to disk create request
- storage: fix the display of capacity when adding disks
- client: fix auth workflow issue BZ 1491550
- rbd-target-api: bypass rpm checks if the platform is not redhat
- rbd-target-api: be less specific with the package checks
- rbd-target-api: health check logic and gateway validity checks updated
- gateway: gateway creation and health checks updated
- ceph: use the first mon in quorum list when exporting the config
- ceph: updated to provide more health information within the UI
- utils: added os_cmd function
- Improved systemd limits and system protection
- hostgroup: fix for disk removal from a hostgroup
- rbd-target-api: fix gateway order during device deletion request
- rbd-target-api: add image_id validation to the disk endpoint
- storage: add quick sanity check to a delete request
- spec: updated to document latest code changes
- gateway: added a 5sec background thread to check gateway health
- hostgroup: UI fixes
- rbd-target-api: fix issue of changes being accepted when a gateway is down
- storage: ensure create_disk issues a return value
- client: doctext update
- utils: fix 'valid_disk' logic
- rbd-target-api: fix to address a problem when deleting rbd images
- client: doc updates and added methods to support group management
- hostgroup: refactored the code, including a number of bug fixes
- rbd-target-api : minor change to make the code more readable
- node: prevent 'info' command causing an exception
- hostgroup: fetch updated group definition to refresh UI subtree
- rbd-target-api: prevent disk create requests when # gateways <2
- storage: catch invalid pool names in disk create request
- gateway: fix api call when clearing the config
- client/auth: fix special characters accepted in UI

* Mon Sep 04 2017 Paul Cuzner <pcuzner@redhat.com> 2.5-2
- automatically check state of gateways every 5 seconds
- hostgroup logic updated
- added an isalive api endpoint to check state of gateways
- abort any change request, when there are offline iscsi gateways

* Tue Aug 15 2017 Jason Dillaman <dillaman@redhat.com> 2.5-1
- version bump to 2.5

* Sat Jan 21 2017 Paul Cuzner <pcuzner@redhat.com> 2.1-1
- updated for TCMU support (krbd/device mapper support removed)
- rbd-target-api restructured to remove python-flask-restful dependency
- api endpoints available through a get /api call
- spec updated for pyOpenSSL dependency (used by API)
- added feature text to disk info command instead of just a feature code (int)
- automatically select TLS version based on version of werkzeug
- disk resize and info now available from the upper level 'disks' section
- requested commands echo'd to the log file improving audit record
- add gateways refresh command
- fix: disk resize now changes all related entries in the tree
- ceph clusters are populated automatically through presence in /etc/ceph
- added ceph cluster name to disk info output
- 'ansible' mode exports decrypt chap passwords automatically
- cli installation binds rbd-target-api to the unit state of rbd-target-gw
- workflow: switch dir to newly created client to speed up client definition
- workflow: non-existent disk gets autodefined within the client dialog
- gateway health determined using iscsi port AND api port state

* Thu Jan 5 2017 Paul Cuzner <pcuzner@redhat.com> 2.0-1
- initial rpm packaging


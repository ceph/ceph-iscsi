# ceph-iscsi
This project provides the common logic and CLI tools for creating and managing
LIO gateways for Ceph.

It includes the ```rbd-target-api``` daemon which is responsible for restoring
the state of LIO following a gateway reboot/outage and exporting a REST API
to configure the system using tools like gwcli. It replaces the existing
'target' service.

There is also a second daemon ```rbd-target-gw``` which exports a REST API
to gather statistics.

It also includes the CLI tool ```gwcli``` which can be used to configure and
manage the Ceph iSCSI gateway, which replaces the existing ```targetcli```
CLI tool. This CLI tool utilizes the ```rbd-target-api``` server daemon to
configure multiple gateways concurrently.

## Usage
This package should be installed on each node that is intended to be an iSCSI
gateway. The Python ```ceph_iscsi_config``` modules are used by:
* the **rbd-target-api** daemon to restore LIO state at boot time
* **API/CLI** configuration tools

## Installation
### Repository
A YUM repository is available with the lastest releases.  The repository is available at `https://download.ceph.com/ceph-iscsi/{version}/rpm/{distribution}/noarch/`.  For example, https://download.ceph.com/ceph-iscsi/latest/rpm/el7/noarch/

Alternatively, you may download the YUM repo description at https://download.ceph.com/ceph-iscsi/latest/rpm/el7/ceph-iscsi.repo

Packages are signed with the following key: https://download.ceph.com/keys/release.asc

### Via RPM
Simply install the provided rpm with:
```rpm -ivh ceph-iscsi-<ver>.el7.noarch.rpm```

### Manually
The following packages are required by ceph-iscsi-config and must be
installed before starting the rbd-target-api and rbd-target-gw services:

python-rados
python-rbd
python-netifaces
python-rtslib
python-configshell
python-cryptography
python-flask

To install the python package that provides the CLI tool, daemons and
application logic, run the provided setup.py script i.e.
```> python setup.py install```

If using systemd, copy the following unit files into their equivalent places
on each gateway:
- <archive_root>/usr/lib/systemd/system/rbd-target-gw.service  --> /lib/systemd/system
- <archive_root>/usr/lib/systemd/system/rbd-target-api.service  --> /lib/systemd/system

Once the unit files are in place, reload the configuration with
```
systemctl daemon-reload
systemctl enable rbd-target-api
systemctl enable rbd-target-gw
systemctl start rbd-target-api
systemctl start rbd-target-gw
```

## Features
The functionality provided by each module in the python package is summarised below;

| Module | Description |
| --- | --- |
| **client** | logic handling the create/update and remove of a NodeACL from a gateway |
| **config** | common code handling the creation and update mechanisms for the rados configuration object |  
| **gateway** | definition of the iSCSI gateway (target plus target portal groups) |
| **lun** | rbd image management (create/resize), combined with mapping to the OS and LIO instance |
| **utils** | common code called by multiple modules |

The rbd-target-api daemon performs the following tasks;
  1. At start up remove any osd blocklist entry that may apply to the running host
  2. Read the configuration object from Rados
  3. Process the configuration
  3.1 map rbd's to the host
  3.2 add rbd's to LIO
  3.3 Create the iscsi target, TPG's and port IP's
  3.4 Define clients (NodeACL's)
  3.5 add the required rbd images to clients
  4. Export a REST API for system configuration.



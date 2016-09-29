#ceph-iscsi-config  
This project provides common logic for creating and managing LIO gateways for ceph. In addition to   
configuration logic, the package also provides a "Config" class that provides a common interface to  
a configuration object stored in rados, which describes the iscsi gateway state; it's gateway members,  
the rbd images exposed through the gateways, and the client definitions that link a client iqn to a  
set of rbd images.  

##Usage
This package should be installed on each node that is intended to be an iSCSI gateway, providing a common  
interface for LUN, Gateway and client management. The modules themselves are typically called by the  
Ansible modules defined in ceph-iscsi-ansible project (https://github.com/pcuzner/ceph-iscsi-ansible).

##Installation
The repo provides setup.py to install natively from python, or an rpm to simplify installation (in the  
archive's packages directory). 

##Features
The functionality provided by each module is summarised below;

| module | Description |
| --- | --- |
| **client** | logic handling the create/update and remove of a NodeACL from a gateway |
| **config** | common code handling the creation and update mechanisms for the rados configuration object |  
| **gateway** | definition of the iSCSI gateway (target plus target portal groups) |
| **lun** | rbd image management (create/resize), combined with mapping to the OS and LIO instance |
| **utils** | common code called by multiple modules |
  
  




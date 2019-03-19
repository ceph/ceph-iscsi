from rtslib_fb import UserBackedStorageObject
from rtslib_fb.utils import RTSLibError

from ceph_iscsi_config.utils import CephiSCSIError

USER_RBD = 'user:rbd'


def lookup_storage_object_by_disk(config, disk):
    backstore = config.config["disks"][disk]["backstore"]
    backstore_object_name = config.config["disks"][disk]["backstore_object_name"]

    try:
        return lookup_storage_object(backstore_object_name, backstore)
    except (RTSLibError, CephiSCSIError):
        return None


def lookup_storage_object(name, backstore):
    if backstore == USER_RBD:
        return UserBackedStorageObject(name=name)
    else:
        raise CephiSCSIError("Could not lookup storage object - "
                             "Unsupported backstore {}".format(backstore))

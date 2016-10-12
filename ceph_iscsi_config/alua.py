'''
This will eventually be moved to rtslib-fb, so it can be used
by targetcli-fb
'''
from rtslib_fb import BlockStorageObject
from rtslib_fb.target import TPG
from rtslib_fb.node import CFSNode
from rtslib_fb.utils import RTSLibError, fread, fwrite
from rtslib_fb import root

class ALUATargetPortGroup(CFSNode):
    """
    ALUA Target Port Group interface
    """

    def __repr__(self):
        return "<ALUA TPG %s>" % self.name

    def __init__(self, storage_obj, name, tag=None):
        """
        @param storage_obj: backstore storage object to create ALUA group for
        @param name: name of ALUA group
        @param tag: target port group id. If not passed in, try to look
                    up existing ALUA TPG with the same name
        """

        # default_tg_pt_gp takes tag 1
        if tag is not None and (tag > 65535 or tag < 1):
            raise RTSLibError("The TPG Tag must be between 1 and 65535")

        super(ALUATargetPortGroup, self).__init__()
        self.name = name
        self.storage_obj = storage_obj

        self._path = "%s/alua/%s" % (storage_obj.path, name)

        if tag is not None:
            try:
                self._create_in_cfs_ine('create')
            except OSError as msg:
                raise RTSLibError(msg)

            try:
                fwrite("%s/tg_pt_gp_id" % self._path, tag)
            except IOError as msg:
                self.delete()
                raise RTSLibError("Cannot set id to %d: %s" % (tag, str(msg)))
        else:
            try:
                self._create_in_cfs_ine('lookup')
            except OSError as msg:
                raise RTSLibError(msg)

    # Public

    def bind_to_lun(self, mapped_lun):
        path = "%s/alua_tg_pt_gp" % mapped_lun.path
        try:
            fwrite(path, str(self.name))
        except IOError as msg:
            raise RTSLibError("Cannot set tpg: " % str(msg))

    def delete(self):
        """
        Delete ALUA TPG and unmap LUNs
        """
        self._check_self()
        # This will reset the ALUA tpg to default_tg_pt_gp
        super(ALUATargetPortGroup, self).delete()

    def _get_alua_access_state(self):
        self._check_self()
        path = "%s/alua_access_state" % self.path
        return int(fread(path))

    def _set_alua_access_state(self, newstate):
        self._check_self()
        path = "%s/alua_access_state" % self.path
        try:
            fwrite(path, str(int(newstate)))
        except IOError as e:
            raise RTSLibError("Cannot change ALUA state: %s" % e)

    def _get_alua_access_type(self):
        self._check_self()
        path = "%s/alua_access_type" % self.path
        return int(fread(path))

    def _set_alua_access_type(self, access_type):
        self._check_self()
        path = "%s/alua_access_type" % self.path
        try:
            fwrite(path, str(int(access_type)))
        except IOError as e:
            raise RTSLibError("Cannot change ALUA access type: %s" % e)

    def _get_preferred(self):
        self._check_self()
        path = "%s/preferred" % self.path
        return int(fread(path))

    def _set_preferred(self, pref):
        self._check_self()
        path = "%s/preferred" % self.path
        try:
            fwrite(path, str(int(pref)))
        except IOError as e:
            raise RTSLibError("Cannot set preferred: %s" % e)

    def _get_alua_support_active_nonoptimized(self):
        self._check_self()
        path = "%s/alua_support_active_nonoptimized" % self.path
        return int(fread(path))

    def _set_alua_support_active_nonoptimized(self, enabled):
        self._check_self()
        path = "%s/alua_support_active_nonoptimized" % self.path
        try:
            fwrite(path, str(int(enabled)))
        except IOError as e:
            raise RTSLibError("Cannot set alua_support_active_nonoptimized: %s" % e)

    def _get_alua_support_active_optimized(self):
        self._check_self()
        path = "%s/alua_support_active_optimized" % self.path
        return int(fread(path))

    def _set_alua_support_active_optimized(self, enabled):
        self._check_self()
        path = "%s/alua_support_active_optimized" % self.path
        try:
            fwrite(path, str(int(enabled)))
        except IOError as e:
            raise RTSLibError("Cannot set alua_support_active_optimized: %s" % e)

    def _get_alua_support_offline(self):
        self._check_self()
        path = "%s/alua_support_offline" % self.path
        return int(fread(path))

    def _set_alua_support_offline(self, enabled):
        self._check_self()
        path = "%s/alua_support_offline" % self.path
        try:
            fwrite(path, str(int(enabled)))
        except IOError as e:
            raise RTSLibError("Cannot set alua_support_offline: %s" % e)

    def _get_alua_support_unavailable(self):
        self._check_self()
        path = "%s/alua_support_unavailable" % self.path
        return int(fread(path))

    def _set_alua_support_unavailable(self, enabled):
        self._check_self()
        path = "%s/alua_support_unavailable" % self.path
        try:
            fwrite(path, str(int(enabled)))
        except IOError as e:
            raise RTSLibError("Cannot set alua_support_unavailable: %s" % e)

    def _get_alua_support_standby(self):
        self._check_self()
        path = "%s/alua_support_standby" % self.path
        return int(fread(path))

    def _set_alua_support_standby(self, enabled):
        self._check_self()
        path = "%s/alua_support_standby" % self.path
        try:
            fwrite(path, str(int(enabled)))
        except IOError as e:
            raise RTSLibError("Cannot set alua_support_standby: %s" % e)

    def _get_tpg_id(self):
        self._check_self()
        path = "%s/tg_pt_gp_id" % self.path
        return int(fread(path))

    alua_access_state = property(_get_alua_access_state, _set_alua_access_state,
                                 doc="Get or set ALUA state. "
                                     "0 = Active/optimized, "
                                     "1 = Active/non-optimized, "
                                     "2 = Standby, "
                                     "3 = Unavailable, "
                                     "14 = Offline")

    alua_access_type = property(_get_alua_access_type, _set_alua_access_type,
                                doc="Get or set ALUA access type. "
                                    "1 = Implicit, 2 = Explicit, 3 = Both")

    preferred = property(_get_preferred, _set_preferred,
                         doc="Get or set preferred bit. 1 = Pref, 0 Not-Pre")

    tpg_id = property(_get_tpg_id,
                      doc="Get ALUA Target Port Group ID")

    alua_support_active_nonoptimized = property(_get_alua_support_active_nonoptimized,
                                                _set_alua_support_active_nonoptimized,
                                                doc="Enable (1) or disable (0) "
                                                    "Active/non-optimized support")

    alua_support_active_optimized = property(_get_alua_support_active_optimized,
                                             _set_alua_support_active_optimized,
                                             doc="Enable (1) or disable (0) "
                                                 "Active/optimized support")

    alua_support_offline = property(_get_alua_support_offline,
                                    _set_alua_support_offline,
                                    doc="Enable (1) or disable (0) "
                                        "offline support")

    alua_support_unavailable = property(_get_alua_support_unavailable,
                                        _set_alua_support_unavailable,
                                        doc="enable (1) or disable (0) "
                                            "unavailable support")
    alua_support_standby = property(_get_alua_support_standby,
                                    _set_alua_support_standby,
                                    doc="enable (1) or disable (0) "
                                        "standby support")

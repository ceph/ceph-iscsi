from rtslib_fb.alua import ALUATargetPortGroup
from rtslib_fb import BlockStorageObject
from rtslib_fb.target import TPG

import ceph_iscsi_config.settings as settings

def alua_format_group_name(tpg, failover_type, is_owner):
    if is_owner:
        return "ao"

    if failover_type == "explicit":
        return "standby{}".format(tpg.tag)
    else:
        return "ano{}".format(tpg.tag)

def alua_create_ao_group(so, tpg, group_name):
    alua_tpg = ALUATargetPortGroup(so, group_name, tpg.tag)
    alua_tpg.alua_support_active_optimized = 1
    alua_tpg.alua_access_state = 0

    return alua_tpg

def alua_create_implicit_group(tpg, so, group_name, is_owner):
    if is_owner:
        alua_tpg = alua_create_ao_group(so, tpg, group_name)
    else:
        alua_tpg = ALUATargetPortGroup(so, group_name, tpg.tag)
        alua_tpg.alua_access_state = 1

    alua_tpg.alua_support_active_nonoptimized = 1
    alua_tpg.alua_access_type = 1
    # Just make sure we get to at least attempt one op for the failover
    # process.
    alua_tpg.implicit_trans_secs = settings.config.osd_op_timeout + 15
    return alua_tpg

def alua_create_explicit_group(tpg, so, group_name, is_owner):
    if is_owner:
        alua_tpg = alua_create_ao_group(so, tpg, group_name)
        alua_tpg.preferred = 1
    else:
        alua_tpg = ALUATargetPortGroup(so, group_name, tpg.tag)

    alua_tpg.alua_support_standby = 1
    # Use Explicit but also set the Implicit bit so we can
    # update the kernel from configfs.
    alua_tpg.alua_access_type = 3
    # start ports in Standby, and let the initiator drive the initial
    # transition to AO.
    alua_tpg.alua_access_state = 2
    return alua_tpg

def alua_create_group(failover_type, tpg, so, is_owner):
    group_name = alua_format_group_name(tpg, failover_type, is_owner)

    if failover_type == "explicit":
        alua_tpg = alua_create_explicit_group(tpg, so, group_name, is_owner)
    else:
        # tmp drop down to implicit. Next patch will check for "implicit"
        # and add error handling up the stack if the failover_type is invalid.
        alua_tpg = alua_create_implicit_group(tpg, so, group_name, is_owner)

    alua_tpg.alua_support_active_optimized = 1
    alua_tpg.alua_support_offline = 0
    alua_tpg.alua_support_unavailable = 0
    alua_tpg.alua_support_transitioning = 1
    alua_tpg.nonop_delay_msecs = 0

    return alua_tpg

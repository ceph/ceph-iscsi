from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64encode, b64decode
import os

import rtslib_fb.root as lio_root

from socket import gethostname
from rtslib_fb.target import NodeACL, Target, TPG
from rtslib_fb.fabric import ISCSIFabricModule
from rtslib_fb.utils import RTSLibError, normalize_wwn

import ceph_iscsi_config.settings as settings

from ceph_iscsi_config.common import Config
from ceph_iscsi_config.utils import encryption_available, CephiSCSIError
from ceph_iscsi_config.gateway_object import GWObject


class GWClient(GWObject):
    """
    This class holds a representation of a client connecting to LIO
    """
    SETTINGS = ["dataout_timeout",
                "nopin_response_timeout",
                "nopin_timeout",
                "cmdsn_depth"]

    seed_metadata = {"auth": {"chap": '', "chap_mutual": ''},
                     "luns": {},
                     "group_name": ""
                     }

    def __init__(self, logger, client_iqn, image_list, chap, chap_mutual, target_iqn):
        """
        Instantiate an instance of an LIO client
        :param client_iqn: (str) iscsi iqn string
        :param image_list: (list) list of rbd images (pool/image) to attach
                           to this client or list of tuples (disk, lunid)
        :param chap: (str) chap credentials in the format 'user/password'
        :param chap_mutual: (str) chap_mutual credentials in the format 'user/password'
        :param target_iqn: (str) target iqn string
        :return:
        """

        self.target_iqn = target_iqn
        self.lun_lookup = {}        # only used for hostgroup based definitions
        self.requested_images = []

        # image_list is normally a list of strings (pool.image_name) but
        # group processing forces a specific lun id allocation to masked disks
        # in this scenario the image list is a tuple
        if image_list:

            if isinstance(image_list[0], tuple):
                # tuple format ('disk_name', {'lun_id': 0})...
                for disk_item in image_list:
                    disk_name = disk_item[0]
                    lun_id = disk_item[1].get('lun_id')
                    self.requested_images.append(disk_name)
                    self.lun_lookup[disk_name] = lun_id
            else:
                self.requested_images = image_list

        self.chap = chap                        # parameters for auth
        self.chap_mutual = chap_mutual          # parameters for mutual auth
        self.mutual = ''
        self.tpgauth = ''
        self.metadata = {}
        self.acl = None
        self.client_luns = {}
        self.tpg = None
        self.tpg_luns = {}
        self.lun_id_list = list(range(256))           # available LUN ids 0..255
        self.change_count = 0

        # enable commit to the config for changes by default
        self.commit_enabled = True

        self.logger = logger
        self.current_config = {}
        self.error = False
        self.error_msg = ''

        try:
            client_iqn, iqn_type = normalize_wwn(['iqn'], client_iqn)
        except RTSLibError as err:
            self.error = True
            self.error_msg = "Invalid iSCSI client name - {}".format(err)

        self.iqn = client_iqn

        # Validate the images list doesn't contain duplicate entries
        dup_images = set([rbd for rbd in image_list
                          if image_list.count(rbd) >= 2])
        if len(dup_images) > 0:
            self.error = True
            dup_string = ','.join(dup_images)
            self.error_msg = ("Client's image list contains duplicate rbd's"
                              ": {}".format(dup_string))

        try:
            super(GWClient, self).__init__('targets', target_iqn, logger,
                                           GWClient.SETTINGS)
        except CephiSCSIError as err:
            self.error = True
            self.error_msg = err

    def setup_luns(self):
        """
        Add the requested LUNs to the node ACL definition. The image list
        defined for the client is compared to the current runtime settings,
        resulting in new images being added, or images removed.
        """

        # first drop the current lunid's used from the candidate list
        # this allows luns to be added/removed, and new id's to occupy free lun-id
        # slots rather than simply tag on the end. In a high churn environment,
        # adding new lun(s) at highest lun +1 could lead to exhausting the
        # 255 lun limit per target
        self.client_luns = self.get_images(self.acl)
        for image_name in self.client_luns:
            lun_id = self.client_luns[image_name]['lun_id']
            self.lun_id_list.remove(lun_id)
            self.logger.debug("(Client.setup_luns) {} has id of "
                              "{}".format(image_name, lun_id))

        self.tpg_luns = self.get_images(self.tpg)
        current_map = dict(self.client_luns)

        for image in self.requested_images:
            if image in self.client_luns:
                del current_map[image]
                continue
            else:
                rc = self._add_lun(image, self.tpg_luns[image])
                if rc != 0:
                    self.error = True
                    self.error_msg = ("{} is missing from the tpg - unable "
                                      "to map".format(image))
                    self.logger.debug("(Client.setup) tpg luns "
                                      "{}".format(self.tpg_luns))
                    self.logger.error("(Client.setup) missing image '{}' from "
                                      "the tpg".format(image))
                    return

        # 'current_map' should be empty, if not the remaining images need
        # to be removed from the client
        if current_map:
            for image in current_map:
                self._del_lun_map(image)
                if self.error:
                    self.logger.error("(Client.setup) unable to delete {} from"
                                      " {}".format(self.iqn,
                                                   image))
                    return

    def update_acl_controls(self):
        self.logger.debug("(update_acl_controls) controls: {}".format(self.controls))
        self.acl.set_attribute('dataout_timeout', str(self.dataout_timeout))

        # Try to detect network problems so we can kill connections
        # and cleanup before the initiator has begun recovery and
        # failed over.

        # LIO default 30
        self.acl.set_attribute('nopin_response_timeout',
                               str(self.nopin_response_timeout))
        # LIO default 15
        self.acl.set_attribute('nopin_timeout', str(self.nopin_timeout))

        # LIO default 64
        self.acl.tcq_depth = self.cmdsn_depth

    def define_client(self):
        """
        Establish the links for this object to the corresponding ACL and TPG
        objects from LIO
        :return:
        """

        iscsi_fabric = ISCSIFabricModule()
        target = Target(iscsi_fabric, self.target_iqn, 'lookup')

        # NB. this will check all tpg's for a matching iqn
        for tpg in target.tpgs:
            for client in tpg.node_acls:
                if client.node_wwn == self.iqn:
                    self.acl = client
                    self.tpg = client.parent_tpg
                    try:
                        self.update_acl_controls()
                    except RTSLibError as err:
                        self.logger.error("(Client.define_client) FAILED to update "
                                          "{}".format(self.iqn))
                        self.error = True
                        self.error_msg = err
                    self.logger.debug("(Client.define_client) - {} already "
                                      "defined".format(self.iqn))
                    return

        # at this point the client does not exist, so create it
        # The configuration only has one active tpg, so pick that one for any
        # acl definitions
        for tpg in target.tpgs:
            if tpg.enable:
                self.tpg = tpg

        try:
            self.acl = NodeACL(self.tpg, self.iqn)
            self.update_acl_controls()
        except RTSLibError as err:
            self.logger.error("(Client.define_client) FAILED to define "
                              "{}".format(self.iqn))
            self.logger.debug("(Client.define_client) failure msg "
                              "{}".format(err))
            self.error = True
            self.error_msg = err
        else:
            self.logger.info("(Client.define_client) {} added "
                             "successfully".format(self.iqn))
            self.change_count += 1

    @staticmethod
    def define_clients(logger, config, target_iqn):
        """
        define the clients (nodeACLs) to the gateway definition
        :param logger: logger object to print to
        :param config: configuration dict from the rados pool
        :raises CephiSCSIError.
        """

        # Client configurations (NodeACL's)
        target_config = config.config['targets'][target_iqn]
        for client_iqn in target_config['clients']:
            client_metadata = target_config['clients'][client_iqn]
            client_chap = CHAP(client_metadata['auth']['chap'])
            client_chap_mutual = CHAP(client_metadata['auth']['chap_mutual'])

            image_list = list(client_metadata['luns'].keys())

            chap_str = client_chap.chap_str
            if client_chap.error:
                raise CephiSCSIError("Unable to decode password for {}. "
                                     "CHAP error: {}".format(client_iqn,
                                                             client_chap.error_msg))
            chap_mutual_str = client_chap_mutual.chap_str
            if client_chap_mutual.error:
                raise CephiSCSIError("Unable to decode password for {}. "
                                     "CHAP_MUTUAL error: {}".format(client_iqn,
                                                                    client_chap.error_msg))

            client = GWClient(logger,
                              client_iqn,
                              image_list,
                              chap_str,
                              chap_mutual_str,
                              target_iqn)

            client.manage('present')  # ensure the client exists

    def try_disable_auth(self, tpg):
        """
        Disable authentication (enable ACL mode) if this is the last CHAP user.

        LIO doesn't allow us to mix and match ACLs and auth under a tpg. We
        only allow ACL mode if there are not CHAP users.
        """

        for client in tpg.node_acls:
            if client.chap_userid or client.chap_password:
                return

        tpg.set_attribute('authentication', '0')

    def configure_auth(self, chap_credentials, chap_mutual_credentials, target_config):
        """
        Attempt to configure authentication for the client
        :return:
        """

        auth_enabled = False
        if '/' in chap_credentials:
            client_username, client_password = chap_credentials.split('/', 1)
            auth_enabled = True
        elif not chap_credentials:
            client_username = ''
            client_password = ''
            chap_credentials = "/"

        if '/' in chap_mutual_credentials:
            client_mutual_username, client_mutual_password = chap_mutual_credentials.split('/', 1)
            auth_enabled = True
        elif not chap_mutual_credentials:
            client_mutual_username = ''
            client_mutual_password = ''
            chap_mutual_credentials = "/"

        self.logger.debug("configuring auth chap={}, chap_mutual={}".format(
            chap_credentials, chap_mutual_credentials))

        acl_credentials = "{}/{}".format(self.acl.chap_userid,
                                         self.acl.chap_password)
        acl_mutual_credentials = "{}/{}".format(self.acl.chap_mutual_userid,
                                                self.acl.chap_mutual_password)

        try:
            self.logger.debug("Updating the ACL")
            if chap_credentials != acl_credentials:
                self.acl.chap_userid = client_username
                self.acl.chap_password = client_password

                new_chap = CHAP(chap_credentials)
                self.logger.debug("chap object set to: {},{},{},{}".format(
                    new_chap.chap_str, new_chap.user, new_chap.password,
                    new_chap.password_str))

                new_chap.chap_str = "{}/{}".format(client_username,
                                                   client_password)
                if new_chap.error:
                    self.error = True
                    self.error_msg = new_chap.error_msg
                    return

            if chap_mutual_credentials != acl_mutual_credentials:
                self.acl.chap_mutual_userid = client_mutual_username
                self.acl.chap_mutual_password = client_mutual_password

                new_chap_mutual = CHAP(chap_mutual_credentials)
                self.logger.debug("chap mutual object set to: {},{},{},{}".format(
                    new_chap_mutual.chap_str, new_chap_mutual.user, new_chap_mutual.password,
                    new_chap_mutual.password_str))

                new_chap_mutual.chap_str = "{}/{}".format(client_mutual_username,
                                                          client_mutual_password)
                if new_chap_mutual.error:
                    self.error = True
                    self.error_msg = new_chap_mutual.error_msg
                    return

            if auth_enabled:
                self.tpg.set_attribute('authentication', '1')
            else:
                self.try_disable_auth(self.tpg)

            self.logger.debug("Updating config object meta data")
            if chap_credentials != acl_credentials:
                self.metadata['auth']['chap'] = new_chap.chap_str
            if chap_mutual_credentials != acl_mutual_credentials:
                self.metadata['auth']['chap_mutual'] = new_chap_mutual.chap_str

        except RTSLibError as err:
            self.error = True
            self.error_msg = ("Unable to configure authentication "
                              "for {} - ".format(self.iqn,
                                                 err))
            self.logger.error("(Client.configure_auth) failed to set "
                              "credentials for {}".format(self.iqn))
        else:
            self.change_count += 1

        self._update_acl(target_config)

    def _update_acl(self, target_config):
        if self.tpg.node_acls:
            self.tpg.set_attribute('generate_node_acls', 0)
            if not target_config['acl_enabled']:
                target_config['acl_enabled'] = True
                self.change_count += 1

    def _add_lun(self, image, lun):
        """
        Add a given image to the client ACL
        :param image: rbd image name of the form pool/image (str)
        :param lun: rtslib lun object
        :return:
        """

        rc = 0
        # get the tpg lun to map this client to
        tpg_lun = lun['tpg_lun']

        # lunid allocated from the current config object setting, or if this is
        # a new device from the next free lun id 'position'
        if image in self.metadata['luns'].keys():
            lun_id = self.metadata['luns'][image]['lun_id']
        else:
            if image in self.lun_lookup:
                # this indicates a lun map for a group managed client
                lun_id = self.lun_lookup[image]
            else:
                lun_id = self.lun_id_list[0]  # pick lowest available lun ID

        self.logger.debug("(Client._add_lun) Adding {} to {} at "
                          "id {}".format(image, self.iqn, lun_id))

        try:
            m_lun = self.acl.mapped_lun(lun_id, tpg_lun=tpg_lun)
        except RTSLibError as err:
            self.logger.error("Client.add_lun RTSLibError for lun id {} -"
                              " {}".format(lun_id, err))
            rc = 12
        else:

            self.client_luns[image] = {"lun_id": lun_id,
                                       "mapped_lun": m_lun,
                                       "tpg_lun": tpg_lun}

            self.metadata['luns'][image] = {"lun_id": lun_id}
            self.lun_id_list.remove(lun_id)
            self.logger.info("(Client.add_lun) added image '{}' to "
                             "{}".format(image, self.iqn))
            self.change_count += 1

        return rc

    def _del_lun_map(self, image):
        """
        Delete a lun from the client's ACL
        :param image: rbd image name to remove
        :return:
        """

        lun = self.client_luns[image]['mapped_lun']
        try:
            lun.delete()
        except RTSLibError as err:
            self.error = True
            self.error_msg = err
        else:
            self.change_count += 1

            # the lun entry could have been deleted by another host, so before
            # we try and delete - make sure it's in our local copy of the
            # metadata!
            if image in self.metadata['luns']:
                del self.metadata['luns'][image]

    def delete(self):
        """
        Delete the client definition from LIO
        :return:
        """

        try:
            self.acl.delete()
            self.try_disable_auth(self.tpg)
            self.change_count += 1
            self.logger.info("(Client.delete) deleted NodeACL for "
                             "{}".format(self.iqn))
        except RTSLibError as err:
            self.error = True
            self.error_msg = "RTS NodeACL delete failure"
            self.logger.error("(Client.delete) failed to delete client {} "
                              "- error: {}".format(self.iqn,
                                                   err))

    def exists(self):
        """
        This function determines whether this instances iqn is already defined
        to LIO
        :return: Boolean
        """

        r = lio_root.RTSRoot()
        client_list = [client.node_wwn for client in r.node_acls]
        return self.iqn in client_list

    def seed_config(self, config):
        """
        function to seed the config object with a new client definition
        """
        target_config = config.config["targets"][self.target_iqn]
        target_config['clients'][self.iqn] = GWClient.seed_metadata
        config.update_item("targets", self.target_iqn, target_config)

        # persist the config update, and leave the connection to the ceph
        # object open since adding just the iqn is only the start of the
        # definition
        config.commit("retain")

    def manage(self, rqst_type, committer=None):
        """
        Manage the allocation or removal of this client
        :param rqst_type is either 'present' (try and create the nodeACL), or
        'absent' - delete the nodeACL
        :param committer is the host responsible for any commits to the
        configuration - this is not needed for Ansible management, but is used
        by the CLI->API->GWClient interaction
        """
        # Build a local object representing the rados configuration object
        config_object = Config(self.logger)
        if config_object.error:
            self.error = True
            self.error_msg = config_object.error_msg
            return

        # use current config to hold a copy of the current rados config
        # object (dict)
        self.current_config = config_object.config
        target_config = self.current_config['targets'][self.target_iqn]
        update_host = committer

        self.logger.debug("GWClient.manage) update host to handle any config "
                          "update is {}".format(update_host))

        if rqst_type == "present":

            ###################################################################
            # Ensure the client exists in LIO                                 #
            ###################################################################

            # first look at the request to see if it matches the settings
            # already in the config object - if so this is just a rerun, or a
            # reboot so config object updates are not needed when we change
            # the LIO environment
            if self.iqn in target_config['clients'].keys():
                self.metadata = target_config['clients'][self.iqn]
                config_image_list = sorted(self.metadata['luns'].keys())

                #
                # Does the request match the current config?

                # extract the chap_str from the config object entry
                config_chap = CHAP(self.metadata['auth']['chap'])
                chap_str = config_chap.chap_str
                if config_chap.error:
                    self.error = True
                    self.error_msg = config_chap.error_msg
                    return
                # extract the chap_mutual_str from the config object entry
                config_chap_mutual = CHAP(self.metadata['auth']['chap_mutual'])
                chap_mutual_str = config_chap_mutual.chap_str
                if config_chap_mutual.error:
                    self.error = True
                    self.error_msg = config_chap_mutual.error_msg
                    return

                if self.chap == chap_str and \
                   self.chap_mutual == chap_mutual_str and \
                   config_image_list == sorted(self.requested_images):
                    self.commit_enabled = False
            else:
                # requested iqn is not in the config object
                self.seed_config(config_object)
                self.metadata = GWClient.seed_metadata

            self.logger.debug("(manage) config updates to be applied from "
                              "this host: {}".format(self.commit_enabled))

            client_exists = self.exists()
            self.define_client()
            if self.error:
                # unable to define the client!
                return

            if client_exists and self.metadata["group_name"]:
                # bypass setup_luns for existing clients that have an
                # associated host group
                pass
            else:
                # either the client didn't exist (new or boot time), or the
                # group_name is not defined so run setup_luns for this client
                bad_images = self.validate_images()
                if not bad_images:

                    self.setup_luns()
                    if self.error:
                        return
                else:
                    # request for images to map to this client that haven't
                    # been added to LIO yet!
                    self.error = True
                    self.error_msg = ("Non-existent images {} requested "
                                      "for {}".format(bad_images, self.iqn))
                    return

            if self.chap == '' and self.chap_mutual == '':
                self.logger.warning("(main) client '{}' configured without"
                                    " security".format(self.iqn))

            self.configure_auth(self.chap, self.chap_mutual, target_config)
            if self.error:
                return

            # check the client object's change count, and update the config
            # object if this is the updating host
            if self.change_count > 0:

                if self.commit_enabled:

                    if update_host == gethostname().split('.')[0]:
                        # update the config object with this clients settings
                        self.logger.debug("Updating config object metadata "
                                          "for '{}'".format(self.iqn))
                        target_config['clients'][self.iqn] = self.metadata
                        config_object.update_item("targets",
                                                  self.target_iqn,
                                                  target_config)

                        # persist the config update
                        config_object.commit()

        elif rqst_type == 'reconfigure':
            self.define_client()

        else:
            ###################################################################
            # Remove the requested client from the config object and LIO      #
            ###################################################################
            if self.exists():
                self.define_client()   # grab the client and parent tpg objects
                self.delete()          # deletes from the local LIO instance
                if self.error:
                    return
                else:
                    # remove this client from the config

                    if update_host == gethostname().split('.')[0]:
                        self.logger.debug("Removing {} from the config "
                                          "object".format(self.iqn))
                        target_config['clients'].pop(self.iqn)
                        config_object.update_item("targets", self.target_iqn, target_config)
                        config_object.commit()

            else:
                # desired state is absent, but the client does not exist
                # in LIO - Nothing to do!
                self.logger.info("(main) client {} removal request, but it's"
                                 "not in LIO...skipping".format(self.iqn))

    def validate_images(self):
        """
        Confirm that the images listed are actually allocated to the tpg and
        can therefore be used by a client
        :return: a list of images that are NOT in the tpg ... should be empty!
        """
        bad_images = []
        tpg_lun_list = self.get_images(self.tpg).keys()
        self.logger.debug("tpg images: {}".format(tpg_lun_list))
        self.logger.debug("request images: {}".format(self.requested_images))
        for image in self.requested_images:
            if image not in tpg_lun_list:
                bad_images.append(image)

        return bad_images

    @staticmethod
    def get_update_host(config):
        """
        decide which gateway host should be responsible for any config object
        updates
        :param config: configuration dict from the rados pool
        :return: a suitable gateway host that is online
        """

        ptr = 0
        potential_hosts = [host_name for host_name in config["gateways"].keys()
                           if isinstance(config["gateways"][host_name], dict)]

        # Assume the 1st element from the list is OK for now
        # TODO check the potential hosts are online/available

        return potential_hosts[ptr]

    def get_images(self, rts_object):
        """
        Funtion to return a dict of luns mapped to either a node ACL or the
        TPG, based on the passed object type
        :param rts_object: rtslib object - either NodeACL or TPG
        :return: dict indexed by image name of LUN object attributes
        """

        luns_mapped = {}

        if isinstance(rts_object, NodeACL):
            # return a dict of images assigned to this client
            for m_lun in rts_object.mapped_luns:

                key = m_lun.tpg_lun.storage_object.name
                luns_mapped[key] = {"lun_id": m_lun.mapped_lun,
                                    "mapped_lun": m_lun,
                                    "tpg_lun": m_lun.tpg_lun}

        elif isinstance(rts_object, TPG):
            # return a dict of *all* images available to this tpg
            for m_lun in rts_object.luns:

                key = m_lun.storage_object.name
                luns_mapped[key] = {"lun_id": m_lun.lun,
                                    "mapped_lun": None,
                                    "tpg_lun": m_lun}
        return luns_mapped


class CHAP(object):

    def __init__(self, chap_str):

        self.error = False
        self.error_msg = ''

        if '/' in chap_str:
            self.user, self.password_str = chap_str.split('/', 1)

            if len(self.password_str) > 16 and encryption_available():
                self.password = self._decrypt()
            else:
                self.password = self.password_str
        else:
            self.user = ''
            self.password = ''

    def _get_chap_str(self):
        if len(self.password) > 0:
            return '{}/{}'.format(self.user,
                                  self.password)
        else:
            return ''

    def _set_chap_str(self, chap_str):

        self.user, self.password_str = chap_str.split('/', 1)

        if encryption_available() and len(self.password_str) > 0:
            self.password = self._encrypt()
        else:
            self.password = self.password_str

    def _decrypt(self):

        key_path = os.path.join(settings.config.ceph_config_dir,
                                settings.config.priv_key)
        try:
            with open(key_path, 'rb') as keyf:
                key = serialization.load_pem_private_key(keyf.read(), None,
                                                         default_backend())
            try:
                plain_pw = key.decrypt(b64decode(self.password_str),
                                       padding.OAEP(
                                           mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                           algorithm=hashes.SHA256(),
                                           label=None)).decode('utf-8')
            except ValueError:
                # decrypting a password that was encrypted with python-crypto?
                plain_pw = key.decrypt(b64decode(self.password_str),
                                       padding.OAEP(
                                           mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                           algorithm=hashes.SHA1(),
                                           label=None)).decode('utf-8')
        except Exception as ex:
            print(ex)
            self.error = True
            self.error_msg = 'Problems decoding the encrypted password'
            return None
        else:
            return plain_pw

    def _encrypt(self):
        key_path = os.path.join(settings.config.ceph_config_dir,
                                settings.config.pub_key)
        try:
            with open(key_path, 'rb') as keyf:
                key = serialization.load_pem_public_key(keyf.read(),
                                                        default_backend())

            encrypted_pw = b64encode(key.encrypt(self.password_str.encode('utf-8'),
                                     padding.OAEP(
                                         mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                         algorithm=hashes.SHA256(),
                                         label=None))).decode('utf-8')
        except Exception:
            self.error = True
            self.error_msg = 'Encoding password failed'
            return None
        else:
            return encrypted_pw

    chap_str = property(_get_chap_str,
                        _set_chap_str,
                        doc="get/set the chap string (user/password)")

# Copyright 2014 Big Switch Networks, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
This module manages the HTTP and HTTPS connections to the backend controllers.

The main class it provides for external use is ServerPool which manages a set
of ServerProxy objects that correspond to individual backend controllers.

The following functionality is handled by this module:
- Translation of rest_* function calls to HTTP/HTTPS calls to the controllers
- Automatic failover between controllers
- SSL Certificate enforcement
- HTTP Authentication

"""
import base64
import httplib
import re
import socket
import ssl
import time

from neutron_lib import exceptions

from oslo_log import log as logging

import eventlet
import eventlet.corolocal
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client as ksclient
from networking_bigswitch.plugins.bigswitch.db import consistency_db as cdb
from networking_bigswitch.plugins.bigswitch.i18n import _
from networking_bigswitch.plugins.bigswitch.i18n import _LE
from networking_bigswitch.plugins.bigswitch.i18n import _LI
from networking_bigswitch.plugins.bigswitch.i18n import _LW
from networking_bigswitch.plugins.bigswitch.utils import Util
import os
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import excutils
from sqlalchemy.types import Enum

LOG = logging.getLogger(__name__)

# The following are used to invoke the API on the external controller
CAPABILITIES_PATH = "/capabilities"
NET_RESOURCE_PATH = "/tenants/%s/networks"
PORT_RESOURCE_PATH = "/tenants/%s/networks/%s/ports"
ROUTER_RESOURCE_PATH = "/tenants/%s/routers"
ROUTER_INTF_OP_PATH = "/tenants/%s/routers/%s/interfaces"
SECURITY_GROUP_RESOURCE_PATH = "/securitygroups"
TENANT_RESOURCE_PATH = "/tenants"
NETWORKS_PATH = "/tenants/%s/networks/%s"
FLOATINGIPS_PATH = "/tenants/%s/floatingips/%s"
PORTS_PATH = "/tenants/%s/networks/%s/ports/%s"
ATTACHMENT_PATH = "/tenants/%s/networks/%s/ports/%s/attachment"
ROUTERS_PATH = "/tenants/%s/routers/%s"
ROUTER_INTF_PATH = "/tenants/%s/routers/%s/interfaces/%s"
SECURITY_GROUP_PATH = "/securitygroups/%s"
TENANT_PATH = "/tenants/%s"
TOPOLOGY_PATH = "/topology"
HEALTH_PATH = "/health"
SWITCHES_PATH = "/switches/%s"
TESTPATH_PATH = ('/testpath/controller-view'
                 '?src-tenant=%(src-tenant)s'
                 '&src-segment=%(src-segment)s&src-ip=%(src-ip)s'
                 '&dst-ip=%(dst-ip)s')
TENANTPOLICY_RESOURCE_PATH = "/tenants/%s/policies"
TENANTPOLICIES_PATH = "/tenants/%s/policies/%s"
SUCCESS_CODES = range(200, 207)
FAILURE_CODES = [0, 301, 302, 303, 400, 401, 403, 404, 500, 501, 502, 503,
                 504, 505]
BASE_URI = '/networkService/v2.0'
ORCHESTRATION_SERVICE_ID = 'Neutron v2.0'
HASH_MATCH_HEADER = 'X-BSN-BVS-HASH-MATCH'
SERVICE_TENANT = 'VRRP_Service'
KS_AUTH_GROUP_NAME = 'keystone_authtoken'
KS_AUTH_DOMAIN_DEFAULT = 'default'
# error messages
NXNETWORK = 'NXVNS'
HTTP_SERVICE_UNAVAILABLE_RETRY_COUNT = 3
HTTP_SERVICE_UNAVAILABLE_RETRY_INTERVAL = 3

KEYSTONE_SYNC_RATE_LIMIT = 30  # Limit KeyStone sync to once in 30 secs
# TOPO_SYNC Responses
TOPO_RESPONSE_OK = (httplib.OK, httplib.OK, True, True)
TOPO_RESPONSE_FAIL = (0, None, None, None)

# RE pattern for checking BCF supported names
BCF_IDENTIFIER_UUID_RE = re.compile(r"[0-9a-zA-Z][-.0-9a-zA-Z_]*")


class TenantIDNotFound(exceptions.NeutronException):
    message = _("Tenant: %(tenant)s is not known by keystone.")
    status = None

    def __init__(self, **kwargs):
        self.tenant = kwargs.get('tenant')
        super(TenantIDNotFound, self).__init__(**kwargs)


class UnsupportedNameException(exceptions.NeutronException):
    """UnsupportedNameException

    Exception class to be raised when encountering object names with
    unsupported names. Namely those that do not conform to the regular
    expression BCF_IDENTIFIER_UUID_RE

    :keyword obj_type
    :keyword obj_id
    :keyword obj_name
    """
    message = _("Object of type %(obj_type)s and id %(obj_id)s has unsupported"
                " character in name \"%(obj_name)s\". It should begin with an"
                " alphanumeric character [0-9a-zA-Z] and can contain space,"
                " underscore, apostrophe, forward slash, opening and closing"
                " square brackets.")
    status = None


class UnsupportedTenantNameInObjectException(exceptions.NeutronException):
    """Unsupported Tenant Name

    Exception class to be raised when objects have tenant names with
    unsupported characters. Namely those that do not conform to the regular
    expression BCF_IDENTIFIER_UUID_RE

    :keyword obj_type
    :keyword obj_id
    :keyword obj_name
    :keyword tenant_name
    """
    message = _("Object of type %(obj_type)s, id %(obj_id)s and name "
                "%(obj_name)s has unsupported character in its tenant name "
                "\"%(tenant_name)s\". It should begin with an"
                "alphanumeric character [0-9a-zA-Z] and can contain space,"
                "underscore, apostrophe and double-quotes.")
    status = None


class NetworkNameChangeError(exceptions.NeutronException):
    message = _("network name is not allowed to be changed.")
    status = None


class RemoteRestError(exceptions.NeutronException):
    message = _("Error in REST call to BCF "
                "controller: %(reason)s")
    status = None

    def __init__(self, **kwargs):
        self.status = kwargs.pop('status', None)
        self.reason = kwargs.get('reason')
        super(RemoteRestError, self).__init__(**kwargs)


class DictDiffer(object):
    """Calculate the difference between two dictionaries as:

    (1) items added
    (2) items removed
    (3) keys same in both but changed values
    (4) keys same in both and unchanged values
    """
    def __init__(self, current_dict, past_dict):
        self.current_dict, self.past_dict = current_dict, past_dict
        self.set_current, self.set_past = (set(current_dict.keys()),
                                           set(past_dict.keys()))
        self.intersect = self.set_current.intersection(self.set_past)

    def added(self):
        return self.set_current - self.intersect

    def removed(self):
        return self.set_past - self.intersect

    def changed(self):
        return set(o for o in self.intersect
                   if self.past_dict[o] != self.current_dict[o])

    def unchanged(self):
        return set(o for o in self.intersect
                   if self.past_dict[o] == self.current_dict[o])


class ObjTypeEnum(Enum):
    """Enum

    Enum to represent various object types whose name requires sanitization
    before syncing to the controller.
    """
    network = "network"
    router = "router"
    security_group = "security_group"
    subnet = "subnet"
    tenant = "tenant"


def is_valid_bcf_name(name):
    """Check if bcf name is valid

    :returns True if name matches BCF_IDENTIFIER_UUID_RE
    :returns False otherwise
    """
    match_obj = BCF_IDENTIFIER_UUID_RE.match(name)
    if match_obj and match_obj.group(0) == name:
        return True
    return False


def get_keystoneauth_cfg(conf, name):
    """get the keystone auth cfg

    Fetch value of keystone_authtoken group from config file when not
    available as part of GroupAttr.

    :rtype: String
    :param conf: oslo config cfg.CONF
    :param name: property name to be retrieved
    """
    try:

        value_list = conf._namespace._get_file_value([(KS_AUTH_GROUP_NAME,
                                                       name)])
        return value_list[0]
    except KeyError as e:
        LOG.warning("Config does not have property %(name)s "
                    "in group keystone_authtoken", {'name': name})
        raise e


class ServerProxy(object):
    """REST server proxy to a network controller."""

    def __init__(self, server, port, ssl, auth, neutron_id, timeout,
                 base_uri, name, mypool, combined_cert):
        self.server = server
        self.port = port
        self.ssl = ssl
        self.base_uri = base_uri
        self.timeout = timeout
        self.name = name
        self.success_codes = SUCCESS_CODES
        self.auth = None
        self.auth_token = None
        self.neutron_id = neutron_id
        self.failed = False
        self.capabilities = []
        # enable server to reference parent pool
        self.mypool = mypool
        # cache connection here to avoid a SSL handshake for every connection
        self.currentconn = None

        if auth:
            if ':' in auth:
                self.auth = 'Basic ' + base64.encodestring(auth).strip()
            else:
                self.auth_token = 'session_cookie="' + auth + '"'

        self.combined_cert = combined_cert

    def get_capabilities(self):
        try:
            body = self.rest_call('GET', CAPABILITIES_PATH)[2]
            if body:
                self.capabilities = jsonutils.loads(body)
        except Exception:
            LOG.exception("Couldn't retrieve capabilities on server "
                          "%(server)s. ", {'server': self.server})
        LOG.info("The following capabilities were received "
                 "for %(server)s: %(cap)s",
                 {'server': self.server, 'cap': self.capabilities})
        return self.capabilities

    def rest_call(self, action, resource, data='', headers=None,
                  timeout=False, reconnect=False):
        uri = self.base_uri + resource
        body = jsonutils.dumps(data)
        headers = headers or {}
        headers['Content-type'] = 'application/json'
        headers['Accept'] = 'application/json'
        headers['NeutronProxy-Agent'] = self.name
        headers['Instance-ID'] = self.neutron_id
        headers['Orchestration-Service-ID'] = ORCHESTRATION_SERVICE_ID

        # TODO(kevinbenton): Re-enable keep-alive in a thread-safe fashion.
        # When multiple workers are enabled the saved connection gets mangled
        # by multiple threads so we always reconnect.
        if 'keep-alive' in self.capabilities and False:
            headers['Connection'] = 'keep-alive'
        else:
            reconnect = True

        if self.auth_token:
            headers['Cookie'] = self.auth_token
        elif self.auth:
            headers['Authorization'] = self.auth

        LOG.debug("ServerProxy: server=%(server)s, port=%(port)d, "
                  "ssl=%(ssl)r",
                  {'server': self.server, 'port': self.port, 'ssl': self.ssl})
        LOG.debug("ServerProxy: resource=%(resource)s, data=%(data)r, "
                  "headers=%(headers)r, action=%(action)s",
                  {'resource': resource, 'data': data, 'headers': headers,
                   'action': action})

        # unspecified timeout is False because a timeout can be specified as
        # None to indicate no timeout.
        if timeout is False:
            timeout = self.timeout

        if timeout != self.timeout:
            # need a new connection if timeout has changed
            reconnect = True

        if not self.currentconn or reconnect:
            if self.currentconn:
                self.currentconn.close()
            if self.ssl:
                currentconn = HTTPSConnectionWithValidation(
                    self.server, self.port, timeout=timeout)
                if currentconn is None:
                    LOG.error('ServerProxy: Could not establish HTTPS '
                              'connection')
                    return 0, None, None, None
                currentconn.combined_cert = self.combined_cert
            else:
                currentconn = httplib.HTTPConnection(
                    self.server, self.port, timeout=timeout)
                if currentconn is None:
                    LOG.error('ServerProxy: Could not establish HTTP '
                              'connection')
                    return 0, None, None, None

        try:
            bcf_request_time = time.time()
            currentconn.request(action, uri, body, headers)
            response = currentconn.getresponse()
            respstr = response.read()
            respdata = respstr
            bcf_response_time = time.time()
            LOG.debug("Time waited to get response from BCF %.2fsecs",
                      (bcf_response_time - bcf_request_time))
            if response.status in self.success_codes:
                try:
                    respdata = jsonutils.loads(respstr)
                except ValueError:
                    # response was not JSON, ignore the exception
                    pass

            ret = (response.status, response.reason, respstr, respdata)
        except httplib.HTTPException:
            # If we were using a cached connection, try again with a new one.
            with excutils.save_and_reraise_exception() as ctxt:
                currentconn.close()
                if reconnect:
                    # if reconnect is true, this was on a fresh connection so
                    # reraise since this server seems to be broken
                    ctxt.reraise = True
                else:
                    # if reconnect is false, it was a cached connection so
                    # try one more time before re-raising
                    ctxt.reraise = False
            return self.rest_call(action, resource, data, headers,
                                  timeout=timeout, reconnect=True)
        except (socket.timeout, socket.error) as e:
            currentconn.close()
            LOG.error('ServerProxy: %(action)s failure, %(e)r',
                      {'action': action, 'e': e})
            ret = 0, None, None, None
        LOG.debug("ServerProxy: status=%(status)d, reason=%(reason)r, "
                  "ret=%(ret)s, data=%(data)r", {'status': ret[0],
                                                 'reason': ret[1],
                                                 'ret': ret[2],
                                                 'data': ret[3]})
        return ret


class ServerPool(object):

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance:
            return cls._instance
        cls._instance = cls()
        return cls._instance

    def __init__(self, timeout=False,
                 base_uri=BASE_URI, name='NeutronRestProxy'):
        LOG.debug("ServerPool: initializing")
        # 'servers' is the list of network controller REST end-points
        # (used in order specified till one succeeds, and it is sticky
        # till next failure). Use 'server_auth' to encode api-key
        servers = cfg.CONF.RESTPROXY.servers
        self.auth = cfg.CONF.RESTPROXY.server_auth
        self.ssl = cfg.CONF.RESTPROXY.server_ssl
        self.neutron_id = cfg.CONF.RESTPROXY.neutron_id
        # unicode config
        self.cfg_unicode_enabled = cfg.CONF.RESTPROXY.naming_scheme_unicode
        self.capabilities = set()

        if 'keystone_authtoken' in cfg.CONF:
            self.auth_user = get_keystoneauth_cfg(cfg.CONF, 'username')
            self.auth_password = get_keystoneauth_cfg(cfg.CONF, 'password')
            self.auth_url = get_keystoneauth_cfg(cfg.CONF, 'auth_url')
            self.auth_tenant = get_keystoneauth_cfg(cfg.CONF, 'project_name')
            self.project_domain_name = get_keystoneauth_cfg(
                cfg.CONF, 'project_domain_name')
            self.user_domain_name = get_keystoneauth_cfg(
                cfg.CONF, 'user_domain_name')
        else:
            # this is for UT only
            LOG.warning("keystone_authtoken not found in "
                        "/etc/neutron/neutron.conf. "
                        "Please check config file")
            self.auth_url = cfg.CONF.RESTPROXY.auth_url
            self.auth_user = cfg.CONF.RESTPROXY.auth_user
            self.auth_password = cfg.CONF.RESTPROXY.auth_password
            self.auth_tenant = cfg.CONF.RESTPROXY.auth_tenant
            self.project_domain_name = KS_AUTH_DOMAIN_DEFAULT
            self.user_domain_name = KS_AUTH_DOMAIN_DEFAULT

        # Use Keystonev3 URL for authentication
        if "v2.0" in self.auth_url:
            self.auth_url = self.auth_url.replace("v2.0", "v3")
        elif "v3" not in self.auth_url:
            self.auth_url = "%s/v3" % self.auth_url

        self.base_uri = base_uri
        self.name = name
        # Cache for Openstack projects
        # The cache is maintained in a separate thread and sync'ed with
        # Keystone periodically.
        self.keystone_tenants = {}

        self.timeout = cfg.CONF.RESTPROXY.server_timeout
        self.always_reconnect = not cfg.CONF.RESTPROXY.cache_connections
        default_port = 8000
        if timeout is not False:
            self.timeout = timeout

        # Function to use to retrieve topology for consistency syncs.
        # Needs to be set by module that uses the servermanager.
        self.get_topo_function = None
        self.get_topo_function_args = {}

        if not servers:
            raise cfg.Error(_('Servers not defined. Aborting server manager.'))
        servers = [s if len(s.rsplit(':', 1)) == 2
                   else "%s:%d" % (s, default_port)
                   for s in servers]
        if any((len(spl) != 2 or not spl[1].isdigit())
               for spl in [sp.rsplit(':', 1)
                           for sp in servers]):
            raise cfg.Error(_('Servers must be defined as <ip>:<port>. '
                              'Configuration was %s') % servers)
        self.servers = []
        for s in servers:
            server, port = s.rsplit(':', 1)
            if server.startswith("[") and server.endswith("]"):
                # strip [] for ipv6 address
                server = server[1:-1]
            self.servers.append(self.server_proxy_for(server, int(port)))

        # update capabilities
        self.get_capabilities()

        self._update_tenant_cache(reconcile=False)

        self.start_background_tasks()

        ServerPool._instance = self

        LOG.debug("ServerPool: initialization done")

    def start_background_tasks(self):
        # consistency check, starts after 1* consistency_interval
        eventlet.spawn(self._consistency_watchdog,
                       cfg.CONF.RESTPROXY.consistency_interval)

        # Start keystone sync thread after 5 consistency sync
        # to give enough time for topology to sync over when
        # neutron-server starts.
        eventlet.spawn_after(
            5 * cfg.CONF.RESTPROXY.consistency_interval,
            self._keystone_sync,
            cfg.CONF.RESTPROXY.keystone_sync_interval)

    def get_capabilities(self):
        """Get capabilities

        If cache has the value, use it
        If Not, do REST calls to BCF controllers to check it

        :return: supported capability list
        """
        # lookup on first try
        # if capabilities is empty, the check is either not done, or failed
        if self.capabilities:
            return self.capabilities

        # Do REST calls to update capabilities at startup
        # Servers should be the same version
        # If one server is down, use online server's capabilities
        capability_list = [set(server.get_capabilities())
                           for server in self.servers]

        new_capabilities = set.union(*capability_list)

        if new_capabilities:
            # Log unicode status
            self.log_unicode_status(new_capabilities)
            self.capabilities = new_capabilities

        # With multiple workers enabled, the fork may occur after the
        # connections to the DB have been established. We need to clear the
        # connections after the first attempt to call the backend to ensure
        # that the established connections will all be local to the thread and
        # not shared. Placing it here in the capabilities call is the easiest
        # way to ensure that its done after everything is initialized and the
        # first call to the backend is made.
        # This is necessary in our plugin and not others because we have a
        # completely separate DB connection for the consistency records. The
        # main connection is made thread-safe in the neutron service init.
        # https://github.com/openstack/neutron/blob/
        # ec716b9e68b8b66a88218913ae4c9aa3a26b025a/neutron/wsgi.py#L104
        if cdb.HashHandler._FACADE:
            cdb.HashHandler._FACADE.get_engine().pool.dispose()

        if not new_capabilities:
            LOG.error('Failed to get capabilities on any controller. ')
        return self.capabilities

    def log_unicode_status(self, new_capabilities):
        """Log unicode running status

        :param new_capabilities: new capabilities
        :return:
        """
        # unicode disabled by user
        if not self.cfg_unicode_enabled:
            LOG.info('naming_scheme_unicode is set to False,'
                     ' Unicode names Disabled')
        # unicode enabled and supported by controller
        elif 'display-name' in new_capabilities:
            LOG.info('naming_scheme_unicode is set to True,'
                     ' Unicode names Enabled')
        # unicode enabled, but not supported by controller
        else:
            LOG.warning('naming_scheme_unicode is set to True,'
                        ' but BCF does not support it.'
                        ' Unicode names Disabled')

    def is_unicode_enabled(self):
        """Check unicode running status

        True: enabled
        False: disabled
        """
        LOG.debug('Current Capabilities: %s', self.get_capabilities())
        if not self.get_capabilities():
            msg = 'Capabilities unknown! Please check BCF controller status.'
            raise RemoteRestError(reason=msg)

        if self.cfg_unicode_enabled and 'display-name' in \
                self.get_capabilities():
            LOG.debug('Unicode Check=True')
            return True
        else:
            LOG.debug('Unicode Check=False')
            return False

    def server_proxy_for(self, server, port):
        combined_cert = self._get_combined_cert_for_server(server, port)
        return ServerProxy(server, port, self.ssl, self.auth, self.neutron_id,
                           self.timeout, self.base_uri, self.name, mypool=self,
                           combined_cert=combined_cert)

    def _get_combined_cert_for_server(self, server, port):
        # The ssl library requires a combined file with all trusted certs
        # so we make one containing the trusted CAs and the corresponding
        # host cert for this server
        combined_cert = None
        if self.ssl and not cfg.CONF.RESTPROXY.no_ssl_validation:
            base_ssl = cfg.CONF.RESTPROXY.ssl_cert_directory
            host_dir = os.path.join(base_ssl, 'host_certs')
            ca_dir = os.path.join(base_ssl, 'ca_certs')
            combined_dir = os.path.join(base_ssl, 'combined')
            combined_cert = os.path.join(combined_dir, '%s.pem' % server)
            if not os.path.exists(base_ssl):
                raise cfg.Error(_('ssl_cert_directory [%s] does not exist. '
                                  'Create it or disable ssl.') % base_ssl)
            for automake in [combined_dir, ca_dir, host_dir]:
                if not os.path.exists(automake):
                    os.makedirs(automake)

            # get all CA certs
            certs = self._get_ca_cert_paths(ca_dir)

            # check for a host specific cert
            hcert, exists = self._get_host_cert_path(host_dir, server)
            if exists:
                certs.append(hcert)
            elif cfg.CONF.RESTPROXY.ssl_sticky:
                self._fetch_and_store_cert(server, port, hcert)
                certs.append(hcert)
            if not certs:
                raise cfg.Error(_('No certificates were found to verify '
                                  'controller %s') % (server))
            self._combine_certs_to_file(certs, combined_cert)
        return combined_cert

    def _combine_certs_to_file(self, certs, cfile):
        """_combine_certs_to_file

        Concatenates the contents of each certificate in a list of
        certificate paths to one combined location for use with ssl
        sockets.
        """
        with open(cfile, 'w') as combined:
            for c in certs:
                with open(c, 'r') as cert_handle:
                    combined.write(cert_handle.read())

    def _get_host_cert_path(self, host_dir, server):
        """returns full path and boolean indicating existence"""
        hcert = os.path.join(host_dir, '%s.pem' % server)
        if os.path.exists(hcert):
            return hcert, True
        return hcert, False

    def _get_ca_cert_paths(self, ca_dir):
        certs = [os.path.join(root, name)
                 for name in [
                     name for (root, dirs, files) in os.walk(ca_dir)
                     for name in files]
                 if name.endswith('.pem')]
        return certs

    def _fetch_and_store_cert(self, server, port, path):
        """_fetch_and_store_cert

        Grabs a certificate from a server and writes it to
        a given path.
        """
        try:
            cert = ssl.get_server_certificate((server, port),
                                              ssl_version=ssl.PROTOCOL_SSLv23)
        except Exception as e:
            raise cfg.Error(_('Could not retrieve initial '
                              'certificate from controller %(server)s. '
                              'Error details: %(error)s') %
                            {'server': server, 'error': e})

        LOG.warning("Storing to certificate for host %(server)s "
                    "at %(path)s", {'server': server, 'path': path})
        self._file_put_contents(path, cert)

        return cert

    def _file_put_contents(self, path, contents):
        # Simple method to write to file.
        # Created for easy Mocking
        with open(path, 'w') as handle:
            handle.write(contents)

    def server_failure(self, resp, ignore_codes=None):
        """Define failure codes as required.

        Note: We assume 301-303 is a failure, and try the next server in
        the server pool.
        """
        if ignore_codes is None:
            ignore_codes = []
        return (resp[0] in FAILURE_CODES and resp[0] not in ignore_codes)

    def action_success(self, resp):
        """Defining success codes as required.

        Note: We assume any valid 2xx as being successful response.
        """
        return resp[0] in SUCCESS_CODES

    def rest_call(self, action, resource, data, headers, ignore_codes,
                  timeout=False):
        good_first = sorted(self.servers, key=lambda x: x.failed)
        first_response = None
        for active_server in good_first:
            LOG.debug("ServerProxy: %(action)s to servers: "
                      "%(server)r, %(resource)s",
                      {'action': action,
                       'server': (active_server.server,
                                  active_server.port),
                       'resource': resource})
            for x in range(HTTP_SERVICE_UNAVAILABLE_RETRY_COUNT + 1):
                ret = active_server.rest_call(action, resource, data, headers,
                                              timeout,
                                              reconnect=self.always_reconnect)
                if ret[0] != httplib.SERVICE_UNAVAILABLE:
                    break
                eventlet.sleep(HTTP_SERVICE_UNAVAILABLE_RETRY_INTERVAL)

            # Store the first response as the error to be bubbled up to the
            # user since it was a good server. Subsequent servers will most
            # likely be cluster slaves and won't have a useful error for the
            # user (e.g. 302 redirect to master)
            if not first_response:
                first_response = ret
            if not self.server_failure(ret, ignore_codes):
                active_server.failed = False
                LOG.debug("ServerProxy: %(action)s succeed for servers: "
                          "%(server)r Response: %(response)s",
                          {'action': action,
                           'server': (active_server.server,
                                      active_server.port),
                           'response': ret[3]})
                return ret
            else:
                LOG.warning('ServerProxy: %(action)s failure for servers:'
                            '%(server)r Response: %(response)s',
                            {'action': action,
                             'server': (active_server.server,
                                        active_server.port),
                             'response': ret[3]})
                LOG.warning("ServerProxy: Error details: "
                            "status=%(status)d, reason=%(reason)r, "
                            "ret=%(ret)s, data=%(data)r",
                            {'status': ret[0], 'reason': ret[1],
                             'ret': ret[2], 'data': ret[3]})
                active_server.failed = True

        # All servers failed, reset server list and try again next time
        LOG.error('ServerProxy: %(action)s failure for all servers: '
                  '%(server)r',
                  {'action': action,
                   'server': tuple((s.server,
                                    s.port) for s in self.servers)})
        return first_response

    def rest_action(self, action, resource, data='', errstr='%s',
                    ignore_codes=None, headers=None, timeout=False):
        """rest_action

        Wrapper for rest_call that verifies success and raises a
        RemoteRestError on failure with a provided error string
        By default, 404 errors on DELETE calls are ignored because
        they already do not exist on the backend.
        """
        ignore_codes = ignore_codes or []
        headers = headers or {}
        if not ignore_codes and action == 'DELETE':
            ignore_codes = [404]
        resp = self.rest_call(action, resource, data, headers, ignore_codes,
                              timeout)
        if self.server_failure(resp, ignore_codes):
            # Request wasn't success, nor can be ignored,
            # do a full synchronization if auto_sync_on_failure is True
            if (cfg.CONF.RESTPROXY.auto_sync_on_failure and
                    resource != TOPOLOGY_PATH):
                LOG.error(_LE("NeutronRestProxyV2: Inconsistency with backend "
                              "controller, triggering full synchronization. "
                              "%(action)s %(resource)s."),
                          {'action': action, 'resource': resource})
                sync_executed, topo_resp = self.force_topo_sync(check_ts=True)
                if sync_executed:
                    return topo_resp
            # either topo_sync not executed or topo_sync itself failed
            LOG.error(errstr, resp[2])
            raise RemoteRestError(reason=resp[2], status=resp[0])
        if resp[0] in ignore_codes:
            LOG.info("NeutronRestProxyV2: Received and ignored error "
                     "code %(code)s on %(action)s action to resource "
                     "%(resource)s",
                     {'code': resp[2], 'action': action,
                      'resource': resource})
        return resp

    def _check_and_raise_exception_unsupported_name(self, obj_type, obj):
        """_check_and_raise_exception_unsupported_name

        Used to sanity check object names and tenant names within an object.
        If they do not comply with the BCF expectation, raises an exception.

        :returns None if all ok
        :raises UnsupportedNameException or
                UnsupportedTenantNameInObjectException if name does not match
                BCF expectation
        """
        if ('name' in obj and obj['name'] and
                not is_valid_bcf_name(obj['name'])):
            raise UnsupportedNameException(obj_type=obj_type,
                                           obj_id=obj['id'],
                                           obj_name=obj['name'])
        if ('tenant_name' in obj and
                not is_valid_bcf_name(obj['tenant_name'])):
            raise UnsupportedTenantNameInObjectException(
                obj_type=obj_type, obj_id=obj['id'], obj_name=obj['name'],
                tenant_name=obj['tenant_name'])

    def rest_create_tenant(self, tenant_id):
        self._update_tenant_cache()
        self._rest_create_tenant(tenant_id)

    def _rest_create_tenant(self, tenant_id):
        tenant_name = self.keystone_tenants.get(tenant_id)
        if not tenant_name:
            raise TenantIDNotFound(tenant=tenant_id)

        if self.is_unicode_enabled():
            data = {"tenant_id": tenant_id, 'tenant_name': tenant_id,
                    'display-name': tenant_name}
        else:
            if not is_valid_bcf_name(tenant_name):
                raise UnsupportedNameException(obj_type=ObjTypeEnum.tenant,
                                               obj_id=tenant_id,
                                               obj_name=tenant_name)
            data = {"tenant_id": tenant_id, 'tenant_name': tenant_name}
        resource = TENANT_RESOURCE_PATH
        errstr = _("Unable to create tenant: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_delete_tenant(self, tenant_id):
        resource = TENANT_PATH % tenant_id
        errstr = _("Unable to delete tenant: %s")
        self.rest_action('DELETE', resource, errstr=errstr)

    def rest_create_router(self, tenant_id, router):
        self._check_and_raise_exception_unsupported_name(ObjTypeEnum.router,
                                                         router)

        resource = ROUTER_RESOURCE_PATH % tenant_id
        data = {"router": router}
        errstr = _("Unable to create remote router: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_update_router(self, tenant_id, router, router_id):
        self._check_and_raise_exception_unsupported_name(ObjTypeEnum.router,
                                                         router)
        resource = ROUTERS_PATH % (tenant_id, router_id)
        data = {"router": router}
        errstr = _("Unable to update remote router: %s")
        self.rest_action('PUT', resource, data, errstr)

    def rest_delete_router(self, tenant_id, router_id):
        resource = ROUTERS_PATH % (tenant_id, router_id)
        errstr = _("Unable to delete remote router: %s")
        self.rest_action('DELETE', resource, errstr=errstr)

    def rest_add_router_interface(self, tenant_id, router_id, intf_details):
        resource = ROUTER_INTF_OP_PATH % (tenant_id, router_id)
        data = {"interface": intf_details}
        errstr = _("Unable to add router interface: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_remove_router_interface(self, tenant_id, router_id, interface_id):
        resource = ROUTER_INTF_PATH % (tenant_id, router_id, interface_id)
        errstr = _("Unable to delete remote intf: %s")
        self.rest_action('DELETE', resource, errstr=errstr)

    def rest_create_network(self, tenant_id, network):
        self._check_and_raise_exception_unsupported_name(ObjTypeEnum.network,
                                                         network)
        if 'subnets' in network:
            for subnet in network['subnets']:
                self._check_and_raise_exception_unsupported_name(
                    ObjTypeEnum.subnet, subnet)
        resource = NET_RESOURCE_PATH % tenant_id
        data = {"network": network}
        errstr = _("Unable to create remote network: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_update_network(self, tenant_id, net_id, network):
        self._check_and_raise_exception_unsupported_name(ObjTypeEnum.network,
                                                         network)
        if 'subnets' in network:
            for subnet in network['subnets']:
                self._check_and_raise_exception_unsupported_name(
                    ObjTypeEnum.subnet, subnet)
        resource = NETWORKS_PATH % (tenant_id, net_id)
        data = {"network": network}
        errstr = _("Unable to update remote network: %s")
        self.rest_action('PUT', resource, data, errstr)

    def rest_delete_network(self, tenant_id, net_id):
        resource = NETWORKS_PATH % (tenant_id, net_id)
        errstr = _("Unable to delete remote network: %s")
        self.rest_action('DELETE', resource, errstr=errstr)

    def rest_create_securitygroup(self, sg):
        self._check_and_raise_exception_unsupported_name(
            ObjTypeEnum.security_group, sg)
        resource = SECURITY_GROUP_RESOURCE_PATH
        data = {"security-group": sg}
        errstr = _("Unable to create security group: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_delete_securitygroup(self, sg_id):
        resource = SECURITY_GROUP_PATH % sg_id
        errstr = _("Unable to delete security group: %s")
        self.rest_action('DELETE', resource, errstr=errstr)

    def rest_get_port(self, tenant_id, net_id, port_id):
        resource = ATTACHMENT_PATH % (tenant_id, net_id, port_id)
        errstr = _("Unable to retrieve port: %s")
        resp = self.rest_action('GET', resource, errstr=errstr,
                                ignore_codes=[404])
        return None if resp[0] == 404 else resp[3]

    def rest_create_port(self, tenant_id, net_id, port):
        resource = ATTACHMENT_PATH % (tenant_id, net_id, port["id"])
        data = {"port": port}
        device_id = port.get("device_id")
        if not port["mac_address"] or not device_id:
            # controller only cares about ports attached to devices
            LOG.warning("No device MAC attached to port %s. "
                        "Skipping notification to controller.",
                        port["id"])
            return
        data["attachment"] = {"id": device_id,
                              "mac": port["mac_address"]}
        errstr = _("Unable to create remote port: %s")
        self.rest_action('PUT', resource, data, errstr)

    def rest_delete_port(self, tenant_id, network_id, port_id):
        resource = ATTACHMENT_PATH % (tenant_id, network_id, port_id)
        errstr = _("Unable to delete remote port: %s")
        self.rest_action('DELETE', resource, errstr=errstr)

    def rest_update_port(self, tenant_id, net_id, port):
        # Controller has no update operation for the port endpoint
        # the create PUT method will replace
        self.rest_create_port(tenant_id, net_id, port)

    def rest_create_floatingip(self, tenant_id, floatingip):
        resource = FLOATINGIPS_PATH % (tenant_id, floatingip['id'])
        errstr = _("Unable to create floating IP: %s")
        self._ensure_tenant_cache(tenant_id)
        self.rest_action('PUT', resource, floatingip, errstr=errstr)

    def rest_update_floatingip(self, tenant_id, floatingip, oldid):
        resource = FLOATINGIPS_PATH % (tenant_id, oldid)
        errstr = _("Unable to update floating IP: %s")
        self.rest_action('PUT', resource, floatingip, errstr=errstr)

    def rest_delete_floatingip(self, tenant_id, oldid):
        resource = FLOATINGIPS_PATH % (tenant_id, oldid)
        errstr = _("Unable to delete floating IP: %s")
        self.rest_action('DELETE', resource, errstr=errstr)

    def rest_get_switch(self, switch_id):
        resource = SWITCHES_PATH % switch_id
        errstr = _("Unable to retrieve switch: %s")
        resp = self.rest_action('GET', resource, errstr=errstr,
                                ignore_codes=[404])
        # return None if switch not found, else return switch info
        return None if resp[0] == 404 else resp[3]

    def rest_get_testpath(self, src, dst):
        resource = TESTPATH_PATH % {'src-tenant': src['tenant'],
                                    'src-segment': src['segment'],
                                    'src-ip': src['ip'],
                                    'dst-ip': dst['ip']}
        errstr = _("Unable to retrieve results for testpath ID: %s")
        resp = self.rest_action('GET', resource, errstr=errstr,
                                ignore_codes=[404])
        # return None if testpath not found, else return testpath info
        return None if (resp[0] not in range(200, 300)) else resp[3]

    def rest_create_tenantpolicy(self, tenant_id, policy):
        policy['ipproto'] = policy['protocol']
        resource = TENANTPOLICY_RESOURCE_PATH % tenant_id
        data = {"policy": policy}
        errstr = _("Unable to create policy: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_update_tenantpolicy(self, tenant_id, policy):
        policy['ipproto'] = policy['protocol']
        resource = TENANTPOLICIES_PATH % (tenant_id, policy['priority'])
        data = {"policy": policy}
        errstr = _("Unable to update policy: %s")
        self.rest_action('PUT', resource, data, errstr)

    def rest_delete_tenantpolicy(self, tenant_id, policy_prio):
        resource = TENANTPOLICIES_PATH % (tenant_id, policy_prio)
        errstr = _("Unable to delete remote policy: %s")
        self.rest_action('DELETE', resource, errstr=errstr)

    def _consistency_watchdog(self, polling_interval=60):
        if 'consistency' not in self.get_capabilities():
            LOG.warning("Backend server(s) do not support automated "
                        "consistency checks.")
            return
        if not polling_interval:
            LOG.warning("Consistency watchdog disabled by polling "
                        "interval setting of %s.", polling_interval)
            return
        while True:
            # If consistency is supported, all we have to do is make any
            # rest call and the consistency header will be added. If it
            # doesn't match, the backend will return a synchronization error
            # that will be handled by the rest_action.
            eventlet.sleep(polling_interval)
            try:
                self.rest_action('GET', HEALTH_PATH)
            except Exception:
                LOG.exception("Encountered an error checking controller "
                              "health.")

    def force_topo_sync(self, check_ts=True):
        """Execute a topology_sync between OSP and BCF.

        Topology sync collects all data from Openstack and pushes to BCF in
        one single REST call. This is a heavy operation and is not executed
        automatically.

        Conditions when this would be called:
        (1) during ServerPool initialization
            (a) must check previous timestamp
        (2) if periodic keystone tenant_cache find a diff in tenant list
            (a) should not check previous timestamp
        (3) externally triggered by neutron force-bcf-sync command
            (a) should not check previous timestamp
        (4) a rest_call to BCF fails on both servers and failure_code is not
            part of the ignore_codes list
            (a) must check previous timestamp

        :param check_ts: boolean flag to check previous
                         timestamp < TOPO_SYNC_EXPIRED_SECS
               prev_resp: a REST response tuple from the previous failed REST
                          call if available. If we skip topo_sync, return the
                          failure as previously observed.
        :return: (sync_executed, response)
                 sync_executed - Boolean - returns True if we were able to
                                acquire a lock to perform topo_sync,
                                False otherwise
                 response - tuple of the typical HTTP response from REST call
                        (response.status, response.reason, respstr, respdata)
        """
        LOG.info(_LI('TOPO_SYNC requested with check_ts %s'), check_ts)

        if not self.get_topo_function:
            raise cfg.Error(_('Server requires synchronization, '
                              'but no topology function was defined.'))

        # get current timestamp
        curr_ts = str(time.time())
        hash_handler = cdb.HashHandler(timestamp_ms=curr_ts)

        if not hash_handler.lock(check_ts):
            LOG.info(_LI("TOPO_SYNC: lock() returned False. Skipping."))
            return False, TOPO_RESPONSE_OK

        # else, perform topo_sync
        try:
            LOG.debug("TOPO_SYNC: requested at %(request_ts)s started at "
                      "%(start_ts)s",
                      {'request_ts': cdb.convert_ts_to_datetime(curr_ts),
                       'start_ts': cdb.convert_ts_to_datetime(time.time())})
            data = self.get_topo_function(
                **self.get_topo_function_args)
            if not data:
                # when keystone sync fails, it fails silently with data = None
                # that is wrong, we need to raise an exception
                raise Exception(_("TOPO_SYNC: failed to retrieve data."))
            LOG.debug("TOPO_SYNC: data received from OSP, sending "
                      "request to BCF.")
            errstr = _("Unable to perform forced topology_sync: %s")
            return True, self.rest_action('POST', TOPOLOGY_PATH, data, errstr)
        except Exception as e:
            # if encountered an exception, set to previous timestamp
            LOG.warning(_LW("TOPO_SYNC: Exception during topology sync. "
                            "Consistency DB timestamp will not be updated."))
            hash_handler.unlock(set_prev_ts=True)
            raise e
        finally:
            hash_handler.unlock()
            diff = time.time() - float(hash_handler.lock_ts)
            LOG.info(_LI("TOPO_SYNC: took %s seconds to execute topo_sync. "
                         "consistency_db unlocked."),
                     str(diff))

    def _ensure_tenant_cache(self, tenant_id):
        if tenant_id not in self.keystone_tenants:
            self._update_tenant_cache()

    def _update_tenant_cache(self, reconcile=True, ratelimit=False):
        if ratelimit is True and self._last_keystone_sync_time is not None:
            if time.time() - self._last_keystone_sync_time <= \
                    KEYSTONE_SYNC_RATE_LIMIT:
                return

        try:
            auth = v3.Password(auth_url=self.auth_url,
                               username=self.auth_user,
                               password=self.auth_password,
                               project_name=self.auth_tenant,
                               user_domain_name=self.user_domain_name,
                               project_domain_name=self.project_domain_name)
            sess = session.Session(auth=auth)
            keystone_client = ksclient.Client(session=sess)
            tenants = keystone_client.projects.list()

            if self.is_unicode_enabled():
                new_cached_tenants = {tn.id: tn.name
                                      for tn in tenants}
            else:
                new_cached_tenants = {tn.id: Util.format_resource_name(tn.name)
                                      for tn in tenants}
            # Add SERVICE_TENANT to handle hidden network for VRRP
            new_cached_tenants[SERVICE_TENANT] = SERVICE_TENANT

            LOG.debug("New TENANTS: %s \nPrevious Tenants %s",
                      new_cached_tenants, self.keystone_tenants)
            diff = DictDiffer(new_cached_tenants, self.keystone_tenants)
            self.keystone_tenants = new_cached_tenants
            if reconcile:
                for tenant_id in diff.added():
                    LOG.debug("TENANT create: id %s name %s",
                              tenant_id, self.keystone_tenants[tenant_id])
                    self._rest_create_tenant(tenant_id)
                for tenant_id in diff.removed():
                    LOG.debug("TENANT delete: id %s", tenant_id)
                    self.rest_delete_tenant(tenant_id)
                if diff.changed():
                    LOG.debug("Tenant cache outdated. Forcing topo_sync.")
                    self.force_topo_sync(check_ts=False)
            return True
        except Exception:
            LOG.exception("Encountered an error syncing with keystone.")
            return False
        finally:
            self._last_keystone_sync_time = time.time()

    def _keystone_sync(self, polling_interval=300):
        while True:
            eventlet.sleep(polling_interval)
            self._update_tenant_cache()


class HTTPSConnectionWithValidation(httplib.HTTPSConnection):

    # If combined_cert is None, the connection will continue without
    # any certificate validation.
    combined_cert = None

    def connect(self):
        sock = socket.create_connection((self.host, self.port),
                                        self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()

        if self.combined_cert:
            self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file,
                                        cert_reqs=ssl.CERT_REQUIRED,
                                        ca_certs=self.combined_cert,
                                        ssl_version=ssl.PROTOCOL_SSLv23)
        else:
            self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file,
                                        cert_reqs=ssl.CERT_NONE,
                                        ssl_version=ssl.PROTOCOL_SSLv23)

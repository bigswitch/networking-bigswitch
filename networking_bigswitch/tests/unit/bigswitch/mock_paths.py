# Copyright 2018 Big Switch Networks, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import six

"""For storing paths used for mocking, this is used in various test files.
"""
# Keystone
KEYSTONE_CLIENT = 'keystoneclient.v3.client.Client'

# Neutron
NEUTRON_AGENT = 'neutron.agent'
OVS_BRIDGE = NEUTRON_AGENT + '.common.ovs_lib.OVSBridge'
PLUGIN_API = NEUTRON_AGENT + '.rpc.PluginApi'
CONSUMER_CREATE = NEUTRON_AGENT + '.rpc.create_consumers'

SG_RPC = NEUTRON_AGENT + '.securitygroups_rpc'

CONTEXT = 'neutron_lib.context'

NEUTRON_CFG = 'neutron.common.config'
LIB_RPC_TRANSPORT = 'neutron_lib.rpc.TRANSPORT'

# oslo_messaging
RPC_SERVER_START = ('oslo_messaging.server.MessageHandlingServer.start')

# BSN
BSN_DIR = 'networking_bigswitch.plugins.bigswitch'

# Config
PL_CONFIG = BSN_DIR + '.config'

# DB
CONSISTENCY_DB = BSN_DIR + '.db.consistency_db'

# Driver
DRIVER_MOD = 'networking_bigswitch.plugins.ml2.drivers.mech_bigswitch.driver'
DRIVER = DRIVER_MOD + '.BigSwitchMechanismDriver'


# plugin/l3_plugin path
PLUGIN_PATH = BSN_DIR + '.plugin'
L3_PLUGIN_PATH = BSN_DIR + '.l3_router_plugin'
BSN_SERVICE_PLUGIN_PATH = BSN_DIR + '.bsn_service_plugin'

NOTIFIER = PLUGIN_PATH + '.AgentNotifierApi'
SPAWN = PLUGIN_PATH + '.eventlet.GreenPool.spawn_n'
MAP_DISPLAY_NAME_OR_TENANT = (PLUGIN_PATH + '.NeutronRestProxyV2Base'
                              '._map_display_name_or_tenant')

# Agent
AGENT_MOD = BSN_DIR + '.agent.restproxy_agent'
SG_AGENT = AGENT_MOD + '.FilterDeviceIDMixin'
IVS_BRIDGE = AGENT_MOD + '.IVSBridge'
NFV_SW_BRIDGE = AGENT_MOD + '.NFVSwitchBridge'

# SERVER MANAGER
SERVER_MANAGER = BSN_DIR + '.servermanager'
SERVER_REST_CALL = SERVER_MANAGER + '.ServerProxy.rest_call'
HTTPCON = SERVER_MANAGER + '.http_client.HTTPConnection'
HTTPSCON = SERVER_MANAGER + '.http_client.HTTPSConnection'

SERVER_POOL = SERVER_MANAGER + '.ServerPool'
POOL_REST_ACTION = SERVER_POOL + '.rest_action'
POOL_REST_CALL = SERVER_POOL + '.rest_call'
BACKGROUND = SERVER_POOL + '.start_background_tasks'
POOL_TOPO_SYNC = SERVER_POOL + '.force_topo_sync'
POOL_UPDATE_TENANT_CACHE = SERVER_POOL + '._update_tenant_cache'
POOL_GET_CAPABILITIES = SERVER_POOL + '.get_capabilities'
IS_UNICODE_ENABLED = SERVER_POOL + '.is_unicode_enabled'

# SSL Cert Related
if six.PY2:
    GET_SERVER_CERTIFICATE = SERVER_MANAGER + '.ssl.get_server_certificate'
else:
    GET_SERVER_CERTIFICATE = SERVER_POOL + '.py34_get_server_certificate'
SSL_CREATE_DEFAULT_CONTEXT = SERVER_MANAGER + '.ssl.create_default_context'
CERT_COMBINER = SERVER_POOL + '._combine_certs_to_file'
FILE_PUT = SERVER_POOL + '._file_put_contents'
GET_CA_CERTS = SERVER_POOL + '._get_ca_cert_paths'

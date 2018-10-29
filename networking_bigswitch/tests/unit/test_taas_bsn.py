# Copyright 2017 Big Switch Networks, Inc.
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


import contextlib
import mock
import webob.exc

from networking_bigswitch.tests.unit.ml2.drivers \
    import test_bigswitch_mech as test_bsm

from neutron.db import servicetype_db as sdb
from neutron.services import provider_configuration as provconf
from neutron.tests.unit.api import test_extensions as test_ex

from neutron_taas.common import constants as taas_const
from neutron_taas.extensions import taas as ext_taas
from neutron_taas.tests.unit.services.taas import test_taas_plugin  # noqa

from oslo_utils import uuidutils

# Generate uuids
TENANT1 = uuidutils.generate_uuid()
TENANT2 = uuidutils.generate_uuid()

TAAS_PREFIX = '/taas'

DB_TAAS_PLUGIN_KLASS = ('neutron_taas.services.taas.taas_plugin.TaasPlugin')
BSN_TAAS_DRIVER_KLASS = ('networking_bigswitch.services.taas.service_drivers.'
                         'taas_bsn.BSNTaasDriver')


class TaasExtensionManager(object):

    def get_resources(self):
        return ext_taas.Taas.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestBSNTaasCase(test_bsm.TestBigSwitchMechDriverBase):
    resource_prefix_map = dict(
        (k, TAAS_PREFIX)
        for k in ext_taas.RESOURCE_ATTRIBUTE_MAP.keys()
    )

    def setUp(self, plugin=None, service_plugins=None, ext_mgr=None):
        ext_mgr = TaasExtensionManager()
        service_plugins = {'taas_plugin_name': DB_TAAS_PLUGIN_KLASS}
        taas_provider = (taas_const.TAAS + ':BSN:' + BSN_TAAS_DRIVER_KLASS +
                         ':default')
        mock.patch.object(provconf.NeutronModule, 'service_providers',
                          return_value=[taas_provider]).start()
        manager = sdb.ServiceTypeManager.get_instance()
        manager.add_provider_configuration(
            taas_const.TAAS, provconf.ProviderConfiguration())
        super(TestBSNTaasCase,
              self).setUp(service_plugins=service_plugins,
                          ext_mgr=ext_mgr)
        self.ext_api = test_ex.setup_extensions_middleware(ext_mgr)

    def _create_tap_service(self, port_id, name=None, tenant_id=None):
        t_s = {'tap_service': {'port_id': port_id}}
        if name:
            t_s['tap_service']['name'] = name
        if tenant_id:
            t_s['tap_service']['tenant_id'] = tenant_id

        ts_req = self.new_create_request('tap_services', t_s, self.fmt)
        return ts_req.get_response(self.ext_api)

    def _create_tap_flow(self, tap_service_id, source_port, direction,
                         name=None, tenant_id=None):
        t_f = {'tap_flow': {'tap_service_id': tap_service_id,
                            'source_port': source_port,
                            'direction': direction}}
        if name:
            t_f['tap_flow']['name'] = name
        if tenant_id:
            t_f['tap_flow']['tenant_id'] = tenant_id

        tf_req = self.new_create_request('tap_flows', t_f, self.fmt)
        return tf_req.get_response(self.ext_api)

    def _make_tap_service(self, port_id, name=None, tenant_id=None):
        res = self._create_tap_service(port_id, name, tenant_id)
        if res.status_int >= webob.exc.HTTPBadRequest.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(self.fmt, res)

    def _make_tap_flow(self, tap_service_id, source_port, direction,
                       name=None, tenant_id=None):
        res = self._create_tap_flow(tap_service_id,
                                    source_port,
                                    direction,
                                    name, tenant_id)
        if res.status_int >= webob.exc.HTTPBadRequest.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(self.fmt, res)

    @contextlib.contextmanager
    def tap_service(self, port_id, name='tap_service1', tenant_id=TENANT1):
        ts = self._make_tap_service(port_id, name, tenant_id)
        yield ts

    @contextlib.contextmanager
    def tap_flow(self, tap_service_id, source_port,
                 direction='BOTH', name='tap_flow1', tenant_id=TENANT1):
        tf = self._make_tap_flow(tap_service_id, source_port,
                                 direction, name, tenant_id)
        yield tf

    @contextlib.contextmanager
    def create_tap_service_and_tap_flow(self):
        with self.port(tenant_id=TENANT1) as port1, \
                self.port(tenant_id=TENANT1) as port2:
            dist_port = port1['port']
            source_port = port2['port']
            with self.tap_service(port_id=dist_port['id']) as t_s:
                ts = t_s['tap_service']
                with self.tap_flow(tap_service_id=ts['id'],
                                   source_port=source_port['id']) as t_f:
                    tf = t_f['tap_flow']
                    self.assertEqual(source_port['id'], tf['source_port'])
                    yield tf

    def test_create_tap_service(self):
        with self.port(tenant_id=TENANT1) as port:
            dist_port = port['port']
            with self.tap_service(port_id=dist_port['id']) as t_s:
                ts = t_s['tap_service']
                self.assertEqual(dist_port['id'], ts['port_id'])
        # TODO(Joe): verify the correct BSN backend call is made

    def test_delete_tap_service(self):
        with self.port(tenant_id=TENANT1) as port:
            dist_port = port['port']
            with self.tap_service(port_id=dist_port['id']) as t_s:
                ts = t_s['tap_service']
                req = self.new_delete_request('tap_services', ts['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPNoContent.code,
                                 res.status_int)
        # TODO(Joe): verify the correct BSN backend call is made

    def test_create_tap_flow(self):
        with self.create_tap_service_and_tap_flow():
            pass
        # TODO(Joe): verify the correct BSN backend call is made

    def test_delete_tap_flow(self):
        with self.create_tap_service_and_tap_flow() as tf:
            req = self.new_delete_request('tap_flows', tf['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)
        # TODO(Joe): verify the correct BSN backend call is made

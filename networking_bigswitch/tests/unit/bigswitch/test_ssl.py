# Copyright 2014 Big Switch Networks, Inc.  All rights reserved.
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
import os

import mock
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from oslo_config import cfg
from oslo_log import log as logging

from networking_bigswitch.tests.unit.bigswitch \
    import test_base as bsn_test_base

from networking_bigswitch.tests.unit.bigswitch.mock_paths import CERT_COMBINER
from networking_bigswitch.tests.unit.bigswitch.mock_paths import FILE_PUT
from networking_bigswitch.tests.unit.bigswitch.mock_paths import GET_CA_CERTS
from networking_bigswitch.tests.unit.bigswitch.mock_paths import \
    GET_SERVER_CERTIFICATE
from networking_bigswitch.tests.unit.bigswitch.mock_paths import HTTPSCON
from networking_bigswitch.tests.unit.bigswitch.mock_paths import \
    SSL_CREATE_DEFAULT_CONTEXT

LOG = logging.getLogger(__name__)


class test_ssl_certificate_base(test_plugin.NeutronDbPluginV2TestCase,
                                bsn_test_base.BigSwitchTestBase):

    plugin_str = ('%s.NeutronRestProxyV2' %
                  bsn_test_base.PLUGIN_PATH)
    servername = None
    cert_base = None

    def _setUp(self):
        self.servername = test_base._uuid()
        self.cert_base = cfg.CONF.RESTPROXY.ssl_cert_directory
        self.host_cert_val = 'DUMMYCERTFORHOST%s' % self.servername
        self.host_cert_path = os.path.join(
            self.cert_base,
            'host_certs',
            '%s.pem' % self.servername
        )
        self.comb_cert_path = os.path.join(
            self.cert_base,
            'combined',
            '%s.pem' % self.servername
        )
        self.ca_certs_path = os.path.join(
            self.cert_base,
            'ca_certs'
        )
        cfg.CONF.set_override('servers', ["%s:443" % self.servername],
                              'RESTPROXY')
        self.setup_patches()

        # Mock method SSL lib uses to grab cert from server
        self.sslgetcert_m = mock.patch(GET_SERVER_CERTIFICATE,
                                       create=True).start()
        self.sslgetcert_m.return_value = self.host_cert_val

        # Mock methods that write and read certs from the file-system
        self.fileput_m = mock.patch(FILE_PUT, create=True).start()
        self.certcomb_m = mock.patch(CERT_COMBINER, create=True).start()
        self.getcacerts_m = mock.patch(GET_CA_CERTS, create=True).start()

    def setUp(self):
        test_plugin.NeutronDbPluginV2TestCase.setUp(self, self.plugin_str)
        self.setup_db()


class TestSslSticky(test_ssl_certificate_base):

    def setUp(self):
        self.setup_config_files()
        cfg.CONF.set_override('server_ssl', True, 'RESTPROXY')
        cfg.CONF.set_override('ssl_sticky', True, 'RESTPROXY')
        self._setUp()
        # # Set fake HTTPS connection's expectation
        # self.fake_certget_m.return_value = self.host_cert_val
        # No CA certs for this test
        self.getcacerts_m.return_value = []

        self.ssl_create_default_context_m = mock.patch(
            SSL_CREATE_DEFAULT_CONTEXT,
            create=True).start()
        super(TestSslSticky, self).setUp()

    def test_sticky_cert(self):
        """Test certificate is stored, and https connection is used

        :return:
        """
        # SSL connection should be successful and cert should be cached
        with mock.patch(HTTPSCON) as https_mock, self.network():
            # CA certs should have been checked for
            self.getcacerts_m.assert_has_calls([mock.call(self.ca_certs_path)])
            # cert should have been fetched via SSL lib
            self.sslgetcert_m.assert_has_calls(
                [mock.call((self.servername, 443))]
            )

            # cert should have been recorded
            self.fileput_m.assert_has_calls([mock.call(self.host_cert_path,
                                                       self.host_cert_val)])

            # no ca certs, so host cert only for this combined cert
            self.certcomb_m.assert_has_calls([mock.call([self.host_cert_path],
                                                        self.comb_cert_path)])

            # confirm that ssl_context is created
            self.ssl_create_default_context_m.assert_called_once()

            # Test HTTPS Connection is used for REST Calls
            https_mock.assert_called_once()

            # confirm that ssl_context is passed
            self.assertTrue(https_mock.
                            call_args_list[0][1].get('context'))

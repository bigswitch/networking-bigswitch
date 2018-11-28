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
import httplib
import socket
import ssl
import time

import mock
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_utils import importutils

from networking_bigswitch.plugins.bigswitch.db import consistency_db
from networking_bigswitch.plugins.bigswitch import servermanager
from networking_bigswitch.tests.unit.bigswitch \
    import test_restproxy_plugin as test_rp
from neutron_lib.plugins import directory

SERVERMANAGER = 'networking_bigswitch.plugins.bigswitch.servermanager'
CONSISTENCYDB = 'networking_bigswitch.plugins.bigswitch.db.consistency_db'
HTTPCON = SERVERMANAGER + '.httplib.HTTPConnection'
HTTPSCON = SERVERMANAGER + '.HTTPSConnectionWithValidation'
SERVER_GET_CAPABILITIES = SERVERMANAGER + '.ServerPool.get_capabilities'


class ServerManagerTests(test_rp.BigSwitchProxyPluginV2TestCase):

    def setUp(self):
        self.socket_mock = mock.patch(
            SERVERMANAGER + '.socket.create_connection').start()
        self.wrap_mock = mock.patch(SERVERMANAGER + '.ssl.wrap_socket').start()
        super(ServerManagerTests, self).setUp()
        # http patch must not be running or it will mangle the servermanager
        # import where the https connection classes are defined
        self.httpPatch.stop()
        self.sm = importutils.import_module(SERVERMANAGER)

    def test_no_servers(self):
        cfg.CONF.set_override('servers', [], 'RESTPROXY')
        self.assertRaises(cfg.Error, servermanager.ServerPool)

    def test_malformed_servers(self):
        cfg.CONF.set_override('servers', ['1.2.3.4', '1.1.1.1:a'], 'RESTPROXY')
        self.assertRaises(cfg.Error, servermanager.ServerPool)

    def test_ipv6_server_address(self):
        cfg.CONF.set_override(
            'servers', ['[ABCD:EF01:2345:6789:ABCD:EF01:2345:6789]:80'],
            'RESTPROXY')
        s = servermanager.ServerPool()
        self.assertEqual(s.servers[0].server,
                         'ABCD:EF01:2345:6789:ABCD:EF01:2345:6789')

    def test_sticky_cert_fetch_fail(self):
        pl = directory.get_plugin()
        pl.servers.ssl = True
        with mock.patch(
            'ssl.get_server_certificate',
            side_effect=Exception('There is no more entropy in the universe')
        ) as sslgetmock:
            self.assertRaises(
                cfg.Error,
                pl.servers._get_combined_cert_for_server,
                *('example.org', 443)
            )
            sslgetmock.assert_has_calls([mock.call(
                ('example.org', 443), ssl_version=ssl.PROTOCOL_SSLv23)])

    def test_consistency_watchdog_stops_with_0_polling_interval(self):
        pl = directory.get_plugin()
        pl.servers.capabilities = ['consistency']
        self.watch_p.stop()
        with mock.patch('eventlet.sleep') as smock:
            # should return immediately a polling interval of 0
            pl.servers._consistency_watchdog(0)
            self.assertFalse(smock.called)

    def test_consistency_watchdog(self):
        pl = directory.get_plugin()
        pl.servers.capabilities = ['dummy']
        self.watch_p.stop()

        with mock.patch('eventlet.sleep') as smock,\
                mock.patch(
                    SERVERMANAGER + '.ServerPool.rest_call',
                    side_effect=servermanager.RemoteRestError(
                        reason='Failure to trigger except clause.'))\
                as rmock,\
                mock.patch(
                    SERVERMANAGER + '.LOG.exception',
                    side_effect=KeyError('Failure to break loop'))\
                as lmock:
            # should return immediately without consistency capability
            pl.servers._consistency_watchdog()
            self.assertFalse(smock.called)

            pl.servers.capabilities = ['consistency']
            self.assertRaises(KeyError,
                              pl.servers._consistency_watchdog)
            rmock.assert_called_with('GET', '/health', '', {}, [], False)
            self.assertEqual(1, len(lmock.mock_calls))

    def test_file_put_contents(self):
        pl = directory.get_plugin()
        with mock.patch(SERVERMANAGER + '.open', create=True) as omock:
            pl.servers._file_put_contents('somepath', 'contents')
            omock.assert_has_calls([mock.call('somepath', 'w')])
            omock.return_value.__enter__.return_value.assert_has_calls([
                mock.call.write('contents')
            ])

    def test_combine_certs_to_file(self):
        pl = directory.get_plugin()
        with mock.patch(SERVERMANAGER + '.open', create=True) as omock:
            omock.return_value.__enter__().read.return_value = 'certdata'
            pl.servers._combine_certs_to_file(['cert1.pem', 'cert2.pem'],
                                              'combined.pem')
            # mock shared between read and write file handles so the calls
            # are mixed together
            omock.assert_has_calls([
                mock.call('combined.pem', 'w'),
                mock.call('cert1.pem', 'r'),
                mock.call('cert2.pem', 'r'),
            ], any_order=True)
            omock.return_value.__enter__.return_value.assert_has_calls([
                mock.call.read(),
                mock.call.write('certdata'),
                mock.call.read(),
                mock.call.write('certdata')
            ])

    # basic authentication
    def test_auth_header(self):
        cfg.CONF.set_override('server_auth', 'username:pass', 'RESTPROXY')
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value
            rv.getresponse.return_value.getheader.return_value = 'HASHHEADER'
            sp.rest_create_network('tenant', 'network')
        callheaders = rv.request.mock_calls[0][1][3]
        self.assertIn('Authorization', callheaders)
        self.assertNotIn('Cookie', callheaders)
        self.assertEqual(callheaders['Authorization'],
                         'Basic dXNlcm5hbWU6cGFzcw==')

    # token based authentication
    def test_auth_token_header(self):
        cfg.CONF.set_override('server_auth', 'fake_token', 'RESTPROXY')
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value
            rv.getresponse.return_value.getheader.return_value = 'HASHHEADER'
            sp.rest_create_network('tenant', 'network')
        callheaders = rv.request.mock_calls[0][1][3]
        self.assertIn('Cookie', callheaders)
        self.assertNotIn('Authorization', callheaders)
        self.assertEqual(callheaders['Cookie'], 'session_cookie="fake_token"')

    def test_header_add(self):
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value
            rv.getresponse.return_value.getheader.return_value = 'HASHHEADER'
            sp.servers[0].rest_call('GET', '/', headers={'EXTRA-HEADER': 'HI'})
        callheaders = rv.request.mock_calls[0][1][3]
        # verify normal headers weren't mangled
        self.assertIn('Content-type', callheaders)
        self.assertEqual(callheaders['Content-type'],
                         'application/json')
        # verify new header made it in
        self.assertIn('EXTRA-HEADER', callheaders)
        self.assertEqual(callheaders['EXTRA-HEADER'], 'HI')

    def test_capabilities_retrieval(self):
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value.getresponse.return_value
            rv.getheader.return_value = 'HASHHEADER'

            # each server will get different capabilities
            rv.read.side_effect = ['["a","b","c"]', '["b","c","d"]']
            # pool capabilities is union of both
            # normally capabilities should be the same across all servers
            # this only happens in two situations:
            # 1. a server is down
            # 2. during upgrade/downgrade
            self.assertEqual(set(['a', 'b', 'c', 'd']), sp.get_capabilities())
            self.assertEqual(2, rv.read.call_count)

            # the pool should cache after the first call
            # so no more HTTP calls should be made
            rv.read.side_effect = ['["w","x","y"]', '["x","y","z"]']
            self.assertEqual(set(['a', 'b', 'c', 'd']), sp.get_capabilities())
            self.assertEqual(2, rv.read.call_count)

    def test_capabilities_retrieval_failure(self):
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value.getresponse.return_value
            rv.getheader.return_value = 'HASHHEADER'
            # a failure to parse should result in an empty capability set
            rv.read.return_value = 'XXXXX'
            self.assertEqual([], sp.servers[0].get_capabilities())

            # as capabilities is empty, it should try to update capabilities
            rv.read.side_effect = ['{"a": "b"}', '["b","c","d"]']
            self.assertEqual(set(['a', 'b', 'c', 'd']), sp.get_capabilities())

    def test_reconnect_on_timeout_change(self):
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value
            rv.getresponse.return_value.getheader.return_value = 'HASHHEADER'
            sp.servers[0].capabilities = ['keep-alive']
            sp.servers[0].rest_call('GET', '/', timeout=10)
            # even with keep-alive enabled, a change in timeout will trigger
            # a reconnect
            sp.servers[0].rest_call('GET', '/', timeout=75)
        conmock.assert_has_calls([
            mock.call('localhost', 9000, timeout=10),
            mock.call('localhost', 9000, timeout=75),
        ], any_order=True)

    def test_connect_failures(self):
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON, return_value=None):
            resp = sp.servers[0].rest_call('GET', '/')
            self.assertEqual(resp, (0, None, None, None))
        # verify same behavior on ssl class
        sp.servers[0].currentcon = False
        sp.servers[0].ssl = True
        with mock.patch(HTTPSCON, return_value=None):
            resp = sp.servers[0].rest_call('GET', '/')
            self.assertEqual(resp, (0, None, None, None))

    def test_reconnect_cached_connection(self):
        self.skipTest("cached connections are currently disabled because "
                      "their assignment to the servermanager object is not "
                      "thread-safe")
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value
            rv.getresponse.return_value.getheader.return_value = 'HASH'
            sp.servers[0].capabilities = ['keep-alive']
            sp.servers[0].rest_call('GET', '/first')
            # raise an error on re-use to verify reconnect
            # return okay the second time so the reconnect works
            rv.request.side_effect = [httplib.ImproperConnectionState(),
                                      mock.MagicMock()]
            sp.servers[0].rest_call('GET', '/second')
        uris = [c[1][1] for c in rv.request.mock_calls]
        expected = [
            sp.base_uri + '/first',
            sp.base_uri + '/second',
            sp.base_uri + '/second',
        ]
        self.assertEqual(uris, expected)

    def test_no_reconnect_recurse_to_infinity(self):
        self.skipTest("cached connections are currently disabled because "
                      "their assignment to the servermanager object is not "
                      "thread-safe")
        # retry uses recursion when a reconnect is necessary
        # this test makes sure it stops after 1 recursive call
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            rv = conmock.return_value
            # hash header must be string instead of mock object
            rv.getresponse.return_value.getheader.return_value = 'HASH'
            sp.servers[0].capabilities = ['keep-alive']
            sp.servers[0].rest_call('GET', '/first')
            # after retrying once, the rest call should raise the
            # exception up
            rv.request.side_effect = httplib.ImproperConnectionState()
            self.assertRaises(httplib.ImproperConnectionState,
                              sp.servers[0].rest_call,
                              *('GET', '/second'))
            # 1 for the first call, 2 for the second with retry
            self.assertEqual(rv.request.call_count, 3)

    def test_socket_error(self):
        sp = servermanager.ServerPool()
        with mock.patch(HTTPCON) as conmock:
            conmock.return_value.request.side_effect = socket.timeout()
            resp = sp.servers[0].rest_call('GET', '/')
            self.assertEqual(resp, (0, None, None, None))

    def test_cert_get_fail(self):
        pl = directory.get_plugin()
        pl.servers.ssl = True
        with mock.patch('os.path.exists', return_value=False):
            self.assertRaises(cfg.Error,
                              pl.servers._get_combined_cert_for_server,
                              *('example.org', 443))

    def test_cert_make_dirs(self):
        pl = directory.get_plugin()
        pl.servers.ssl = True
        cfg.CONF.set_override('ssl_sticky', False, 'RESTPROXY')
        # pretend base dir exists, 3 children don't, and host cert does
        with mock.patch('os.path.exists', side_effect=[True, False, False,
                                                       False, True]) as exmock,\
                mock.patch('os.makedirs') as makemock,\
                mock.patch(
                    SERVERMANAGER + '.ServerPool._combine_certs_to_file')\
                as combmock:
            # will raise error because no certs found
            self.assertIn(
                'example.org',
                pl.servers._get_combined_cert_for_server('example.org', 443)
            )
            base = cfg.CONF.RESTPROXY.ssl_cert_directory
            hpath = base + '/host_certs/example.org.pem'
            combpath = base + '/combined/example.org.pem'
            combmock.assert_has_calls([mock.call([hpath], combpath)])
            self.assertEqual(exmock.call_count, 5)
            self.assertEqual(makemock.call_count, 3)

    def test_no_cert_error(self):
        pl = directory.get_plugin()
        pl.servers.ssl = True
        cfg.CONF.set_override('ssl_sticky', False, 'RESTPROXY')
        # pretend base dir exists and 3 children do, but host cert doesn't
        with mock.patch(
            'os.path.exists',
            side_effect=[True, True, True, True, False]
        ) as exmock:
            # will raise error because no certs found
            self.assertRaises(
                cfg.Error,
                pl.servers._get_combined_cert_for_server,
                *('example.org', 443)
            )
            self.assertEqual(exmock.call_count, 5)

    def test_action_success(self):
        pl = directory.get_plugin()
        self.assertTrue(pl.servers.action_success((200,)))

    def test_server_failure(self):
        pl = directory.get_plugin()
        self.assertTrue(pl.servers.server_failure((404,)))
        # server failure has an ignore codes option
        self.assertFalse(pl.servers.server_failure((404,),
                                                   ignore_codes=[404]))

    def test_retry_on_unavailable(self):
        pl = directory.get_plugin()
        with mock.patch(SERVERMANAGER + '.ServerProxy.rest_call',
                        return_value=(httplib.SERVICE_UNAVAILABLE,
                                      0, 0, 0)) as srestmock,\
                mock.patch(SERVERMANAGER + '.eventlet.sleep') as tmock:
            # making a call should trigger retries with sleeps in between
            pl.servers.rest_call('GET', '/', '', None, [])
            rest_call = [mock.call('GET', '/', '', None, False,
                                   reconnect=True)]
            rest_call_count = (
                servermanager.HTTP_SERVICE_UNAVAILABLE_RETRY_COUNT + 1)
            srestmock.assert_has_calls(rest_call * rest_call_count)
            sleep_call = [mock.call(
                servermanager.HTTP_SERVICE_UNAVAILABLE_RETRY_INTERVAL)]
            # should sleep 1 less time than the number of calls
            sleep_call_count = rest_call_count - 1
            tmock.assert_has_calls(sleep_call * sleep_call_count)

    def test_delete_failure_forces_topo_sync(self):
        pl = directory.get_plugin()
        with mock.patch(SERVERMANAGER + '.ServerProxy.rest_call',
                        return_value=(httplib.INTERNAL_SERVER_ERROR,
                                      0, 0, 0)), \
                mock.patch(SERVERMANAGER + '.ServerPool.force_topo_sync',
                           return_value=(False,
                                         servermanager.TOPO_RESPONSE_OK)) \
                as topo_mock:
            # a failed DELETE call should trigger a forced topo_sync
            # with check_ts True
            self.assertRaises(servermanager.RemoteRestError,
                              pl.servers.rest_action,
                              **{'action': 'DELETE', 'resource': '/',
                                 'data': '',
                                 'errstr': "Unable to DELETE query to BCF: %s",
                                 'ignore_codes': []})
            topo_mock.assert_called_once_with(**{'check_ts': True})

    def test_post_failure_forces_topo_sync(self):
        pl = directory.get_plugin()
        with mock.patch(SERVERMANAGER + '.ServerProxy.rest_call',
                        return_value=(httplib.INTERNAL_SERVER_ERROR,
                                      0, 0, 0)), \
                mock.patch(SERVERMANAGER + '.ServerPool.force_topo_sync',
                           return_value=(False,
                                         servermanager.TOPO_RESPONSE_OK)) \
                as topo_mock:
            # a failed POST call should trigger a forced topo_sync
            # with check_ts True
            self.assertRaises(servermanager.RemoteRestError,
                              pl.servers.rest_action,
                              **{'action': 'POST', 'resource': '/', 'data': '',
                                 'errstr': "Unable to POST query to BCF: %s",
                                 'ignore_codes': []})
            topo_mock.assert_called_once_with(**{'check_ts': True})

    def test_topo_sync_failure_does_not_force_topo_sync(self):
        pl = directory.get_plugin()
        with mock.patch(SERVERMANAGER + '.ServerProxy.rest_call',
                        return_value=(httplib.INTERNAL_SERVER_ERROR,
                                      0, 0, 0)), \
                mock.patch(SERVERMANAGER + '.ServerPool.force_topo_sync',
                           return_value=(False,
                                         servermanager.TOPO_RESPONSE_OK)) \
                as topo_mock:
            # a failed POST call for topology path should raise an exception
            # and not call force_topo_sync like other failed rest_action
            self.assertRaises(servermanager.RemoteRestError,
                              pl.servers.rest_action,
                              **{'action': 'POST', 'resource': '/topology',
                                 'data': '',
                                 'errstr': "Unable to perform topo_sync: %s",
                                 'ignore_codes': []})
            topo_mock.assert_not_called()

    def test_not_found_sync_raises_error_without_topology(self):
        pl = directory.get_plugin()
        pl.servers.get_topo_function = None
        with \
            mock.patch(
                SERVERMANAGER + '.ServerProxy.rest_call',
                return_value=(httplib.NOT_FOUND, 0, 0, 0)):
            # making a call should trigger a conflict sync that will
            # error without the topology function set
            self.assertRaises(
                cfg.Error,
                pl.servers.rest_action,
                *('GET', '/', '', None, [])
            )

    def test_no_sync_without_keystone(self):
        pl = directory.get_plugin()
        with\
            mock.patch(SERVERMANAGER + '.ServerPool._update_tenant_cache',
                       return_value=(False)),\
            mock.patch(SERVERMANAGER + '.ServerProxy.rest_call',
                       return_value=(httplib.CONFLICT, 0, 0, 0)) as srestmock:
            # making a call should trigger a conflict sync
            pl.servers.rest_call('GET', '/', '', None, [])
            srestmock.assert_called_once_with(
                'GET', '/', '', None, False, reconnect=True)

    def test_no_send_all_data_without_keystone(self):
        pl = directory.get_plugin()
        with mock.patch(SERVERMANAGER + '.ServerPool._update_tenant_cache',
                        return_value=(False)), \
            mock.patch(SERVERMANAGER + '.ServerPool.force_topo_sync',
                       return_value=(False, servermanager.TOPO_RESPONSE_OK)) \
                as tmock:
            # making a call should trigger a conflict sync
            self.assertRaises(Exception, pl._send_all_data())  # noqa
            tmock.assert_called_once()

    def test_floating_calls(self):
        pl = directory.get_plugin()
        with mock.patch(SERVERMANAGER + '.ServerPool.rest_action') as ramock:
            body1 = {'id': 'somefloat'}
            body2 = {'name': 'myfl'}
            pl.servers.rest_create_floatingip('tenant', body1)
            pl.servers.rest_update_floatingip('tenant', body2, 'id')
            pl.servers.rest_delete_floatingip('tenant', 'oldid')
            ramock.assert_has_calls([
                mock.call('PUT', '/tenants/tenant/floatingips/somefloat',
                          body1,
                          errstr=u'Unable to create floating IP: %s'),
                mock.call('PUT', '/tenants/tenant/floatingips/id',
                          body2,
                          errstr=u'Unable to update floating IP: %s'),
                mock.call('DELETE', '/tenants/tenant/floatingips/oldid',
                          errstr=u'Unable to delete floating IP: %s')
            ])

    def test_HTTPSConnectionWithValidation_without_cert(self):
        con = self.sm.HTTPSConnectionWithValidation(
            'www.example.org', 443, timeout=90)
        con.source_address = '127.0.0.1'
        con.request("GET", "/")
        self.socket_mock.assert_has_calls([mock.call(
            ('www.example.org', 443), 90, '127.0.0.1'
        )])
        self.wrap_mock.assert_has_calls([mock.call(
            self.socket_mock(), None, None, cert_reqs=ssl.CERT_NONE,
            ssl_version=ssl.PROTOCOL_SSLv23
        )])
        self.assertEqual(con.sock, self.wrap_mock())

    def test_HTTPSConnectionWithValidation_with_cert(self):
        con = self.sm.HTTPSConnectionWithValidation(
            'www.example.org', 443, timeout=90)
        con.combined_cert = 'SOMECERTS.pem'
        con.source_address = '127.0.0.1'
        con.request("GET", "/")
        self.socket_mock.assert_has_calls([mock.call(
            ('www.example.org', 443), 90, '127.0.0.1'
        )])
        self.wrap_mock.assert_has_calls([mock.call(
            self.socket_mock(), None, None, ca_certs='SOMECERTS.pem',
            cert_reqs=ssl.CERT_REQUIRED,
            ssl_version=ssl.PROTOCOL_SSLv23
        )])
        self.assertEqual(con.sock, self.wrap_mock())

    def test_HTTPSConnectionWithValidation_tunnel(self):
        tunnel_mock = mock.patch.object(
            self.sm.HTTPSConnectionWithValidation,
            '_tunnel').start()
        con = self.sm.HTTPSConnectionWithValidation(
            'www.example.org', 443, timeout=90)
        con.source_address = '127.0.0.1'
        con.set_tunnel('myproxy.local', 3128)
        con.request("GET", "/")
        self.socket_mock.assert_has_calls([mock.call(
            ('www.example.org', 443), 90, '127.0.0.1'
        )])
        self.wrap_mock.assert_has_calls([mock.call(
            self.socket_mock(), None, None, cert_reqs=ssl.CERT_NONE,
            ssl_version=ssl.PROTOCOL_SSLv23
        )])
        # _tunnel() doesn't take any args
        tunnel_mock.assert_has_calls([mock.call()])
        self.assertEqual(con._tunnel_host, 'myproxy.local')
        self.assertEqual(con._tunnel_port, 3128)
        self.assertEqual(con.sock, self.wrap_mock())

    def test_is_unicode_enabled(self):
        """Verify that unicode is enabled only when both conditions are True:

         1. naming_scheme_unicode is True or empty
         2. BCF capabilities include display-name

        :return:
        """
        self.is_unicode_enabled_p.stop()

        def capability_unicode_supported():
            return ['dummy', 'display-name']

        def capability_unicode_unsupported():
            return ['dummy']

        patch_supported = mock.patch(
            SERVER_GET_CAPABILITIES,
            side_effect=capability_unicode_supported)

        patch_unsupported = mock.patch(
            SERVER_GET_CAPABILITIES,
            side_effect=capability_unicode_unsupported)

        # Create a server pool with default naming_scheme_unicode
        # verify default value is true
        sp = servermanager.ServerPool()
        self.assertTrue(cfg.CONF.RESTPROXY.naming_scheme_unicode)

        # config enabled, and unicode is supported on bcf
        patch_supported.start()
        self.assertTrue(sp.is_unicode_enabled())
        patch_supported.stop()

        # config enabled, but unicode is not supported on bcf
        patch_unsupported.start()
        self.assertFalse(sp.is_unicode_enabled())
        patch_unsupported.stop()

        # Recreate the server pool, as the config is read during initialization
        cfg.CONF.set_override('naming_scheme_unicode', False, 'RESTPROXY')
        sp = servermanager.ServerPool()

        # config disabled, though unicode is supported on bcf
        patch_supported.start()
        self.assertFalse(sp.is_unicode_enabled())
        patch_supported.stop()

        # config disabled, and unicode is not supported on bcf
        patch_unsupported.start()
        self.assertFalse(sp.is_unicode_enabled())
        patch_unsupported.stop()


class TestSockets(test_rp.BigSwitchProxyPluginV2TestCase):

    def setUp(self):
        super(TestSockets, self).setUp()
        # http patch must not be running or it will mangle the servermanager
        # import where the https connection classes are defined
        self.httpPatch.stop()
        self.sm = importutils.import_module(SERVERMANAGER)

    def test_socket_create_attempt(self):
        # exercise the socket creation to make sure it works on both python
        # versions
        con = self.sm.HTTPSConnectionWithValidation('127.0.0.1', 0, timeout=1)
        # if httpcon was created, a connect attempt should raise a socket error
        self.assertRaises(socket.error, con.connect)


class HashLockingTests(test_rp.BigSwitchProxyPluginV2TestCase):

    def _get_hash_from_handler_db(self, handler):
        with handler.session.begin(subtransactions=True):
            res = (handler.session.query(consistency_db.ConsistencyHash).
                   filter_by(hash_id=handler.hash_id).first())
            return res.hash

    def test_lock_no_initial_record(self):
        handler = consistency_db.HashHandler()
        h1 = handler.lock()
        # lock() request on empty DB should succeed
        self.assertTrue(h1)
        # db should have a lock marker
        self.assertEqual(handler.lock_marker,
                         self._get_hash_from_handler_db(handler))
        # prev_lock_ts must be 0 for initial case
        self.assertEqual(handler.prev_lock_ts, '0')
        # unlock() should clear the lock
        handler.unlock()
        self.assertEqual(handler.lock_ts,
                         self._get_hash_from_handler_db(handler))

    def test_db_duplicate_on_insert(self):
        handler = consistency_db.HashHandler()
        with mock.patch.object(
            handler.session, 'add', side_effect=[db_exc.DBDuplicateEntry, '']
        ) as add_mock:
            handler.lock()
            # duplicate insert failure should result in retry
            self.assertEqual(2, add_mock.call_count)

    def test_lock_check_ts_true_prev_lock_exists(self):
        handler1 = consistency_db.HashHandler()
        h1 = handler1.lock()
        self.assertTrue(h1)
        self.assertEqual(handler1.lock_marker,
                         self._get_hash_from_handler_db(handler1))

        # 2nd thread came in just 10 millisecs after first one, and first one
        # still holds the lock, expired  = False
        timestamp_2 = float(handler1.lock_ts) + 10
        handler2 = consistency_db.HashHandler(timestamp_ms=timestamp_2)
        h2 = handler2.lock()
        self.assertFalse(h2)
        self.assertEqual(handler1.lock_ts, handler2.prev_lock_ts)

    def test_lock_check_ts_false_prev_lock_exists(self):
        handler1 = consistency_db.HashHandler()
        h1 = handler1.lock()
        self.assertTrue(h1)
        self.assertEqual(handler1.lock_marker,
                         self._get_hash_from_handler_db(handler1))
        self.assertEqual('0', handler1.prev_lock_ts)

        hh2_ts_hh1_ts_plus_1780 = float(handler1.lock_ts) + 1780
        handler2 = consistency_db.HashHandler(
            hash_id='1', timestamp_ms=hh2_ts_hh1_ts_plus_1780)
        with mock.patch(CONSISTENCYDB + '.eventlet.sleep',
                        side_effect=[Exception]) as emock:
            try:
                handler2.lock(check_ts=False)
            except Exception:
                pass
        self.assertEqual(1, emock.call_count)
        self.assertEqual(handler1.lock_ts, handler2.prev_lock_ts)

    def test_lock_check_ts_true_prev_lock_not_expired(self):
        handler1 = consistency_db.HashHandler()
        h1 = handler1.lock()
        self.assertTrue(h1)
        self.assertEqual(handler1.lock_marker,
                         self._get_hash_from_handler_db(handler1))

        handler1.unlock()
        self.assertEqual(handler1.lock_ts,
                         self._get_hash_from_handler_db(handler1))

        # thread 1 has executed the complete lock-unlock cycle
        # thread 2 now tries to get lock with check_ts True
        # TOPO_SYNC_EXPIRED_SECS = 1800
        hh2_ts_under_limit = float(handler1.lock_ts) + 1000
        handler2 = consistency_db.HashHandler(hash_id=1,
                                              timestamp_ms=hh2_ts_under_limit)
        h2 = handler2.lock()
        self.assertFalse(h2)
        self.assertEqual(handler1.lock_ts, handler2.prev_lock_ts)

    def test_lock_check_ts_true_prev_lock_expired(self):
        handler1 = consistency_db.HashHandler()
        h1 = handler1.lock()
        self.assertTrue(h1)
        self.assertEqual(handler1.lock_marker,
                         self._get_hash_from_handler_db(handler1))

        handler1.unlock()
        self.assertEqual(handler1.lock_ts,
                         self._get_hash_from_handler_db(handler1))

        # thread 1 has executed the complete lock-unlock cycle
        # thread 2 now tries to get lock with check_ts True
        # TOPO_SYNC_EXPIRED_SECS = 1 for testing
        time.sleep(1)
        handler2 = consistency_db.HashHandler()
        # only for testing
        consistency_db.TOPO_SYNC_EXPIRED_SECS = 1
        h2 = handler2.lock()
        self.assertTrue(h2)
        self.assertEqual(handler1.lock_ts, handler2.prev_lock_ts)

    def test_lock_check_ts_false_prev_lock_not_expired(self):
        handler1 = consistency_db.HashHandler()
        h1 = handler1.lock()
        self.assertTrue(h1)
        self.assertEqual(handler1.lock_marker,
                         self._get_hash_from_handler_db(handler1))

        handler1.unlock()
        self.assertEqual(handler1.lock_ts,
                         self._get_hash_from_handler_db(handler1))

        # thread 1 has executed the complete lock-unlock cycle
        # thread 2 now tries to get lock with check_ts True
        # TOPO_SYNC_EXPIRED_SECS = 1800
        hh2_ts_under_limit = float(handler1.lock_ts) + 1000
        handler2 = consistency_db.HashHandler(hash_id=1,
                                              timestamp_ms=hh2_ts_under_limit)
        h2 = handler2.lock(check_ts=False)
        self.assertTrue(h2)
        self.assertEqual(handler1.lock_ts, handler2.prev_lock_ts)

    def test_lock_check_ts_false_lock_clash(self):
        # 2 threads try to lock the DB at the same time when check_ts is False
        # and no thread holds the lock
        handler1 = consistency_db.HashHandler()
        h1 = handler1.lock()
        self.assertTrue(h1)
        handler1.unlock()
        self.assertEqual(handler1.lock_ts,
                         self._get_hash_from_handler_db(handler1))

        handler2 = consistency_db.HashHandler()

        with mock.patch.object(handler2._FACADE, 'get_engine') as ge, \
                mock.patch(CONSISTENCYDB + '.eventlet.sleep',
                           side_effect=[None]) as emock:
            conn = ge.return_value.begin.return_value.__enter__.return_value
            firstresult = mock.Mock()
            # a rowcount of 0 simulates the effect of another db client
            # updating the same record the handler was trying to update
            firstresult.rowcount = 0
            secondresult = mock.Mock()
            secondresult.rowcount = 1
            conn.execute.side_effect = [firstresult, secondresult]
            h2 = handler2.lock(check_ts=False)
            self.assertTrue(h2)
            # update should have been called again after the failure
            self.assertEqual(2, conn.execute.call_count)
            # sleep should have been called once, during first result failure
            emock.assert_called_once()

    def test_clear_lock(self):
        handler = consistency_db.HashHandler()
        handler.lock()  # lock the table
        self.assertEqual(handler.lock_marker,
                         self._get_hash_from_handler_db(handler))
        handler.unlock()
        self.assertEqual(handler.lock_ts,
                         self._get_hash_from_handler_db(handler))

    def test_handler_already_holding_lock(self):
        handler = consistency_db.HashHandler()
        handler.lock()  # lock the table
        with mock.patch.object(handler._FACADE, 'get_engine') as ge:
            handler.lock()
            # get engine should not have been called because no update
            # should have been made
            self.assertFalse(ge.called)
            self.assertTrue(handler.lock_ts, handler.prev_lock_ts)

    def test_unlock_set_prev_ts(self):
        handler1 = consistency_db.HashHandler()
        handler1.lock()
        self.assertEqual(handler1.lock_marker,
                         self._get_hash_from_handler_db(handler1))
        handler1.unlock()

        # first lock-unlock is done. now comes a second call with
        # check_ts = False
        handler2 = consistency_db.HashHandler()
        h2 = handler2.lock(check_ts=False)
        self.assertTrue(h2)
        self.assertEqual(handler1.lock_ts, handler2.prev_lock_ts)

        # now assuming exception occured during topo_sync, call
        # handler2.unlock(set_prev_ts=True)
        handler2.unlock(set_prev_ts=True)
        # hash in consistency_db will be previous hash_handler's lock_ts
        self.assertEqual(handler1.lock_ts,
                         self._get_hash_from_handler_db(handler2))
        # try unlock again on the same handler2 - it should have no effect
        # as unlock(set_prev_ts) removed TOPO_SYNC marker. this simulates
        # unlock() being called in the finally block of force_topo_sync()
        handler2.unlock()
        self.assertEqual(handler1.lock_ts,
                         self._get_hash_from_handler_db(handler2))

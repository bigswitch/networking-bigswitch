# Copyright 2016 Big Switch Networks, Inc.  All rights reserved.
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
#
# Adapted from neutron.tests.unit.db.test_agents_db.py

from networking_bigswitch.plugins.bigswitch.db import reachability_test_db
from neutron.tests.unit import testlib_api
from neutron_lib import context


class TestReachabilityQuickTestDbMixin(testlib_api.SqlTestCase):
    def setUp(self):
        super(TestReachabilityQuickTestDbMixin, self).setUp()
        self.context = context.get_admin_context()
        self.dbmixin = reachability_test_db.ReachabilityQuickTestDbMixin()

    def _assert_ref_fields_are_equal(self, reference, result):
        """Compare (key, value) pairs of a reference dict with the result

           Note: the result MAY have additional keys
        """

        for field, value in reference.items():
            self.assertEqual(value, result[field], field)

    def test_create_reachabilityquicktest(self):
        reachabilityquicktest_dict = {
            'reachabilityquicktest': {
                'tenant_id': 'admin_tenant_id',
                'name': 'quicktest',
                'src_tenant_id': 'src_admin_tenant_id',
                'src_tenant_name': 'admin',
                'src_segment_id': 'web_segment_id',
                'src_segment_name': 'web',
                'src_ip': '10.1.1.2',
                'dst_ip': '10.2.1.2',
                'expected_result': 'dropped'
            }
        }

        reachabilityquicktest = self.dbmixin.create_reachabilityquicktest(
            self.context, reachabilityquicktest_dict)
        self._assert_ref_fields_are_equal(
            reachabilityquicktest_dict['reachabilityquicktest'],
            reachabilityquicktest)

    def test_get_reachabilityquicktest(self):
        pass

    def test_get_reachabilityquicktests(self):
        pass

    def test_update_reachabilityquicktest(self):
        pass

    def test_delete_reachabilityquicktest(self):
        pass

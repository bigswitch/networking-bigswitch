# Copyright 2013 Big Switch Networks, Inc.
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

from neutron.tests.unit.db import test_agentschedulers_db

from networking_bigswitch.tests.unit.bigswitch import test_base


class BigSwitchDhcpAgentNotifierTestCase(
        test_agentschedulers_db.OvsDhcpAgentNotifierTestCase,
        test_base.BigSwitchTestBase):

    plugin_str = ('%s.NeutronRestProxyV2' %
                  test_base.PLUGIN_PATH)

    def setUp(self):
        self.setup_config_files()
        self.setup_patches()
        test_agentschedulers_db.OvsDhcpAgentNotifierTestCase.setUp(self)
        self.setup_db()
        self.startHttpPatch()

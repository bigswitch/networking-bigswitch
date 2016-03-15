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
#

from bsnstacklib.plugins.bigswitch.db import network_template_db  # noqa
from bsnstacklib.plugins.bigswitch.db import reachability_test_db  # noqa
from bsnstacklib.plugins.bigswitch.db import routerrule_db  # noqa
from neutron.db.migration.models import head


def get_metadata():
    return head.model_base.BASEV2.metadata

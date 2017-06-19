# Copyright 2017 Big Switch Networks, Inc.
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

from neutron_taas.services.taas import service_drivers as taas_service_drivers

from oslo_log import helpers as log_helpers
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class BSNTaasDriver(taas_service_drivers.TaasBaseDriver):
    """BSN Taas Service Driver class"""

    def __init__(self, service_plugin):
        LOG.debug("Loading BSNTaasDriver.")
        super(BSNTaasDriver, self).__init__(service_plugin)

    @log_helpers.log_method_call
    def create_tap_service_precommit(self, context):
        pass

    @log_helpers.log_method_call
    def create_tap_service_postcommit(self, context):
        # TODO(Joe): call to controller
        pass

    @log_helpers.log_method_call
    def delete_tap_service_precommit(self, context):
        pass

    @log_helpers.log_method_call
    def delete_tap_service_postcommit(self, context):
        # TODO(Joe): call to controller
        pass

    @log_helpers.log_method_call
    def create_tap_flow_precommit(self, context):
        pass

    @log_helpers.log_method_call
    def create_tap_flow_postcommit(self, context):
        # TODO(Joe): call to controller
        pass

    @log_helpers.log_method_call
    def delete_tap_flow_precommit(self, context):
        pass

    @log_helpers.log_method_call
    def delete_tap_flow_postcommit(self, context):
        # TODO(Joe): call to controller
        pass

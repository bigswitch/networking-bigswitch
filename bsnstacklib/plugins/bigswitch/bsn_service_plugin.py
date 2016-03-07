# Copyright 2011 OpenStack Foundation.
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

from datetime import datetime

from neutron.db import common_db_mixin
from neutron.services import service_base
from oslo_log import log
from oslo_serialization import jsonutils

from bsnstacklib.plugins.bigswitch.db import network_template_db
from bsnstacklib.plugins.bigswitch.db import reachability_test_db
from bsnstacklib.plugins.bigswitch.extensions import bsnserviceextension
from bsnstacklib.plugins.bigswitch import servermanager

LOG = log.getLogger(__name__)


class BSNServicePlugin(service_base.ServicePluginBase,
                       bsnserviceextension.BSNServicePluginBase,
                       common_db_mixin.CommonDbMixin):

    supported_extension_aliases = ["bsn-service-extension"]

    def __init__(self):
        super(BSNServicePlugin, self).__init__()
        # initialize BCF server handler
        self.servers = servermanager.ServerPool.get_instance()
        self.networktemplate_db_mixin = network_template_db\
            .NetworkTemplateDbMixin()
        self.network_template_assignment_db_mixin = network_template_db\
            .NetworkTemplateAssignmentDbMixin()
        self.reachabilitytest_db_mixin = reachability_test_db\
            .ReachabilityTestDbMixin()
        self.reachabilityquicktest_db_mixin = reachability_test_db\
            .ReachabilityQuickTestDbMixin()

    def get_plugin_type(self):
        # Tell Neutron this is a BSN service plugin
        return 'BSNSERVICEPLUGIN'

    def get_plugin_name(self):
        return 'bsn_service_extension'

    def get_plugin_description(self):
        return "BSN Service Plugin"

    # public CRUD methods for network templates
    def get_networktemplates(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        return self.networktemplate_db_mixin.get_networktemplates(
            context=context, filters=filters, fields=fields, sorts=sorts,
            limit=limit, marker=marker, page_reverse=page_reverse)

    def get_networktemplate(self, context, id, fields=None):
        return self.networktemplate_db_mixin.get_networktemplate(
            context=context, id=id, fields=fields)

    def create_networktemplate(self, context, networktemplate):
        return self.networktemplate_db_mixin.create_networktemplate(
            context=context, networktemplate=networktemplate)

    def delete_networktemplate(self, context, id):
        self.networktemplate_db_mixin.delete_networktemplate(
            context=context, id=id)

    def update_networktemplate(self, context, id, networktemplate):
        return self.networktemplate_db_mixin.update_networktemplate(
            context=context, id=id, networktemplate=networktemplate)

    # public CRUD methods for Network Template Assignment
    def get_networktemplateassignments(self, context, filters=None,
                                       fields=None, sorts=None, limit=None,
                                       marker=None, page_reverse=False):
        return self.network_template_assignment_db_mixin\
            .get_networktemplateassignments(
                context=context, filters=filters, fields=fields, sorts=sorts,
                limit=limit, marker=marker, page_reverse=page_reverse)

    def get_networktemplateassignment(self, context, id, fields=None):
        return self.network_template_assignment_db_mixin\
            .get_networktemplateassignment(context=context, id=id,
                                           fields=fields)

    def create_networktemplateassignment(self, context,
                                         networktemplateassignment):
        return self.network_template_assignment_db_mixin\
            .create_networktemplateassignment(
                context=context,
                networktemplateassignment=networktemplateassignment)

    def delete_networktemplateassignment(self, context, id):
        self.network_template_assignment_db_mixin\
            .delete_networktemplateassignment(context=context, id=id)

    def update_networktemplateassignment(self, context, id,
                                         networktemplateassignment):
        return self.network_template_assignment_db_mixin\
            .update_networktemplateassignment(
                context=context, id=id,
                networktemplateassignment=networktemplateassignment)

    # common method to parse response from the controller
    def parse_result(self, response, expected_result):
        if not response:
            test_result = "fail"
            detail = [{'path-index': "No result"}]
        elif response[0].get("summary", [{}])[0].get("forward-result") != \
                expected_result:
            test_result = "fail"
            detail = [{'path-index': "Expected: %s. Actual: %s" % (
                expected_result,
                response[0].get("summary", [{}])[0].get("forward-result"))}]
            try:
                detail[0]['path-index'] += \
                    " - " + response[0]['summary'][0]['logical-error']
            except Exception:
                pass
        elif response[0].get("summary", [{}])[0].get("forward-result") == \
                expected_result:
            test_result = "pass"
            detail = response[0].get("physical-path", [{}])
        else:
            try:
                detail = [{'path-index':
                    response[0]['summary'][0]['logical-error']}]
            except Exception:
                detail = [{'path-index': jsonutils.dumps(response)}]
            test_result = "fail"
        detail[0]['path-index'] = detail[0].get('path-index', '')
        detail[0]['hop-index'] = detail[0].get('hop-index', '')
        detail[0]['hop-name'] = detail[0].get('hop-name', '')
        return test_result, detail

    # public CRUD methods for Reachability Test
    def get_reachabilitytests(self, context, filters=None, fields=None,
                              sorts=None, limit=None, marker=None,
                              page_reverse=False):
        return self.reachabilitytest_db_mixin.get_reachabilitytests(
            context, filters=filters, fields=fields, sorts=sorts, limit=limit,
            marker=marker, page_reverse=page_reverse)

    def get_reachabilitytest(self, context, id, fields=None):
        return self.reachabilitytest_db_mixin.get_reachabilitytest(
            context=context, id=id, fields=fields)

    def create_reachabilitytest(self, context, reachabilitytest):
        return self.reachabilitytest_db_mixin.create_reachabilitytest(
            context=context, reachabilitytest=reachabilitytest)

    def update_reachabilitytest(self, context, id, reachabilitytest):
        reachabilitytest_data = reachabilitytest['reachabilitytest']
        reachabilitytest = self.reachabilitytest_db_mixin\
            ._get_reachabilitytest(context, id)
        if 'run_test' in reachabilitytest_data and \
                reachabilitytest_data['run_test']:
            # run test on the controller and get results
            # update fields in reachabilitytest_data dict
            src = reachabilitytest.get_connection_source()
            dst = reachabilitytest.get_connection_destination()
            response = self.servers.rest_get_testpath(src, dst)
            test_result, detail = self.parse_result(
                response, reachabilitytest.expected_result)
            reachabilitytest_data['test_result'] = test_result
            reachabilitytest_data['detail'] = detail
            # reset run_test to false and set timestamp to now
            reachabilitytest_data['run_test'] = False
            reachabilitytest_data['test_time'] = datetime.now()
        return self.reachabilitytest_db_mixin.update_reachabilitytest(
            context=context, id=id,
            reachabilitytest={'reachabilitytest': reachabilitytest_data})

    def delete_reachabilitytest(self, context, id):
        self.reachabilitytest_db_mixin.delete_reachabilitytest(
            context=context, id=id)

    # public CRUD methods for Reachability Quick Test
    def get_reachabilityquicktests(self, context, filters=None, fields=None,
                                   sorts=None, limit=None, marker=None,
                                   page_reverse=False):
        return self.reachabilityquicktest_db_mixin.get_reachabilityquicktests(
            context=context, filters=filters, fields=fields, sorts=sorts,
            limit=limit, marker=marker, page_reverse=page_reverse)

    def get_reachabilityquicktest(self, context, id, fields=None):
        return self.reachabilityquicktest_db_mixin.get_reachabilityquicktest(
            context=context, id=id, fields=fields)

    def create_reachabilityquicktest(self, context, reachabilityquicktest):
        return self.reachabilityquicktest_db_mixin\
            .create_reachabilityquicktest(
                context=context, reachabilityquicktest=reachabilityquicktest)

    def update_reachabilityquicktest(self, context, id, reachabilityquicktest):
        reachabilityquicktest_data = \
            reachabilityquicktest['reachabilityquicktest']
        reachabilityquicktest = self.reachabilityquicktest_db_mixin\
            ._get_reachabilityquicktest(context, id)
        if 'save_test' in reachabilityquicktest_data and \
                reachabilityquicktest_data['save_test']:
            # just copy paste the test and return
            quicktest = self.reachabilityquicktest_db_mixin\
                ._get_reachabilityquicktest(context, id)
            # update name as given in the args, not the default name
            quicktest.name = reachabilityquicktest_data['name']
            # remove ID, as we want it to be unique per test
            # not unique per tenant
            quicktest_dict = self.reachabilityquicktest_db_mixin\
                ._make_reachabilityquicktest_dict(quicktest)
            quicktest_dict.pop('id')
            self.reachabilitytest_db_mixin.create_reachabilitytest_withresult(
                context=context,
                reachabilitytest={'reachabilitytest': quicktest_dict})
            # reset the save_test flag
            reachabilityquicktest_data['save_test'] = False
        if 'run_test' in reachabilityquicktest_data and \
                reachabilityquicktest_data['run_test']:
            # run test on the controller and get results
            # update fields in reachabilityquicktest_data dict
            src = reachabilityquicktest.get_connection_source()
            dst = reachabilityquicktest.get_connection_destination()
            response = self.servers.rest_get_testpath(src, dst)
            test_result, detail = self.parse_result(
                response, reachabilityquicktest.expected_result)
            reachabilityquicktest_data['test_result'] = test_result
            reachabilityquicktest_data['detail'] = detail
            # reset run_test to false and set timestamp to now
            reachabilityquicktest_data['run_test'] = False
            reachabilityquicktest_data['test_time'] = datetime.now()
        return self.reachabilityquicktest_db_mixin\
            .update_reachabilityquicktest(
                context=context, id=id,
                reachabilityquicktest={'reachabilityquicktest':
                                       reachabilityquicktest_data})

    def delete_reachabilityquicktest(self, context, id):
        self.reachabilityquicktest_db_mixin.delete_reachabilityquicktest(
            context=context, id=id)

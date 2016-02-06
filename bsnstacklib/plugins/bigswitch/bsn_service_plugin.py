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
from oslo_db import exception as db_exc
from oslo_log import log
from sqlalchemy.orm import exc

from bsnstacklib.plugins.bigswitch.db import network_template_db
from bsnstacklib.plugins.bigswitch.db.network_template_db import \
    NetworkTemplate
from bsnstacklib.plugins.bigswitch.db.network_template_db import \
    NetworkTemplateAssignment
from bsnstacklib.plugins.bigswitch.db import reachability_test_db
from bsnstacklib.plugins.bigswitch.db.reachability_test_db import \
    ReachabilityQuickTest
from bsnstacklib.plugins.bigswitch.db.reachability_test_db import \
    ReachabilityTest
from bsnstacklib.plugins.bigswitch.extensions import bsnserviceextension
from bsnstacklib.plugins.bigswitch import servermanager
from oslo_serialization import jsonutils

LOG = log.getLogger(__name__)


class BSNServicePlugin(service_base.ServicePluginBase,
                       bsnserviceextension.BSNServicePluginBase,
                       common_db_mixin.CommonDbMixin):

    supported_extension_aliases = ["bsn-service-extension"]

    def __init__(self):
        super(BSNServicePlugin, self).__init__()
        # initialize BCF server handler
        self.servers = servermanager.ServerPool.get_instance()

    def get_plugin_type(self):
        # Tell Neutron this is a BSN service plugin
        return 'BSNSERVICEPLUGIN'

    def get_plugin_name(self):
        return 'bsn_service_extension'

    def get_plugin_description(self):
        return "BSN Service Plugin"

    # Network Template
    def _make_networktemplate_dict(self, template, fields=None):
        return self._fields({
            'id': template.id,
            'body': template.body,
            'name': template.name}, fields)

    def _get_networktemplate(self, context, id):
        try:
            networktemplate = self._get_by_id(context, NetworkTemplate, id)
        except exc.NoResultFound:
            raise network_template_db.NetworkTemplateNotFound(id=id)
        return networktemplate

    # public CRUD methods for network templates
    def get_networktemplates(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        networktemplates = \
            self._get_collection(context, NetworkTemplate,
                                 self._make_networktemplate_dict,
                                 filters=filters, fields=fields)
        return networktemplates

    def get_networktemplate(self, context, id, fields=None):
        networktemplate = self._get_networktemplate(context, id)
        return self._make_networktemplate_dict(networktemplate, fields)

    def create_networktemplate(self, context, networktemplate):
        networktemplate_data = networktemplate['networktemplate']
        with context.session.begin(subtransactions=True):
            networktemplate = \
                NetworkTemplate(body=networktemplate_data['body'],
                                name=networktemplate_data['name'])
            context.session.add(networktemplate)
        return self._make_networktemplate_dict(networktemplate)

    def delete_networktemplate(self, context, id):
        with context.session.begin(subtransactions=True):
            networktemplate = self._get_networktemplate(context, id)
            context.session.delete(networktemplate)

    def update_networktemplate(self, context, id, networktemplate):
        networktemplate_data = networktemplate['networktemplate']
        with context.session.begin(subtransactions=True):
            networktemplate = self._get_networktemplate(context, id)
            networktemplate.update(networktemplate_data)
        return self._make_networktemplate_dict(networktemplate)

    # Network Template Assignment
    def _make_networktemplateassignment_dict(self, templateassignment,
                                             fields=None):
        return self._fields({
            'id': templateassignment.id,
            'template_id': templateassignment.template_id,
            'tenant_id': templateassignment.tenant_id,
            'stack_id': templateassignment.stack_id}, fields)

    def _get_networktemplateassignment(self, context, id):
        try:
            networktemplateassignment = self._get_by_id(
                context, NetworkTemplateAssignment, id)
        except exc.NoResultFound:
            raise network_template_db.NetworkTemplateAssignmentNotFound(id=id)
        return networktemplateassignment

    # public CRUD methods for Network Template Assignment
    def get_networktemplateassignments(self, context, filters=None,
                                       fields=None, sorts=None, limit=None,
                                       marker=None, page_reverse=False):
        networktemplateassignments = \
            self._get_collection(context, NetworkTemplateAssignment,
                                 self._make_networktemplateassignment_dict,
                                 filters=filters, fields=fields)
        return networktemplateassignments

    def get_networktemplateassignment(self, context, id, fields=None):
        networktemplateassignment = \
            self._get_networktemplateassignment(context, id)
        return self._make_networktemplateassignment_dict(
            networktemplateassignment, fields)

    def create_networktemplateassignment(self, context,
                                         networktemplateassignment):
        networktemplateassignment_data = \
            networktemplateassignment['networktemplateassignment']
        with context.session.begin(subtransactions=True):
            networktemplateassignment = NetworkTemplateAssignment(
                id=networktemplateassignment_data['tenant_id'],
                tenant_id=networktemplateassignment_data['tenant_id'],
                template_id=networktemplateassignment_data['template_id'],
                stack_id=networktemplateassignment_data['stack_id'])
            try:
                context.session.add(networktemplateassignment)
            except db_exc.DBDuplicateEntry:
                raise network_template_db.NetworkTemplateAssignmentExists(
                    tenant_id=networktemplateassignment.tenant_id)
        return self._make_networktemplateassignment_dict(
            networktemplateassignment)

    def delete_networktemplateassignment(self, context, id):
        with context.session.begin(subtransactions=True):
            networktemplateassignment = \
                self._get_networktemplateassignment(context, id)
            context.session.delete(networktemplateassignment)

    def update_networktemplateassignment(self, context, id,
                                         networktemplateassignment):
        networktemplateassignment_data = \
            networktemplateassignment['networktemplateassignment']
        with context.session.begin(subtransactions=True):
            networktemplateassignment = \
                self._get_networktemplateassignment(context, id)
            networktemplateassignment.update(networktemplateassignment_data)
        return self._make_networktemplateassignment_dict(
            networktemplateassignment)

    # Reachability Test
    def _make_reachabilitytest_dict(self, reachabilitytest, fields=None):
        return self._fields({
            'id': reachabilitytest.id,
            'tenant_id': reachabilitytest.tenant_id,
            'name': reachabilitytest.name,
            'src_tenant_name': reachabilitytest.src_tenant_name,
            'src_segment_name': reachabilitytest.src_segment_name,
            'src_ip': reachabilitytest.src_ip,
            'dst_ip': reachabilitytest.dst_ip,
            'expected_result': reachabilitytest.expected_result,
            'test_time': reachabilitytest.test_time,
            'test_result': reachabilitytest.test_result,
            'detail': reachabilitytest.detail,
            'run_test': reachabilitytest.run_test}, fields)

    def _get_reachabilitytest(self, context, id):
        try:
            reachabilitytest = self._get_by_id(context, ReachabilityTest, id)
        except exc.NoResultFound:
            raise reachability_test_db.ReachabilityTestNotFound(id=id)
        return reachabilitytest

    # public CRUD methods for Reachability Test
    def get_reachabilitytests(self, context, filters=None, fields=None,
                              sorts=None, limit=None, marker=None,
                              page_reverse=False):
        reachabilitytests = \
            self._get_collection(context, ReachabilityTest,
                                 self._make_reachabilitytest_dict,
                                 filters=filters, fields=fields)
        return reachabilitytests

    def get_reachabilitytest(self, context, id, fields=None):
        reachabilitytest = \
            self._get_reachabilitytest(context, id)
        return self._make_reachabilitytest_dict(reachabilitytest, fields)

    def create_reachabilitytest(self, context, reachabilitytest):
        reachabilitytest_data = reachabilitytest['reachabilitytest']
        with context.session.begin(subtransactions=True):
            reachabilitytest = ReachabilityTest(
                tenant_id=reachabilitytest_data['tenant_id'],
                name=reachabilitytest_data['name'],
                src_tenant_name=reachabilitytest_data['src_tenant_name'],
                src_segment_name=reachabilitytest_data['src_segment_name'],
                src_ip=reachabilitytest_data['src_ip'],
                dst_ip=reachabilitytest_data['dst_ip'],
                expected_result=reachabilitytest_data['expected_result'])
            context.session.add(reachabilitytest)
        return self._make_reachabilitytest_dict(reachabilitytest)

    def create_reachabilitytest_withresult(self, context, reachabilitytest):
        reachabilitytest_data = reachabilitytest['reachabilitytest']
        with context.session.begin(subtransactions=True):
            reachabilitytest = ReachabilityTest(
                tenant_id=reachabilitytest_data['tenant_id'],
                name=reachabilitytest_data['name'],
                src_tenant_name=reachabilitytest_data['src_tenant_name'],
                src_segment_name=reachabilitytest_data['src_segment_name'],
                src_ip=reachabilitytest_data['src_ip'],
                dst_ip=reachabilitytest_data['dst_ip'],
                expected_result=reachabilitytest_data['expected_result'],
                test_result=reachabilitytest_data['test_result'],
                detail=reachabilitytest_data['detail'],
                test_time=reachabilitytest_data['test_time'])
            context.session.add(reachabilitytest)
        return self._make_reachabilitytest_dict(reachabilitytest)

    def parse_result(self, response, expected_result):
        test_result = "pending"
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

    def update_reachabilitytest(self, context, id, reachabilitytest):
        reachabilitytest_data = reachabilitytest['reachabilitytest']
        reachabilitytest = self._get_reachabilitytest(context, id)
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
        with context.session.begin(subtransactions=True):
            reachabilitytest = self._get_reachabilitytest(context, id)
            reachabilitytest.update(reachabilitytest_data)
        return self._make_reachabilitytest_dict(reachabilitytest)

    def delete_reachabilitytest(self, context, id):
        with context.session.begin(subtransactions=True):
            reachabilitytest = self._get_reachabilitytest(context, id)
            context.session.delete(reachabilitytest)

    # Reachability Quick Test
    def _make_reachabilityquicktest_dict(self, reachabilityquicktest,
                                         fields=None):
        return self._fields({
            'id': reachabilityquicktest.id,
            'tenant_id': reachabilityquicktest.tenant_id,
            'name': reachabilityquicktest.name,
            'src_tenant_name': reachabilityquicktest.src_tenant_name,
            'src_segment_name': reachabilityquicktest.src_segment_name,
            'src_ip': reachabilityquicktest.src_ip,
            'dst_ip': reachabilityquicktest.dst_ip,
            'expected_result': reachabilityquicktest.expected_result,
            'test_time': reachabilityquicktest.test_time,
            'test_result': reachabilityquicktest.test_result,
            'detail': reachabilityquicktest.detail,
            'run_test': reachabilityquicktest.run_test}, fields)

    def _get_reachabilityquicktest(self, context, id):
        try:
            reachabilityquicktest = self._get_by_id(
                context, ReachabilityQuickTest, id)
        except exc.NoResultFound:
            raise reachability_test_db.ReachabilityQuickTestNotFound(id=id)
        return reachabilityquicktest

    # public CRUD methods for Reachability Quick Test
    def get_reachabilityquicktests(self, context, filters=None, fields=None,
                                   sorts=None, limit=None, marker=None,
                                   page_reverse=False):
        reachabilityquicktests = \
            self._get_collection(context, ReachabilityQuickTest,
                                 self._make_reachabilityquicktest_dict,
                                 filters=filters, fields=fields)
        return reachabilityquicktests

    def get_reachabilityquicktest(self, context, id, fields=None):
        reachabilityquicktest = \
            self._get_reachabilityquicktest(context, id)
        return self._make_reachabilityquicktest_dict(
            reachabilityquicktest, fields)

    def create_reachabilityquicktest(self, context, reachabilityquicktest):
        quicktest_data = reachabilityquicktest['reachabilityquicktest']
        with context.session.begin(subtransactions=True):
            reachabilityquicktest = ReachabilityQuickTest(
                id=quicktest_data['tenant_id'],
                tenant_id=quicktest_data['tenant_id'],
                name=quicktest_data['name'],
                src_tenant_name=quicktest_data['src_tenant_name'],
                src_segment_name=quicktest_data['src_segment_name'],
                src_ip=quicktest_data['src_ip'],
                dst_ip=quicktest_data['dst_ip'],
                expected_result=quicktest_data['expected_result'])
            context.session.add(reachabilityquicktest)
        return self._make_reachabilityquicktest_dict(reachabilityquicktest)

    def update_reachabilityquicktest(self, context, id, reachabilityquicktest):
        reachabilityquicktest_data = \
            reachabilityquicktest['reachabilityquicktest']
        reachabilityquicktest = self._get_reachabilityquicktest(context, id)
        if 'save_test' in reachabilityquicktest_data and \
                reachabilityquicktest_data['save_test']:
            # just copy paste the test and return
            quicktest = self._get_reachabilityquicktest(context, id)
            # update name as given in the args, not the default name
            quicktest.name = reachabilityquicktest_data['name']
            # remove ID, as we want it to be unique per test
            # not unique per tenant
            quicktest_dict = self._make_reachabilityquicktest_dict(quicktest)
            quicktest_dict.pop('id')
            self.create_reachabilitytest_withresult(
                context, {'reachabilitytest': quicktest_dict})
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

        with context.session.begin(subtransactions=True):
            reachabilityquicktest = self._get_reachabilityquicktest(
                context, id)
            reachabilityquicktest.update(reachabilityquicktest_data)
        return self._make_reachabilityquicktest_dict(reachabilityquicktest)

    def delete_reachabilityquicktest(self, context, id):
        with context.session.begin(subtransactions=True):
            reachabilityquicktest = self._get_reachabilityquicktest(
                context, id)
            context.session.delete(reachabilityquicktest)

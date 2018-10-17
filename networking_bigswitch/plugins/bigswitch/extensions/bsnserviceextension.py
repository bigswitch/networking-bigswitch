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

from neutron.api import extensions as neutron_extensions
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper
from neutron_lib.api import extensions
from neutron_lib.plugins import directory

import abc
from networking_bigswitch.plugins.bigswitch import constants
from networking_bigswitch.plugins.bigswitch import extensions as bsn_extensions

# Ensure the extension is loaded at startup
neutron_extensions.append_api_extensions_path(bsn_extensions.__path__)

RESOURCE_ATTRIBUTE_MAP = {
    'networktemplates': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:string': None},
               'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'is_visible': False},
        'body': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True}
    },
    'networktemplateassignments': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:string': None},
               'is_visible': True},
        'template_id': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'is_visible': True},
        'stack_id': {'allow_post': True, 'allow_put': True,
                     'validate': {'type:string': None},
                     'is_visible': True},
        'template': {'allow_post': False, 'allow_put': False,
                     'is_visible': True},
    },
    'reachabilitytests': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True},
        'src_tenant_id': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:string': None},
                          'is_visible': True},
        'src_tenant_name': {'allow_post': True, 'allow_put': True,
                            'validate': {'type:string': None},
                            'is_visible': True},
        'src_segment_id': {'allow_post': True, 'allow_put': True,
                           'validate': {'type:string': None},
                           'is_visible': True},
        'src_segment_name': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:string': None},
                             'is_visible': True},
        'src_ip': {'allow_post': True, 'allow_put': True,
                   'is_visible': True},
        'dst_ip': {'allow_post': True, 'allow_put': True,
                   'is_visible': True},
        'expected_result': {'allow_post': True, 'allow_put': True,
                            'validate': {'type:string': None},
                            'is_visible': True},
        'test_time': {'allow_post': False, 'allow_put': False,
                      'is_visible': True},
        'test_result': {'allow_post': False, 'allow_put': False,
                        'is_visible': True},
        'detail': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'logical_path': {'allow_post': False, 'allow_put': False,
                         'is_visible': True},
        'run_test': {'allow_post': False, 'allow_put': True,
                     'is_visible': True},
    },
    'reachabilityquicktests': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True},
        'src_tenant_id': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:string': None},
                          'is_visible': True},
        'src_tenant_name': {'allow_post': True, 'allow_put': True,
                            'validate': {'type:string': None},
                            'is_visible': True},
        'src_segment_id': {'allow_post': True, 'allow_put': True,
                           'validate': {'type:string': None},
                           'is_visible': True},
        'src_segment_name': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:string': None},
                             'is_visible': True},
        'src_ip': {'allow_post': True, 'allow_put': True,
                   'is_visible': True},
        'dst_ip': {'allow_post': True, 'allow_put': True,
                   'is_visible': True},
        'expected_result': {'allow_post': True, 'allow_put': True,
                            'validate': {'type:string': None},
                            'is_visible': True},
        'test_time': {'allow_post': False, 'allow_put': False,
                      'is_visible': True},
        'test_result': {'allow_post': False, 'allow_put': False,
                        'is_visible': True},
        'detail': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'logical_path': {'allow_post': False, 'allow_put': False,
                         'is_visible': True},
        'run_test': {'allow_post': False, 'allow_put': True,
                     'is_visible': True},
        'save_test': {'allow_post': False, 'allow_put': True,
                      'is_visible': True},
    },
    'tenantpolicies': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'is_visible': True},
        'priority': {'allow_post': True, 'allow_put': False,
                     'validate': {'type:integer': None},
                     'is_visible': True},
        'source': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': None},
                   'is_visible': True},
        'source_port': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:integer': None},
                        'is_visible': True,
                        'default': 0},
        'destination': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True},
        'destination_port': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:integer': None},
                             'is_visible': True, 'default': 0},
        'protocol': {'allow_post': True, 'allow_put': True,
                     'validate': {'type:string': None},
                     'is_visible': True, 'default': ''},
        'action': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': None},
                   'is_visible': True},
        'nexthops': {'allow_post': True, 'allow_put': True,
                     'validate': {'type:string': None},
                     'is_visible': True,
                     'default': ''},
    },
    'forcesynctopologies': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'project_id': {'allow_post': True, 'allow_put': False,
                       'validate': {'type:string': None},
                       'is_visible': True},
        'timestamp_ms': {'allow_post': False, 'allow_put': True,
                         'validate': {'type:string': None},
                         'is_visible': True},
        'timestamp_datetime': {'allow_post': False, 'allow_put': False,
                               'validate': {'type:string': None},
                               'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'validate': {'type:string': None},
                   'is_visible': True}
    },
}


class Bsnserviceextension(extensions.ExtensionDescriptor):

    """API extension for handling BSN service plugin."""

    @classmethod
    def get_name(cls):
        return "Big Switch Networks Service Plugin"

    @classmethod
    def get_alias(cls):
        return "bsn-service-extension"

    @classmethod
    def get_description(cls):
        return "Provides REST API for BSN specific service extensions."

    @classmethod
    def get_namespace(cls):
        return \
            "http://docs.openstack.org/ext/neutron/bsnserviceplugin/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2015-10-29T04:20:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Extended Resources."""
        resources = []
        net_template_inst = directory.get_plugin(constants.BSN_SERVICE_PLUGIN)
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        for collection in RESOURCE_ATTRIBUTE_MAP:
            controller = base.create_resource(
                collection, plural_mappings[collection], net_template_inst,
                RESOURCE_ATTRIBUTE_MAP[collection])
            resource = neutron_extensions.ResourceExtension(
                collection, controller)
            resources.append(resource)
        return resources

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


class BSNServicePluginBase(object):

    # Network Template
    @abc.abstractmethod
    def get_networktemplates(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        pass

    @abc.abstractmethod
    def get_networktemplate(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_networktemplate(self, context, networktemplate):
        pass

    @abc.abstractmethod
    def delete_networktemplate(self, context, id):
        pass

    @abc.abstractmethod
    def update_networktemplate(self, context, id, networktemplate):
        pass

    # Network Template Assignment
    @abc.abstractmethod
    def get_networktemplateassignments(self, context, filters=None,
                                       fields=None, sorts=None, limit=None,
                                       marker=None, page_reverse=False):
        pass

    @abc.abstractmethod
    def get_networktemplateassignment(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_networktemplateassignment(self, context,
                                         networktemplateassignment):
        pass

    @abc.abstractmethod
    def delete_networktemplateassignment(self, context, id):
        pass

    @abc.abstractmethod
    def update_networktemplateassignment(self, context, id,
                                         networktemplateassignment):
        pass

    # Reachability Test
    @abc.abstractmethod
    def get_reachabilitytests(self, context, filters=None, fields=None,
                              sorts=None, limit=None, marker=None,
                              page_reverse=False):
        pass

    @abc.abstractmethod
    def get_reachabilitytest(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_reachabilitytest(self, context, reachabilitytest):
        pass

    @abc.abstractmethod
    def update_reachabilitytest(self, context, id, reachabilitytest):
        pass

    @abc.abstractmethod
    def delete_reachabilitytest(self, context, id):
        pass

    # Reachability Quick Test
    @abc.abstractmethod
    def get_reachabilityquicktests(self, context, filters=None, fields=None,
                                   sorts=None, limit=None, marker=None,
                                   page_reverse=False):
        pass

    @abc.abstractmethod
    def get_reachabilityquicktest(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_reachabilityquicktest(self, context, reachabilityquicktest):
        pass

    @abc.abstractmethod
    def update_reachabilityquicktest(self, context, id, reachabilityquicktest):
        pass

    @abc.abstractmethod
    def delete_reachabilityquicktest(self, context, id):
        pass

    # Tenant router policies
    @abc.abstractmethod
    def get_tenantpolicies(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        pass

    @abc.abstractmethod
    def get_tenantpolicy(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_tenantpolicy(self, context, tenantpolicy):
        pass

    @abc.abstractmethod
    def update_tenantpolicy(self, context, id, tenantpolicy):
        pass

    @abc.abstractmethod
    def delete_tenantpolicy(self, context, id):
        pass

    # Force Topology Sync command
    @abc.abstractmethod
    def update_forcesynctopology(self, context, id, forcesynctopology):
        pass

    @abc.abstractmethod
    def get_forcesynctopologies(self, context, filters=None, fields=None,
                                sorts=None, limit=None, marker=None,
                                page_reverse=False):
        pass

    @abc.abstractmethod
    def get_forcesynctopology(self, context, id, fields=None):
        pass

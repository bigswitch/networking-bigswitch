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
from networking_bigswitch.plugins.bigswitch.i18n import _
from neutronclient.common import extension


# network templates
def _networktemplate_updatable_args(parser):
    parser.add_argument(
        'name',
        help=_('Name of this network template.'))
    parser.add_argument(
        'body',
        help=_('Body of this network template.'))


def _networktemplate_updatable_args2body(parsed_args, body, client):
    if parsed_args.name:
        body['name'] = parsed_args.name
    if parsed_args.body:
        body['body'] = parsed_args.body


class NetworkTemplate(extension.NeutronClientExtension):
    resource = 'networktemplate'
    resource_plural = '%ss' % resource
    object_path = '/%s' % resource_plural
    resource_path = '/%s/%%s' % resource_plural
    versions = ['2.0']


class NetworkTemplatesList(extension.ClientExtensionList, NetworkTemplate):
    """List Network Templates"""

    shell_command = 'network-templates-list'
    list_columns = ['id', 'name', 'body']


class NetworkTemplatesCreate(extension.ClientExtensionCreate, NetworkTemplate):
    """Create a Network Template."""

    shell_command = 'network-templates-create'
    list_columns = ['id', 'name', 'body']

    def add_known_arguments(self, parser):
        _networktemplate_updatable_args(parser)

    def args2body(self, parsed_args):
        body = {}
        client = self.get_client()
        _networktemplate_updatable_args2body(parsed_args, body, client)
        return {'networktemplate': body}


class NetworkTemplatesUpdate(extension.ClientExtensionUpdate, NetworkTemplate):
    """Update a network template."""

    shell_command = 'network-templates-update'
    list_columns = ['id', 'name', 'body']

    def add_known_arguments(self, parser):
        _networktemplate_updatable_args(parser)

    def args2body(self, parsed_args):
        body = {}
        client = self.get_client()
        _networktemplate_updatable_args2body(parsed_args, body, client)
        return {'networktemplate': body}


class NetworkTemplatesDelete(extension.ClientExtensionDelete, NetworkTemplate):
    """Delete a network template."""

    shell_command = 'network-templates-delete'


class NetworkTemplatesShow(extension.ClientExtensionShow, NetworkTemplate):
    """Show a network template."""

    shell_command = 'network-templates-show'


# network template assignment
def _networktemplateassignment_updatable_args(parser):
    parser.add_argument(
        'template_id', metavar='template-id',
        help=_('ID of the network template associated with this tenant.'))
    parser.add_argument(
        'stack_id', metavar='stack-id',
        help=_('ID of the heat template associated with this tenant.'))


def _networktemplateassignment_updatable_args2body(parsed_args, body, client):
    if parsed_args.template_id:
        body['template_id'] = parsed_args.template_id
    if parsed_args.stack_id:
        body['stack_id'] = parsed_args.stack_id


class NetworkTemplateAssignment(extension.NeutronClientExtension):
    resource = 'networktemplateassignment'
    resource_plural = '%ss' % resource
    object_path = '/%s' % resource_plural
    resource_path = '/%s/%%s' % resource_plural
    versions = ['2.0']


class NetworkTemplateAssignmentsList(extension.ClientExtensionList,
                                     NetworkTemplateAssignment):
    """List Network Template Assignments"""

    shell_command = 'network-template-assignments-list'
    list_columns = ['tenant_id', 'template_id', 'stack_id']


class NetworkTemplateAssignmentsCreate(extension.ClientExtensionCreate,
                                       NetworkTemplateAssignment):
    """Create a Network Template Assignment."""

    shell_command = 'network-template-assignments-create'
    list_columns = ['tenant_id', 'template_id', 'stack_id']

    def add_known_arguments(self, parser):
        _networktemplateassignment_updatable_args(parser)

    def args2body(self, parsed_args):
        body = {}
        client = self.get_client()
        _networktemplateassignment_updatable_args2body(parsed_args,
                                                       body,
                                                       client)
        return {'networktemplateassignment': body}


class NetworkTemplateAssignmentsUpdate(extension.ClientExtensionUpdate,
                                       NetworkTemplateAssignment):
    """Update a Network Template Assignment."""

    allow_names = False
    shell_command = 'network-template-assignments-update'
    list_columns = ['tenant_id', 'template_id', 'stack_id']

    def add_known_arguments(self, parser):
        _networktemplateassignment_updatable_args(parser)

    def args2body(self, parsed_args):
        body = {}
        client = self.get_client()
        _networktemplateassignment_updatable_args2body(parsed_args,
                                                       body,
                                                       client)
        return {'networktemplateassignment': body}


class NetworkTemplateAssignmentsDelete(extension.ClientExtensionDelete,
                                       NetworkTemplateAssignment):
    """Delete a Network Template Assignment."""

    shell_command = 'network-template-assignments-delete'


class NetworkTemplateAssignmentsShow(extension.ClientExtensionShow,
                                     NetworkTemplateAssignment):
    """Show a Network Template Assignment."""

    shell_command = 'network-template-assignments-show'


# reachability tests
def _reachabilitytest_updatable_args(parser):
    parser.add_argument(
        'name',
        help=_('Name of this reachability test.'))
    parser.add_argument(
        'src_tenant_id', metavar='src-tenant-id',
        help=_('Tenant ID of the src-ip.'))
    parser.add_argument(
        'src_tenant_name', metavar='src-tenant-name',
        help=_('Tenant name of the src-ip.'))
    parser.add_argument(
        'src_segment_id', metavar='src-segment-id',
        help=_('Network id of the src-ip.'))
    parser.add_argument(
        'src_segment_name', metavar='src-segment-name',
        help=_('Network name of the src-ip.'))
    parser.add_argument(
        'src_ip', metavar='src-ip',
        help=_('Source IP of the reachability test.'))
    parser.add_argument(
        'dst_ip', metavar='dst-ip',
        help=_('Destination IP of the reachability test.'))
    parser.add_argument(
        'expected_result', metavar='expected-result',
        help=_('Expected result of the test.'))


def _reachabilitytest_runtest_args(parser):
    parser.add_argument('name',
                        help=_('Name of this reachability test.'))


def _reachabilitytest_updatable_args2body(parsed_args, body, client):
    if parsed_args.name:
        body['name'] = parsed_args.name
    if parsed_args.src_tenant_id:
        body['src_tenant_id'] = parsed_args.src_tenant_id
    if parsed_args.src_tenant_name:
        body['src_tenant_name'] = parsed_args.src_tenant_name
    if parsed_args.src_segment_id:
        body['src_segment_id'] = parsed_args.src_segment_id
    if parsed_args.src_segment_name:
        body['src_segment_name'] = parsed_args.src_segment_name
    if parsed_args.src_ip:
        body['src_ip'] = parsed_args.src_ip
    if parsed_args.dst_ip:
        body['dst_ip'] = parsed_args.dst_ip
    if parsed_args.expected_result:
        body['expected_result'] = parsed_args.expected_result


class ReachabilityTest(extension.NeutronClientExtension):
    resource = 'reachabilitytest'
    resource_plural = '%ss' % resource
    object_path = '/%s' % resource_plural
    resource_path = '/%s/%%s' % resource_plural
    versions = ['2.0']


class ReachabilityTestsList(extension.ClientExtensionList, ReachabilityTest):
    """List Reachability Tests."""

    shell_command = 'reachability-tests-list'
    list_columns = ['id', 'name', 'src_tenant_id', 'src_tenant_name',
                    'src_segment_id', 'src_segment_name',
                    'src_ip', 'dst_ip', 'expected_result']


class ReachabilityTestsCreate(extension.ClientExtensionCreate,
                              ReachabilityTest):
    """Create a Reachability Test."""

    shell_command = 'reachability-tests-create'
    list_columns = ['id', 'name', 'src_tenant_id', 'src_tenant_name',
                    'src_segment_id', 'src_segment_name',
                    'src_ip', 'dst_ip', 'expected_result']

    def add_known_arguments(self, parser):
        _reachabilitytest_updatable_args(parser)

    def args2body(self, parsed_args):
        body = {}
        client = self.get_client()
        _reachabilitytest_updatable_args2body(parsed_args, body, client)
        return {'reachabilitytest': body}


class ReachabilityTestsUpdate(extension.ClientExtensionUpdate,
                              ReachabilityTest):
    """Update a Reachability Test."""

    shell_command = 'reachability-tests-update'
    list_columns = ['id', 'name', 'src_tenant_id', 'src_tenant_name',
                    'src_segment_id', 'src_segment_name',
                    'src_ip', 'dst_ip', 'expected_result']

    def add_known_arguments(self, parser):
        _reachabilitytest_updatable_args(parser)

    def args2body(self, parsed_args):
        body = {}
        client = self.get_client()
        _reachabilitytest_updatable_args2body(parsed_args, body, client)
        return {'reachabilitytest': body}


class ReachabilityTestsRun(extension.ClientExtensionUpdate,
                           ReachabilityTest):
    """Run a Reachability Test."""

    shell_command = 'reachability-tests-run'
    list_columns = ['id', 'name', 'src_tenant_id', 'src_tenant_name',
                    'src_segment_id', 'src_segment_name',
                    'src_ip', 'dst_ip', 'expected_result', 'test_result',
                    'detail', 'logical_path', 'test_time']

    def args2body(self, parsed_args):
        body = {}
        body['run_test'] = True
        return {'reachabilitytest': body}


class ReachabilityTestsDelete(extension.ClientExtensionDelete,
                              ReachabilityTest):
    """Delete a Reachability Test."""

    shell_command = 'reachability-tests-delete'


class ReachabilityTestsShow(extension.ClientExtensionShow, ReachabilityTest):
    """Show a Reachability Test."""

    shell_command = 'reachability-tests-show'


# reachability quick tests
class ReachabilityQuickTest(extension.NeutronClientExtension):
    resource = 'reachabilityquicktest'
    resource_plural = '%ss' % resource
    object_path = '/%s' % resource_plural
    resource_path = '/%s/%%s' % resource_plural
    versions = ['2.0']


class ReachabilityQuickTestsList(extension.ClientExtensionList,
                                 ReachabilityQuickTest):
    """List Reachability Quick Tests."""

    shell_command = 'reachability-quick-tests-list'
    list_columns = ['id', 'name', 'src_tenant_id', 'src_tenant_name',
                    'src_segment_id', 'src_segment_name',
                    'src_ip', 'dst_ip', 'expected_result']


class ReachabilityQuickTestsCreate(extension.ClientExtensionCreate,
                                   ReachabilityQuickTest):
    """Create a Reachability Quick Test."""

    shell_command = 'reachability-quick-tests-create'
    list_columns = ['id', 'name', 'src_tenant_id', 'src_tenant_name',
                    'src_segment_id', 'src_segment_name',
                    'src_ip', 'dst_ip', 'expected_result']

    def add_known_arguments(self, parser):
        _reachabilitytest_updatable_args(parser)

    def args2body(self, parsed_args):
        body = {}
        client = self.get_client()
        _reachabilitytest_updatable_args2body(parsed_args, body, client)
        return {'reachabilityquicktest': body}


class ReachabilityQuickTestsUpdate(extension.ClientExtensionUpdate,
                                   ReachabilityQuickTest):
    """Update a Reachability Quick Test."""

    shell_command = 'reachability-quick-tests-update'
    list_columns = ['id', 'name', 'src_tenant_id', 'src_tenant_name',
                    'src_segment_id', 'src_segment_name',
                    'src_ip', 'dst_ip', 'expected_result']

    def add_known_arguments(self, parser):
        _reachabilitytest_updatable_args(parser)

    def args2body(self, parsed_args):
        body = {}
        client = self.get_client()
        _reachabilitytest_updatable_args2body(parsed_args, body, client)
        return {'reachabilityquicktest': body}


class ReachabilityQuickTestsRun(extension.ClientExtensionUpdate,
                                ReachabilityQuickTest):
    """Run a Reachability Quick Test."""

    shell_command = 'reachability-quick-tests-run'
    list_columns = ['id', 'name', 'src_tenant_id', 'src_tenant_name',
                    'src_segment_id', 'src_segment_name',
                    'src_ip', 'dst_ip', 'expected_result', 'test_result',
                    'detail', 'logical_path', 'test_time']

    def args2body(self, parsed_args):
        body = {}
        body['run_test'] = True
        return {'reachabilityquicktest': body}


class ReachabilityQuickTestsDelete(extension.ClientExtensionDelete,
                                   ReachabilityQuickTest):
    """Delete a Reachability Quick Test."""

    shell_command = 'reachability-quick-tests-delete'


class ReachabilityQuickTestsShow(extension.ClientExtensionShow,
                                 ReachabilityQuickTest):
    """Show a Reachability Quick Test."""

    shell_command = 'reachability-quick-tests-show'


# tenant policies
def _tenantpolicy_updateable_args(parser):
    parser.add_argument(
        'source',
        help=_('Source for the policy.'))
    parser.add_argument(
        '-source_port',
        help=_('Source port for the policy. Optional.'))
    parser.add_argument(
        'destination',
        help=_('Destination for the policy.'))
    parser.add_argument(
        '-destination_port',
        help=_('Destination port for the policy. Optional.'))
    parser.add_argument(
        'action',
        help=_('Action for matching traffic - permit or deny.'))
    parser.add_argument(
        '-protocol',
        help=_('Protocol for matching traffic when specifying '
               'source or destination port.'))
    parser.add_argument(
        '-nexthops',
        help=_('Optional nexthops.'))


def _tenantpolicy_updateable_args2body(parsed_args, body, client):
    if parsed_args.source:
        body['source'] = parsed_args.source
    if parsed_args.source_port:
        body['source_port'] = parsed_args.source_port
    if parsed_args.destination:
        body['destination'] = parsed_args.destination
    if parsed_args.destination_port:
        body['destination_port'] = parsed_args.destination_port
    if parsed_args.action:
        body['action'] = parsed_args.action
    if parsed_args.protocol:
        body['protocol'] = parsed_args.protocol
    if parsed_args.nexthops:
        body['nexthops'] = parsed_args.nexthops


class TenantPolicy(extension.NeutronClientExtension):
    resource = 'tenantpolicy'
    resource_plural = 'tenantpolicies'
    object_path = '/%s' % resource_plural
    resource_path = '/%s/%%s' % resource_plural
    versions = ['2.0']


class TenantPoliciesList(extension.ClientExtensionList, TenantPolicy):
    """List Tenant Policies"""

    shell_command = 'tenant-policies-list'
    list_columns = ['id', 'priority', 'source', 'source_port', 'destination',
                    'destination_port', 'action', 'nexthops']


class TenantPoliciesCreate(extension.ClientExtensionCreate, TenantPolicy):
    """Create a Tenant Policy."""

    shell_command = 'tenant-policies-create'
    list_columns = ['id', 'priority', 'source', 'source_port', 'destination',
                    'destination_port', 'action', 'protocol', 'nexthops']

    def add_known_arguments(self, parser):
        # create takes an extra argument of 'priority'
        parser.add_argument(
            'priority',
            help=_('Priority for the policy. Valid range 1 to 2999'))
        _tenantpolicy_updateable_args(parser)

    def args2body(self, parsed_args):
        body = {}
        client = self.get_client()
        # create takes an extra argument of 'priority'
        if parsed_args.priority:
            body['priority'] = parsed_args.priority
        _tenantpolicy_updateable_args2body(parsed_args, body, client)
        return {'tenantpolicy': body}


class TenantPoliciesUpdate(extension.ClientExtensionUpdate, TenantPolicy):
    """Update a Tenant Policy."""

    shell_command = 'tenant-policies-update'
    list_columns = ['id', 'priority', 'source', 'source_port', 'destination',
                    'destination_port', 'action', 'protocol', 'nexthops']

    def add_known_arguments(self, parser):
        _tenantpolicy_updateable_args(parser)

    def args2body(self, parsed_args):
        body = {}
        client = self.get_client()
        _tenantpolicy_updateable_args2body(parsed_args, body, client)
        return {'tenantpolicy': body}


class TenantPoliciesDelete(extension.ClientExtensionDelete, TenantPolicy):
    """Delete a tenant policy."""

    shell_command = 'tenant-policies-delete'


class TenantPoliciesShow(extension.ClientExtensionShow, TenantPolicy):
    """Show a tenant policy."""

    shell_command = 'tenant-policies-show'


# Force Sync Topology
class ForceSyncTopology(extension.NeutronClientExtension):
    resource = 'forcesynctopology'
    resource_plural = 'forcesynctopologies'
    object_path = '/%s' % resource_plural
    resource_path = '/%s/%%s' % resource_plural
    versions = ['2.0']


class ForceSyncTopologiesUpdate(extension.ClientExtensionUpdate,
                                ForceSyncTopology):
    """Force a complete Topology Sync to BCF controller."""

    shell_command = 'force-bcf-sync'
    list_columns = ['id', 'status']

    def args2body(self, parsed_args):
        body = {'timestamp_ms': 'now'}
        return {'forcesynctopology': body}


class ForceSyncTopologiesList(extension.ClientExtensionList,
                              ForceSyncTopology):
    """Show the status of last scheduled Topology Sync to BCF."""

    shell_command = 'bcf-sync-status'
    list_columns = ['id', 'timestamp_ms', 'timestamp_datetime', 'status']

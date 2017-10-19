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
from networking_bigswitch.plugins.bigswitch import routerrule_db
from networking_bigswitch.plugins.bigswitch import servermanager
from networking_bigswitch.plugins.bigswitch.utils import Util
from neutron.db import api as db
from neutron.db.api import _tag_retriables_as_unretriable
from neutron.db import common_db_mixin
from neutron.db import l3_db
from neutron_lib.api import validators
from neutron_lib.db import model_base
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy.orm import exc, relationship
from sqlalchemy.types import Enum

LOG = logging.getLogger(__name__)

DEFAULT_POLICY_PRIORITY = 14000
# number of fields in a router rule string
ROUTER_RULE_COMPONENT_COUNT = 5


class TenantPolicyException(n_exc.NeutronException):
    message = _("Error in tenant policy operation: %(error_msg)s")
    status = None

    def __init__(self, **kwargs):
        self.tenant = kwargs.get('error_msg')
        super(TenantPolicyException, self).__init__(**kwargs)


class TenantPolicy(model_base.BASEV2,
                   model_base.HasId,
                   model_base.HasProject):
    __tablename__ = 'bsn_tenantpolicies'
    priority = sa.Column(sa.Integer, nullable=False)
    source = sa.Column(sa.String(255), nullable=False)
    source_port = sa.Column(sa.Integer, nullable=True)
    destination = sa.Column(sa.String(255), nullable=False)
    destination_port = sa.Column(sa.Integer, nullable=True)
    protocol = sa.Column(Enum("tcp", "udp"), nullable=True)
    action = sa.Column(Enum("deny", "permit", name="action"), nullable=False)
    nexthops = relationship('TenantPolicyNextHop',
                            cascade='all,delete,delete-orphan')

    class Meta(object):
        unique_together = ('priority', 'tenant_id')


class TenantPolicyNextHop(model_base.BASEV2):
    __tablename__ = 'bsn_tenantpolicy_nexthops'
    policy_id = sa.Column(sa.String(36), sa.ForeignKey('bsn_tenantpolicies.id',
                                                       ondelete="CASCADE"),
                          primary_key=True)
    nexthop = sa.Column(sa.String(255), nullable=False, primary_key=True)


class TenantPolicyNotFound(n_exc.NotFound):
    message = _("Tenant Policy %(id)s could not be found")

class TenantPolicyExists(n_exc.NeutronException):
    message = _("Tenant policy for tenant ID %(tenant_id)s with "
                "priority %(priority)s exists")

class TenantRouterDoesNotExist(n_exc.NotFound):
    message = _("Tenant does not have a router to apply policy. "
                "Please create a router before adding policies.")


class TenantPolicyDbMixin(common_db_mixin.CommonDbMixin, l3_db.L3_NAT_db_mixin):
    # internal methods
    def _make_tenantpolicy_dict(self, tenantpolicy, fields=None):
        nexthops = [hop['nexthop'] for hop in tenantpolicy.nexthops]
        return self._fields({
            'id': tenantpolicy.id,
            'tenant_id': tenantpolicy.tenant_id,
            'priority': tenantpolicy.priority,
            'source': tenantpolicy.source,
            'source_port': tenantpolicy.source_port,
            'destination': tenantpolicy.destination,
            'destination_port': tenantpolicy.destination_port,
            'protocol': tenantpolicy.protocol,
            'action': tenantpolicy.action,
            'nexthops': nexthops}, fields)

    def _get_tenantpolicy(self, context, id):
        try:
            tenantpolicy = self._get_by_id(context, TenantPolicy, id)
        except exc.NoResultFound:
            raise TenantPolicyNotFound(id=id)
        return tenantpolicy

    def _validate_port_number(self, port_num):
        msg = None
        int_port_num = int(port_num)
        if (int_port_num not in range(0,65536)
            and int_port_num != routerrule_db.DEFAULT_RULE_PRIORITY):
            msg = _("Port number specified %s in policy not in valid "
                    "range of 1 to 65535." % port_num)
        return msg

    def _validate_nexthops(self, nexthops):
        msg = None
        seen = []
        for ip in nexthops:
            msg = validators.validate_ip_address(ip)
            if ip in seen:
                msg = _("Duplicate nexthop in rule '%s'") % ip
                return msg
            seen.append(ip)
        return msg

    def _validate_action(self, action):
        msg = None
        if action not in ['permit', 'deny']:
            msg = _("Action must be either permit or deny."
                    " '%s' was provided") % action
        return msg

    def _validate_priority(self, priority):
        msg = None
        int_priority  = int(priority)
        if (int_priority not in range(1, 3001)
            and int_priority != DEFAULT_POLICY_PRIORITY):
            msg = _("User must provide valid priority between 1 and 3000. "
                    "%s was provided.") % priority
        return msg

    def _cleanse_policy(self, policy_data):
        """
        Some values are given defaults via the REST API, but those should be
        set to NULL when going to the DB.
        This method normalizes those values.
        """
        if int(policy_data['source_port']) == 0:
            policy_data['source_port'] = None
        if int(policy_data['destination_port']) == 0:
            policy_data['destination_port'] = None
        if policy_data['protocol'] == '':
            policy_data['protocol'] = None
        return policy_data

    def _validate_and_cleanse_policy(self, context, policy_data):
        """
        Validate every field of the policy and raise exceptions if any.
        This is a simple syntax validation. Actual funtional validation is
        performed at the backend by BCF and error message returned is bubbled
        up to the Horizon GUI.

        :param context: context of the transaction
        :param policy_data: the policy resource to be validated
        """
        policy_data['tenant_id'] = Util.get_tenant_id_for_create(
            context, policy_data)
        errors = [validators.validate_subnet(policy_data['source']),
                  validators.validate_subnet(policy_data['destination']),
                  self._validate_nexthops(policy_data['nexthops']),
                  self._validate_action(policy_data['action']),
                  self._validate_priority(policy_data['priority']),
                  self._validate_port_number(policy_data['source_port']),
                  self._validate_port_number(policy_data['destination_port'])]
        errors = [m for m in errors if m]
        if errors:
            LOG.debug(errors)
            raise n_exc.InvalidInput(error_message=errors)

        return self._cleanse_policy(policy_data)

    # public CRUD methods for network templates
    def get_tenantpolicies(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        with db.context_manager.reader.using(context):
            tenantpolicies = \
                self._get_collection(context, TenantPolicy,
                                     self._make_tenantpolicy_dict,
                                     filters=filters, fields=fields)
        return tenantpolicies

    def get_tenantpolicy(self, context, id, fields=None):
        with db.context_manager.reader.using(context):
            tenantpolicy = self._get_tenantpolicy(context, id)
            return self._make_tenantpolicy_dict(tenantpolicy, fields)

    @_tag_retriables_as_unretriable
    def create_tenantpolicy(self, context, tenantpolicy):
        tenantpolicy_data = tenantpolicy['tenantpolicy']
        tenantpolicy_data = self._validate_and_cleanse_policy(
            context, tenantpolicy_data)
        with db.context_manager.writer.using(context):
            router_exists = context.session.query(l3_db.Router).filter_by(
                project_id=tenantpolicy_data['project_id']).first()
            if not router_exists:
                raise TenantRouterDoesNotExist()

            tenantpolicy = TenantPolicy(
                id=uuidutils.generate_uuid(),
                tenant_id=tenantpolicy_data['tenant_id'],
                priority=tenantpolicy_data['priority'],
                source=tenantpolicy_data['source'],
                source_port=tenantpolicy_data['source_port'],
                destination=tenantpolicy_data['destination'],
                destination_port=tenantpolicy_data['destination_port'],
                protocol=tenantpolicy_data['protocol'],
                action=tenantpolicy_data['action'],
                nexthops=[TenantPolicyNextHop(nexthop=hop)
                          for hop in tenantpolicy_data['nexthops']])
            try:
                context.session.add(tenantpolicy)
            except db_exc.DBDuplicateEntry:
                raise TenantPolicyExists(tenant_id=tenantpolicy.project_id,
                                         priority=tenantpolicy.priority)
        return self._make_tenantpolicy_dict(tenantpolicy)

    def delete_tenantpolicy(self, context, id):
        with db.context_manager.writer.using(context):
            tenantpolicy = self._get_tenantpolicy(context, id)
            context.session.delete(tenantpolicy)

    def update_tenantpolicy(self, context, servers, id, tenantpolicy):
        tenantpolicy_data = tenantpolicy['tenantpolicy']
        tenantpolicy_data = self._validate_and_cleanse_policy(
            context, tenantpolicy_data)
        with db.context_manager.writer.using(context):
            tenantpolicy = self._get_tenantpolicy(context, id)
            tenantpolicy.update(tenantpolicy_data)
        return self._make_tenantpolicy_dict(tenantpolicy)

    # handle default policy during create and delete of routers
    def _get_tenant_default_router_policy(self, tenant):
        """
        Returns a rule dictionary. Can be empty.
        """
        rules = cfg.CONF.ROUTER.tenant_default_router_rule
        default_rule = {}
        tenant_rule = {}
        for rule in rules:
            items = rule.split(':')
            # put an empty string on the end if nexthops wasn't specified
            if len(items) < ROUTER_RULE_COMPONENT_COUNT:
                items.append('')
            try:
                (tenant_id, source, destination, action, nexthops) = items
            except ValueError:
                continue
            parsed_rule = {'priority': -1,
                           'source': source,
                           'destination': destination,
                           'action': action,
                           'nexthops': [hop for hop in nexthops.split(',')
                                        if hop]}
            if tenant_id == '*':
                if default_rule:
                    # a default rule already exists
                    raise TenantPolicyException(
                        error_msg='Number of default rules exceeds the '
                                  'limit of 1!')
                default_rule = parsed_rule
            if tenant_id == tenant:
                if tenant_rule:
                    raise TenantPolicyException(
                        error_msg='Number of tenant specific router rules '
                                  'exceeds the limit of 1!')
                tenant_rule = parsed_rule
        return tenant_rule if tenant_rule else default_rule

    def create_default_policy(self, context, tenant_id, default_policy_dict):
        with db.context_manager.writer.using(context):
            existing_def_rule = (context.session.query(TenantPolicy)
                                 .filter_by(tenant_id=tenant_id)
                                 .filter_by(priority=DEFAULT_POLICY_PRIORITY))
            if existing_def_rule:
                return None
            default_policy = TenantPolicy(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                priority=DEFAULT_POLICY_PRIORITY,
                source=default_policy_dict['source'],
                source_port=None,
                destination=default_policy_dict['destination'],
                destination_port=None,
                protocol=None,
                action=default_policy_dict['action'],
                nexthops=default_policy_dict['nexthops'])
            context.session.add(default_policy)
        return self._make_tenantpolicy_dict(default_policy)

    def remove_default_policy(self, context, tenant_id):
        with db.context_manager.writer.using(context):
            upstream_routers = super(TenantPolicyDbMixin, self).get_routers(
                context, filters={"tenant_id": [tenant_id]})

            LOG.debug('upstream_routers are: %s' % upstream_routers)
            if upstream_routers:
                # there are other routers under tenant. retain all policies
                return
            # tenant doesn't have another router, remove all policies
            LOG.debug("Tenant doesn't have another router after router "
                      "deletion. Removing all policies under the tenant.")
            (context.session.query(TenantPolicy)
             .filter_by(tenant_id=tenant_id)
             .delete(synchronize_session='fetch'))
            context.session.flush()
            return

    # methods required for supporting l3_db.L3_NAT_db_mixin
    def update_router(self, context, id, router):
        with db.context_manager.writer.using(context):
            return super(TenantPolicyDbMixin, self).update_router(
                context, id, router)

    def delete_router(self, context, router_id):
        with db.context_manager.writer.using(context):
            super(TenantPolicyDbMixin, self).delete_router(context, router_id)

    def get_router(self, context, id, fields=None):
        with db.context_manager.reader.using(context):
            return super(TenantPolicyDbMixin, self).get_router(
                context, id, fields)

    def get_routers(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        with db.context_manager.reader.using(context):
            return super(TenantPolicyDbMixin, self).get_routers(
                context, filters, fields, sorts=sorts, limit=limit,
                marker=marker, page_reverse=page_reverse)

    def get_sync_data(self, context, router_ids=None, active=None):
        """Query routers and their related floating_ips, interfaces."""
        with db.context_manager.reader.using(context):
            return super(TenantPolicyDbMixin, self).get_sync_data(
                context, router_ids, active=active)

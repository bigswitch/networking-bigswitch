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
from neutron.common import exceptions
from neutron.db import common_db_mixin
from neutron.db import model_base
from oslo_db import exception as db_exc
import sqlalchemy as sa
from sqlalchemy.orm import exc, relationship
from sqlalchemy.types import Enum


class TenantPolicy(model_base.BASEV2,
                   model_base.HasId,
                   model_base.HasTenant):
    __tablename__ = 'bsn_tenantpolicies'
    priority = sa.Column(sa.Integer, nullable=False)
    source = sa.Column(sa.String(255), nullable=False)
    destination = sa.Column(sa.String(255), nullable=False)
    action = sa.Column(Enum("deny", "permit", name="action"), nullable=False)
    nexthops = relationship('TenantPolicyNextHop',
                            cascade='all,delete,delete-orphan')

    class Meta(object):
        unique_together = ('priority', 'tenant_id')


class TenantPolicyNextHop(model_base.BASEV2):
    __tablename__ = 'bsn_policy_nexthops'
    policy_id = sa.Column(sa.String(36), sa.ForeignKey('bsn_tenantpolicies.id',
                                                       ondelete="CASCADE"),
                          primary_key=True)
    nexthop = sa.Column(sa.String(255), nullable=False, primary_key=True)


class TenantPolicyNotFound(exceptions.NotFound):
    message = _("Tenant Policy %(id)s could not be found")


class TenantPolicyDbMixin(common_db_mixin.CommonDbMixin):
    # internal methods
    def _make_tenantpolicy_dict(self, tenantpolicy, fields=None):
        nexthops = [hop['nexthop'] for hop in tenantpolicy.nexthops]
        return self._fields({
            'id': tenantpolicy.id,
            'tenant_id': tenantpolicy.tenant_id,
            'priority': tenantpolicy.priority,
            'source': tenantpolicy.source,
            'destination': tenantpolicy.destination,
            'action': tenantpolicy.action,
            'nexthops': nexthops}, fields)

    def _get_tenantpolicy(self, context, id):
        try:
            tenantpolicy = self._get_by_id(context, TenantPolicy, id)
        except exc.NoResultFound:
            raise TenantPolicyNotFound(id=id)
        return tenantpolicy

    # public CRUD methods for network templates
    def get_tenantpolicies(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        tenantpolicies = \
            self._get_collection(context, TenantPolicy,
                                 self._make_tenantpolicy_dict,
                                 filters=filters, fields=fields)
        return tenantpolicies

    def get_tenantpolicy(self, context, id, fields=None):
        tenantpolicy = self._get_tenantpolicy(context, id)
        return self._make_tenantpolicy_dict(tenantpolicy, fields)

    def create_tenantpolicy(self, context, tenantpolicy):
        tenantpolicy_data = tenantpolicy['tenantpolicy']
        with context.session.begin(subtransactions=True):
            tenantpolicy = TenantPolicy(
                tenant_id=tenantpolicy_data['tenant_id'],
                priority=tenantpolicy_data['priority'],
                source=tenantpolicy_data['source'],
                destination=tenantpolicy_data['destination'],
                action=tenantpolicy_data['action'],
                nexthops=[TenantPolicyNextHop(nexthop=hop)
                          for hop in tenantpolicy_data['nexthops']])
            context.session.add(tenantpolicy)
        return self._make_tenantpolicy_dict(tenantpolicy)

    def delete_tenantpolicy(self, context, id):
        with context.session.begin(subtransactions=True):
            tenantpolicy = self._get_tenantpolicy(context, id)
            context.session.delete(tenantpolicy)

    def update_tenantpolicy(self, context, id, tenantpolicy):
        tenantpolicy_data = tenantpolicy['tenantpolicy']
        with context.session.begin(subtransactions=True):
            tenantpolicy = self._get_tenantpolicy(context, id)
            tenantpolicy.update(tenantpolicy_data)
        return self._make_tenantpolicy_dict(tenantpolicy)

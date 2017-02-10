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
from neutron.db import common_db_mixin
from neutron_lib.db import model_base
from neutron_lib import exceptions
from oslo_db import exception as db_exc
import sqlalchemy as sa
from sqlalchemy.orm import exc


class NetworkTemplate(model_base.BASEV2, model_base.HasId):
    __tablename__ = 'networktemplates'
    __table_args__ = {'extend_existing': True}
    body = sa.Column(sa.Text(), nullable=False)
    name = sa.Column(sa.String(255), nullable=False, unique=True)


class NetworkTemplateNotFound(exceptions.NotFound):
    message = _("Network Template %(id)s could not be found")


class NetworkTemplateDbMixin(common_db_mixin.CommonDbMixin):
    # internal methods
    def _make_networktemplate_dict(self, template, fields=None):
        return self._fields({
            'id': template.id,
            'body': template.body,
            'name': template.name}, fields)

    def _get_networktemplate(self, context, id):
        try:
            networktemplate = self._get_by_id(context, NetworkTemplate, id)
        except exc.NoResultFound:
            raise NetworkTemplateNotFound(id=id)
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


class NetworkTemplateAssignment(model_base.BASEV2,
                                model_base.HasId,
                                model_base.HasProject):
    __tablename__ = 'networktemplateassignments'
    __table_args__ = {'extend_existing': True}
    template_id = sa.Column(sa.Integer, sa.ForeignKey('networktemplates.id'),
                            nullable=False)
    stack_id = sa.Column(sa.String(255), nullable=False)
    template = sa.orm.relationship("NetworkTemplate")


class NetworkTemplateAssignmentNotFound(exceptions.NotFound):
    message = _("Network Template Assignment %(id)s could not be found")


class NetworkTemplateAssignmentExists(exceptions.NeutronException):
    message = \
        _("Network Template Assignment for tenant ID %(tenant_id)s exists")


class NetworkTemplateAssignmentDbMixin(common_db_mixin.CommonDbMixin):
    # internal methods
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
            raise NetworkTemplateAssignmentNotFound(id=id)
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
                raise NetworkTemplateAssignmentExists(
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

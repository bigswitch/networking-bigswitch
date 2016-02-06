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

from neutron.common import exceptions
from neutron.db import model_base
from neutron.i18n import _
import sqlalchemy as sa


class NetworkTemplate(model_base.BASEV2, model_base.HasId,
                      model_base.HasTenant):
    __tablename__ = 'networktemplates'
    __table_args__ = {'extend_existing': True}
    body = sa.Column(sa.Text(), nullable=False)
    name = sa.Column(sa.String(255), nullable=False, unique=True)


class NetworkTemplateNotFound(exceptions.NotFound):
    message = _("Network Template %(id)s could not be found")


class NetworkTemplateAssignment(model_base.BASEV2, model_base.HasId):
    __tablename__ = 'networktemplateassignments'
    __table_args__ = {'extend_existing': True}
    tenant_id = sa.Column(sa.String(255), nullable=False, unique=True)
    template_id = sa.Column(sa.Integer, sa.ForeignKey('networktemplates.id'),
                            nullable=False)
    stack_id = sa.Column(sa.String(255), nullable=False)
    template = sa.orm.relationship("NetworkTemplate")


class NetworkTemplateAssignmentNotFound(exceptions.NotFound):
    message = _("Network Template Assignment %(id)s could not be found")


class NetworkTemplateAssignmentExists(exceptions.NeutronException):
    message = \
        _("Network Template Assignment for tenant ID %(tenant_id)s exists")

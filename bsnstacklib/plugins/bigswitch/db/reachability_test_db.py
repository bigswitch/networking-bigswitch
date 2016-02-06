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
from oslo_serialization import jsonutils

import sqlalchemy as sa
from sqlalchemy.dialects.mysql.base import VARCHAR
from sqlalchemy.types import Enum, TIMESTAMP, TypeDecorator


class JSONEncodedDict(TypeDecorator):
    """Represents an immutable structure as a json-encoded string.
    Usage::
        JSONEncodedDict(255)
    """
    impl = VARCHAR

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = jsonutils.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = jsonutils.loads(value)
        return value


class ReachabilityTest(model_base.BASEV2,
                       model_base.HasId,
                       model_base.HasTenant):
    '''
    A table to store user configured reachability tests.
    '''
    __tablename__ = 'reachabilitytest'
    name = sa.Column(sa.String(64), nullable=False, unique=True)
    src_tenant_name = sa.Column(sa.String(255), nullable=False)
    src_segment_name = sa.Column(sa.String(255), nullable=False)
    src_ip = sa.Column(sa.String(16), nullable=False)
    dst_ip = sa.Column(sa.String(16), nullable=False)
    expected_result = sa.Column(Enum("reached destination", "dropped by route",
                                     "dropped by policy",
                                     "dropped due to private segment",
                                     "packet in", "forwarded", "dropped",
                                     "multiple sources",
                                     "unsupported", "invalid input",
                                     name="expected_result"), nullable=False)
    test_time = sa.Column(TIMESTAMP(timezone=True), nullable=True)
    test_result = sa.Column(Enum("pass", "fail", "pending"),
                            default="pending", nullable=False)
    detail = sa.Column(JSONEncodedDict(8192), nullable=True)
    run_test = sa.Column(sa.Boolean, nullable=False, default=False)

    def get_connection_source(self):
        source = {}
        source['tenant'] = self.src_tenant_name
        source['segment'] = self.src_segment_name
        source['ip'] = self.src_ip
        return source

    def get_connection_destination(self):
        destination = {}
        destination['ip'] = self.dst_ip
        return destination


class ReachabilityTestNotFound(exceptions.NotFound):
    message = _("Reachability Test %(id)s could not be found")


class ReachabilityQuickTest(model_base.BASEV2,
                            model_base.HasId,
                            model_base.HasTenant):
    '''
    A table to store user configured reachability quick tests.
    '''
    __tablename__ = 'reachabilityquicktest'
    name = sa.Column(sa.String(64), nullable=False, unique=True)
    src_tenant_name = sa.Column(sa.String(255), nullable=False)
    src_segment_name = sa.Column(sa.String(255), nullable=False)
    src_ip = sa.Column(sa.String(16), nullable=False)
    dst_ip = sa.Column(sa.String(16), nullable=False)
    expected_result = sa.Column(Enum("reached destination", "dropped by route",
                                     "dropped by policy",
                                     "dropped due to private segment",
                                     "packet in", "forwarded", "dropped",
                                     "multiple sources",
                                     "unsupported", "invalid input",
                                     name="expected_result"), nullable=False)
    test_time = sa.Column(TIMESTAMP(timezone=True), nullable=True)
    test_result = sa.Column(Enum("pass", "fail", "pending"),
                            default="pending", nullable=False)
    detail = sa.Column(JSONEncodedDict(8192), nullable=True)
    run_test = sa.Column(sa.Boolean, nullable=False, default=False)
    save_test = sa.Column(sa.Boolean, nullable=False, default=False)

    def get_connection_source(self):
        source = {}
        source['tenant'] = self.src_tenant_name
        source['segment'] = self.src_segment_name
        source['ip'] = self.src_ip
        return source

    def get_connection_destination(self):
        destination = {}
        destination['ip'] = self.dst_ip
        return destination


class ReachabilityQuickTestNotFound(exceptions.NotFound):
    message = _("Reachability Quick Test %(id)s could not be found")

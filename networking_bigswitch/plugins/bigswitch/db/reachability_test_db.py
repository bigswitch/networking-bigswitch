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
from networking_bigswitch.plugins.bigswitch.utils import Util
from neutron.db import common_db_mixin
from neutron_lib.db import model_base
from neutron_lib import exceptions
from oslo_serialization import jsonutils

import sqlalchemy as sa
from sqlalchemy.dialects.mysql.base import VARCHAR
from sqlalchemy.orm import exc
from sqlalchemy.types import Enum, TIMESTAMP, TypeDecorator


class JSONEncodedDict(TypeDecorator):
    """encoded JSON dict

    Represents an immutable structure as a json-encoded string.
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
                       model_base.HasProject):
    """Reachability Test

    A table to store user configured reachability tests.
    """
    __tablename__ = 'reachabilitytest'
    name = sa.Column(sa.String(64), nullable=False, unique=True)
    src_tenant_id = sa.Column(sa.String(length=36), nullable=True)
    src_tenant_name = sa.Column(sa.String(255), nullable=False)
    src_segment_id = sa.Column(sa.String(length=36), nullable=True)
    src_segment_name = sa.Column(sa.String(255), nullable=True)
    src_ip = sa.Column(sa.String(16), nullable=False)
    dst_ip = sa.Column(sa.String(16), nullable=False)
    expected_result = sa.Column(Enum("dropped by route",
                                     "dropped by policy",
                                     "not permitted by security groups",
                                     "dropped due to private segment",
                                     "dropped due to loop",
                                     "packet in",
                                     "forwarded",
                                     "dropped",
                                     "unspecified source",
                                     "unsupported",
                                     "invalid input",
                                     "inconsistent status",
                                     "no traffic detected",
                                     name="expected_result"), nullable=False)
    test_time = sa.Column(TIMESTAMP(timezone=True), nullable=True)
    test_result = sa.Column(Enum("pass", "fail", "pending"),
                            default="pending", nullable=False)
    detail = sa.Column(JSONEncodedDict(8192), nullable=True)
    logical_path = sa.Column(JSONEncodedDict(8192), nullable=True)
    run_test = sa.Column(sa.Boolean, nullable=False, default=False)

    def get_connection_source(self, unicode_mode=False):
        source = {}
        if unicode_mode:
            if not self.src_tenant_id:
                raise ReachabilityTestUnicodeTenantIdMissing(
                    test_name=self.name)
            source['tenant'] = self.src_tenant_id
            if not self.src_segment_id:
                raise ReachabilityTestUnicodeSegmentIdMissing(
                    test_name=self.name)
            source['segment'] = self.src_segment_id
        else:
            source['tenant'] = Util.format_resource_name(self.src_tenant_name)
            if not self.src_segment_name:
                raise ReachabilityTestSegmentNameMissing(test_name=self.name)
            source['segment'] = Util.format_resource_name(
                self.src_segment_name)
        source['ip'] = self.src_ip
        return source

    def get_connection_destination(self):
        destination = {}
        destination['ip'] = self.dst_ip
        return destination


class ReachabilityTestNotFound(exceptions.NotFound):
    message = _("Reachability Test %(id)s could not be found")


class ReachabilityTestUnicodeTenantIdMissing(exceptions.NeutronException):
    message = _("Source Tenant ID is required when Unicode is ENABLED. "
                "Please update Test %(test_name)s.")


class ReachabilityTestUnicodeSegmentIdMissing(exceptions.NeutronException):
    message = _("Source Segment ID is required when Unicode is ENABLED. "
                "Please update Test %(test_name)s.")


class ReachabilityTestSegmentNameMissing(exceptions.NeutronException):
    message = _("Source Segment Name is required when Unicode is DISABLED. "
                "Please recreate the network and update Test %(test_name)s.")


class ReachabilityTestDbMixin(common_db_mixin.CommonDbMixin):
    # internal methods
    def _make_reachabilitytest_dict(self, reachabilitytest, fields=None):
        return self._fields({
            'id': reachabilitytest.id,
            'tenant_id': reachabilitytest.tenant_id,
            'name': reachabilitytest.name,
            'src_tenant_id': reachabilitytest.src_tenant_id,
            'src_tenant_name': reachabilitytest.src_tenant_name,
            'src_segment_id': reachabilitytest.src_segment_id,
            'src_segment_name': reachabilitytest.src_segment_name,
            'src_ip': reachabilitytest.src_ip,
            'dst_ip': reachabilitytest.dst_ip,
            'expected_result': reachabilitytest.expected_result,
            'test_time': reachabilitytest.test_time,
            'test_result': reachabilitytest.test_result,
            'detail': reachabilitytest.detail,
            'logical_path': reachabilitytest.logical_path,
            'run_test': reachabilitytest.run_test}, fields)

    def _get_reachabilitytest(self, context, id):
        try:
            reachabilitytest = self._get_by_id(context, ReachabilityTest, id)
        except exc.NoResultFound:
            raise ReachabilityTestNotFound(id=id)
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
                src_tenant_id=reachabilitytest_data.get('src_tenant_id'),
                src_tenant_name=reachabilitytest_data['src_tenant_name'],
                src_segment_id=reachabilitytest_data.get('src_segment_id'),
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
                src_tenant_id=reachabilitytest_data.get('src_tenant_id'),
                src_tenant_name=reachabilitytest_data['src_tenant_name'],
                src_segment_id=reachabilitytest_data.get('src_segment_id'),
                src_segment_name=reachabilitytest_data['src_segment_name'],
                src_ip=reachabilitytest_data['src_ip'],
                dst_ip=reachabilitytest_data['dst_ip'],
                expected_result=reachabilitytest_data['expected_result'],
                test_result=reachabilitytest_data['test_result'],
                detail=reachabilitytest_data['detail'],
                test_time=reachabilitytest_data['test_time'])
            context.session.add(reachabilitytest)
        return self._make_reachabilitytest_dict(reachabilitytest)

    def update_reachabilitytest(self, context, id, reachabilitytest):
        reachabilitytest_data = reachabilitytest['reachabilitytest']
        with context.session.begin(subtransactions=True):
            reachabilitytest = self._get_reachabilitytest(context, id)
            reachabilitytest.update(reachabilitytest_data)
        return self._make_reachabilitytest_dict(reachabilitytest)

    def delete_reachabilitytest(self, context, id):
        with context.session.begin(subtransactions=True):
            reachabilitytest = self._get_reachabilitytest(context, id)
            context.session.delete(reachabilitytest)


class ReachabilityQuickTest(model_base.BASEV2,
                            model_base.HasId,
                            model_base.HasProject):
    """Reachability Quick Test

    A table to store user configured reachability quick tests.
    """
    __tablename__ = 'reachabilityquicktest'
    name = sa.Column(sa.String(64), nullable=False, unique=True)
    src_tenant_id = sa.Column(sa.String(length=36), nullable=True)
    src_tenant_name = sa.Column(sa.String(255), nullable=False)
    src_segment_id = sa.Column(sa.String(length=36), nullable=True)
    src_segment_name = sa.Column(sa.String(255), nullable=True)
    src_ip = sa.Column(sa.String(16), nullable=False)
    dst_ip = sa.Column(sa.String(16), nullable=False)
    expected_result = sa.Column(Enum("dropped by route",
                                     "dropped by policy",
                                     "not permitted by security groups",
                                     "dropped due to private segment",
                                     "dropped due to loop",
                                     "packet in",
                                     "forwarded",
                                     "dropped",
                                     "unspecified source",
                                     "unsupported",
                                     "invalid input",
                                     "inconsistent status",
                                     "no traffic detected",
                                     name="expected_result"), nullable=False)
    test_time = sa.Column(TIMESTAMP(timezone=True), nullable=True)
    test_result = sa.Column(Enum("pass", "fail", "pending"),
                            default="pending", nullable=False)
    detail = sa.Column(JSONEncodedDict(8192), nullable=True)
    logical_path = sa.Column(JSONEncodedDict(8192), nullable=True)
    run_test = sa.Column(sa.Boolean, nullable=False, default=False)
    save_test = sa.Column(sa.Boolean, nullable=False, default=False)

    def get_connection_source(self, unicode_mode=False):
        source = {}
        if unicode_mode:
            if not self.src_tenant_id:
                raise ReachabilityTestUnicodeTenantIdMissing(
                    test_name=self.name)
            source['tenant'] = self.src_tenant_id
            if not self.src_segment_id:
                raise ReachabilityTestUnicodeSegmentIdMissing(
                    test_name=self.name)
            source['segment'] = self.src_segment_id
        else:
            source['tenant'] = Util.format_resource_name(self.src_tenant_name)
            if not self.src_segment_name:
                raise ReachabilityTestSegmentNameMissing(
                    test_name=self.name)
            source['segment'] = Util.format_resource_name(
                self.src_segment_name)
        source['ip'] = self.src_ip
        return source

    def get_connection_destination(self):
        destination = {}
        destination['ip'] = self.dst_ip
        return destination


class ReachabilityQuickTestDbMixin(common_db_mixin.CommonDbMixin):
    # internal methods
    def _make_reachabilityquicktest_dict(self, reachabilityquicktest,
                                         fields=None):
        return self._fields({
            'id': reachabilityquicktest.id,
            'tenant_id': reachabilityquicktest.tenant_id,
            'name': reachabilityquicktest.name,
            'src_tenant_id': reachabilityquicktest.src_tenant_id,
            'src_tenant_name': reachabilityquicktest.src_tenant_name,
            'src_segment_id': reachabilityquicktest.src_segment_id,
            'src_segment_name': reachabilityquicktest.src_segment_name,
            'src_ip': reachabilityquicktest.src_ip,
            'dst_ip': reachabilityquicktest.dst_ip,
            'expected_result': reachabilityquicktest.expected_result,
            'test_time': reachabilityquicktest.test_time,
            'test_result': reachabilityquicktest.test_result,
            'detail': reachabilityquicktest.detail,
            'logical_path': reachabilityquicktest.logical_path,
            'run_test': reachabilityquicktest.run_test}, fields)

    def _get_reachabilityquicktest(self, context, id):
        try:
            reachabilityquicktest = self._get_by_id(
                context, ReachabilityQuickTest, id)
        except exc.NoResultFound:
            raise ReachabilityTestNotFound(id=id)
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
                src_tenant_id=quicktest_data.get('src_tenant_id'),
                src_tenant_name=quicktest_data['src_tenant_name'],
                src_segment_id=quicktest_data.get('src_segment_id'),
                src_segment_name=quicktest_data['src_segment_name'],
                src_ip=quicktest_data['src_ip'],
                dst_ip=quicktest_data['dst_ip'],
                expected_result=quicktest_data['expected_result'])
            context.session.add(reachabilityquicktest)
        return self._make_reachabilityquicktest_dict(reachabilityquicktest)

    def update_reachabilityquicktest(self, context, id, reachabilityquicktest):
        reachabilityquicktest_data = \
            reachabilityquicktest['reachabilityquicktest']
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

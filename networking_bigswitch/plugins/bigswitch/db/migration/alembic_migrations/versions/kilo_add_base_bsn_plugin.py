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

"""add base BSN plugin

Revision ID: kilo
Revises:
Create Date: 2016-01-04 17:59:34.311932

"""

# revision identifiers, used by Alembic.
revision = 'kilo'
down_revision = None
branch_labels = None
depends_on = None

from alembic import op
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


def upgrade():
    op.create_table(
        'networktemplates',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('name', sa.String(255), nullable=False, unique=True))

    op.create_table(
        'networktemplateassignments',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('tenant_id', sa.String(255), nullable=False, unique=True),
        sa.Column('stack_id', sa.String(255), nullable=False),
        sa.Column('template_id', sa.String(length=36),
                  sa.ForeignKey('networktemplates.id'),
                  nullable=False),)

    op.create_table(
        'reachabilitytest',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('tenant_id', sa.String(255), nullable=False),
        sa.Column('name', sa.String(64), nullable=False, unique=True),
        sa.Column('src_tenant_name', sa.String(255), nullable=False),
        sa.Column('src_segment_name', sa.String(255), nullable=False),
        sa.Column('src_ip', sa.String(16), nullable=False),
        sa.Column('dst_ip', sa.String(16), nullable=False),
        sa.Column('expected_result',
                  Enum("reached destination", "dropped by route",
                       "dropped by policy", "dropped due to private segment",
                       "packet in", "forwarded", "dropped", "multiple sources",
                       "unsupported", "invalid input", name="expected_result"),
                  nullable=False),
        sa.Column('test_time', TIMESTAMP(timezone=True), nullable=True),
        sa.Column('test_result', Enum("pass", "fail", "pending"),
                  nullable=False, default="pending"),
        sa.Column('detail', JSONEncodedDict(8192), nullable=True),
        sa.Column('run_test', sa.Boolean, nullable=False, default=False))

    op.create_table(
        'reachabilityquicktest',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('tenant_id', sa.String(255), nullable=False),
        sa.Column('name', sa.String(64), nullable=False, unique=True),
        sa.Column('src_tenant_name', sa.String(255), nullable=False),
        sa.Column('src_segment_name', sa.String(255), nullable=False),
        sa.Column('src_ip', sa.String(16), nullable=False),
        sa.Column('dst_ip', sa.String(16), nullable=False),
        sa.Column('expected_result',
                  Enum("reached destination", "dropped by route",
                       "dropped by policy", "dropped due to private segment",
                       "packet in", "forwarded", "dropped", "multiple sources",
                       "unsupported", "invalid input", name="expected_result"),
                  nullable=False),
        sa.Column('test_time', TIMESTAMP(timezone=True), nullable=True),
        sa.Column('test_result', Enum("pass", "fail", "pending"),
                  nullable=False, default="pending"),
        sa.Column('detail', JSONEncodedDict(8192), nullable=True),
        sa.Column('run_test', sa.Boolean, nullable=False, default=False),
        sa.Column('save_test', sa.Boolean, nullable=False, default=False))

    op.create_table(
        'bsn_routerrules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('priority', sa.Integer(), nullable=False),
        sa.Column('source', sa.String(length=64), nullable=False),
        sa.Column('destination', sa.String(length=64), nullable=False),
        sa.Column('action', sa.String(length=10), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('priority', 'router_id', name='unique_prio_rid'))

    op.create_table(
        'bsn_nexthops',
        sa.Column('rule_id', sa.Integer(), nullable=False),
        sa.Column('nexthop', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['rule_id'], ['bsn_routerrules.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('rule_id', 'nexthop'))


def downgrade():
    pass

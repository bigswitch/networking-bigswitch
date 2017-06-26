# Copyright 2017, Big Switch Networks
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
"""tenant policy plugin

Revision ID: 66cc6bc031de
Revises: f774eae87144
Create Date: 2017-06-27 12:10:07.018858

"""

# revision identifiers, used by Alembic.
revision = '66cc6bc031de'
down_revision = 'f774eae87144'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa
from sqlalchemy.types import Enum


def upgrade():
    op.create_table(
        'bsn_tenantpolicies',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(255), nullable=True),
        sa.Column('priority', sa.Integer(), nullable=False),
        sa.Column('source', sa.String(length=64), nullable=False),
        sa.Column('source_port', sa.Integer(), nullable=True),
        sa.Column('destination', sa.String(length=64), nullable=False),
        sa.Column('destination_port', sa.Integer(), nullable=True),
        sa.Column('protocol', Enum("tcp", "udp"), nullable=False),
        sa.Column('action', sa.String(length=10), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('priority', 'project_id', name='unique_prio_tid'))

    op.create_table(
        'bsn_tenantpolicy_nexthops',
        sa.Column('policy_id', sa.String(length=36), nullable=False),
        sa.Column('nexthop', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['policy_id'], ['bsn_tenantpolicies.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_id', 'nexthop'))


def downgrade():
    pass

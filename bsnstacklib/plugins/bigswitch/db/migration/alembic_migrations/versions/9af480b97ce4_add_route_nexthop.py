# Copyright 2016, Big Switch Networks
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

"""add route nexthop

Revision ID: 9af480b97ce4
Revises: 1ef57200f387
Create Date: 2016-07-11 15:32:32.283665

"""

# revision identifiers, used by Alembic.
revision = '9af480b97ce4'
down_revision = '1ef57200f387'
branch_labels = None
depends_on = None

import sqlalchemy as sa

from alembic import op


def upgrade():
    op.create_table(
        'bsn_routes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=True),
        sa.Column('destination', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('router_id', 'destination',
                            name='unique_rid_dest'))

    op.create_table(
        'bsn_routenexthops',
        sa.Column('route_id', sa.Integer(), nullable=False),
        sa.Column('nexthop', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['route_id'], ['bsn_routes.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('route_id', 'nexthop'))


def downgrade():
    pass

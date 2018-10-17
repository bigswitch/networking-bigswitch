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

"""add tenant/segment id for reachability tests

Revision ID: 938c3e0e2029
Revises:
Create Date: 2018-10-15 11:04:57.644914

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '938c3e0e2029'
down_revision = '7db8cd315b95'
branch_labels = None
depends_on = None


def upgrade():
    # reachability test
    # segment name can be empty for uuid based schema (supported queens/5.0)
    op.alter_column(
        table_name='reachabilitytest',
        column_name='src_segment_name',
        existing_type=sa.String(255, convert_unicode=True),
        nullable=True)

    # If unicode is off, tenant id can be empty
    op.add_column('reachabilitytest',
                  sa.Column('src_tenant_id', sa.String(36), nullable=True))

    # If unicode is off, segment id can be empty
    op.add_column('reachabilitytest',
                  sa.Column('src_segment_id', sa.String(36), nullable=True))

    # reachability quick test
    # segment name can be empty for uuid based schema (supported queens/5.0)
    op.alter_column(
        table_name='reachabilityquicktest',
        column_name='src_segment_name',
        existing_type=sa.String(255),
        nullable=True)

    # If unicode is off, tenant id can be empty
    op.add_column('reachabilityquicktest',
                  sa.Column('src_tenant_id', sa.String(36), nullable=True))

    # If unicode is off, segment id can be empty
    op.add_column('reachabilityquicktest',
                  sa.Column('src_segment_id', sa.String(36), nullable=True))


def downgrade():
    pass

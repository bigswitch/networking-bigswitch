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

"""testpath modify uniq constraint

Revision ID: 1ef57200f387
Revises: 1086543dfc0f
Create Date: 2016-06-18 14:04:20.625692

"""

# revision identifiers, used by Alembic.
revision = '1ef57200f387'
down_revision = '1086543dfc0f'
branch_labels = None
depends_on = None

from alembic import op


def upgrade():
    op.drop_constraint(
        'name', 'reachabilitytest',
        type_="unique")

    op.create_unique_constraint(
        constraint_name="unique_name",
        table_name="reachabilitytest",
        columns=['name', 'tenant_id'])


def downgrade():
    pass

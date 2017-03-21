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
"""support multiple logical routers

Revision ID: 34f888285695
Revises: e6cb930d25de
Create Date: 2017-01-17 04:44:12.582865

"""

# revision identifiers, used by Alembic.
revision = '34f888285695'
down_revision = '1ef57200f387'
branch_labels = None
depends_on = None

from alembic import op
from oslo_db.exception import DBError
import sqlalchemy as sa


def upgrade():
    # add column tenant_id. allow nullable until we add values
    try:
        op.add_column('bsn_routerrules',
                      sa.Column('tenant_id', sa.String(255), nullable=True))
    except DBError as e:
        if ('Duplicate' not in e.message):
            raise e

    # populate it with the correct tenant_id from upstream table routers
    connection = op.get_bind()
    connection.execute("UPDATE bsn_routerrules bsn "
                       "INNER JOIN routers upstream "
                       "ON bsn.router_id = upstream.id "
                       "SET bsn.tenant_id = upstream.project_id;")

    # set the tenant_id column nullable to false
    op.alter_column('bsn_routerrules', 'tenant_id',
                    existing_type=sa.String(length=255), nullable=False)
    # update default rule priority. only to be executed if the constraint
    # addition succeeds in the previous statement.
    connection.execute("UPDATE bsn_routerrules "
                       "SET priority = 14000 "
                       "WHERE priority = 3000;")

    # drop the existing unique key constraint
    try:
        op.drop_constraint('unique_prio_rid', 'bsn_routerrules',
                           type_='unique')
    except Exception as e:
        pass

    # create unique key constraint named 'unique_prio_tid' on table
    # 'bsn_routerrules' including columns 'tenant_id' and 'priority'
    try:
        op.create_index('unique_prio_tid', 'bsn_routerrules',
                        ['tenant_id', 'priority'], unique=True)
    except Exception as e:
        pass


def downgrade():
    pass

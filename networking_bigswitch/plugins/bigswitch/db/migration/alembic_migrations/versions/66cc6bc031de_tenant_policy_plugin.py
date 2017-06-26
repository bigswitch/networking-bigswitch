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
down_revision = '2dc6f1b7c0a1'
branch_labels = None
depends_on = None

from alembic import op
from oslo_utils import uuidutils
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
        sa.Column('protocol', Enum("tcp", "udp"), nullable=True),
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

    # copy old rule data

    # get SQL connection
    connection = op.get_bind()

    # define SQL commands to get table data
    FETCH_ROUTERRULE_SQL = ("SELECT * FROM bsn_routerrules")
    INSERT_ROUTERRULE_SQL = (
        'INSERT INTO bsn_tenantpolicies (id, project_id, priority, source, '
        'destination, action) '
        'VALUES (\'%(id)s\', \'%(project_id)s\', \'%(priority)s\', '
        '\'%(source)s\', \'%(destination)s\', \'%(action)s\');')
    FETCH_NEXTHOPS_SQL = ('SELECT * FROM bsn_nexthops '
                          'WHERE rule_id = \'%(old_id)s\'')
    INSERT_NEXTHOPS_SQL = (
        'INSERT INTO bsn_tenantpolicy_nexthops (policy_id, nexthop) '
        'VALUES (\'%(policy_id)s\', \'%(nexthop)s\')')

    res = connection.execute(FETCH_ROUTERRULE_SQL)
    routerrules = res.fetchall()
    for rule in routerrules:
        # insert into new table
        # update integer ID with UUID based ID
        old_id = rule[0]
        id = uuidutils.generate_uuid()
        project_id = rule[6]
        priority = rule[1]
        source = rule[2]
        destination = rule[3]
        action = rule[4]
        CMD_EXEC = (INSERT_ROUTERRULE_SQL %
                    {'id': id, 'project_id': project_id, 'priority': priority,
                     'source': source, 'destination': destination,
                     'action': action})
        connection.execute(CMD_EXEC)

        # now insert the nexthops
        res_nexthops = connection.execute(FETCH_NEXTHOPS_SQL %
                                          {'old_id': old_id})
        nexthops = res_nexthops.fetchall()
        for nexthop in nexthops:
            CMD_EXEC = (INSERT_NEXTHOPS_SQL %
                        {'policy_id': id, 'nexthop': nexthop[1]})
            connection.execute(CMD_EXEC)

    # drop old tables
    # (not just yet. in the next minor BCF release)
    # op.drop_table('bsn_nexthops')
    # op.drop_table('bsn_routerrules')


def downgrade():
    pass

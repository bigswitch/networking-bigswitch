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
"""testpath add column logical path

Revision ID: 2dc6f1b7c0a1
Revises: f774eae87144
Create Date: 2017-10-12 14:12:51.467479

"""

# revision identifiers, used by Alembic.
revision = '2dc6f1b7c0a1'
down_revision = 'f774eae87144'
branch_labels = None
depends_on = None

import sqlalchemy as sa

from alembic import op
from oslo_serialization import jsonutils
from sqlalchemy.dialects.mysql.base import VARCHAR
from sqlalchemy.types import TypeDecorator


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
    op.add_column('reachabilitytest',
                  sa.Column('logical_path', JSONEncodedDict(8192),
                            nullable=True))
    op.add_column('reachabilityquicktest',
                  sa.Column('logical_path', JSONEncodedDict(8192),
                            nullable=True))


def downgrade():
    pass

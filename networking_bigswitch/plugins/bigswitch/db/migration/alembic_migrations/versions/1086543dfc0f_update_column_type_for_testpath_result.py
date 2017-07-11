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

"""update column type for testpath result

Revision ID: 1086543dfc0f
Revises: kilo
Create Date: 2016-04-25 11:54:44.646798

"""

# revision identifiers, used by Alembic.
revision = '1086543dfc0f'
down_revision = 'kilo'
branch_labels = None
depends_on = None

from alembic import op
from sqlalchemy.types import Enum


def upgrade():
    op.alter_column(
        'reachabilitytest', 'expected_result',
        type_=Enum("dropped by route",
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
                   name="expected_result"),
        existing_nullable=False)

    op.alter_column(
        'reachabilityquicktest', 'expected_result',
        type_=Enum("dropped by route",
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
                   name="expected_result"),
        existing_nullable=False)


def downgrade():
    pass

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

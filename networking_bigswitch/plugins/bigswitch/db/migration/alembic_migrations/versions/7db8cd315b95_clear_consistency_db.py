"""clear consistency_db

Revision ID: 7db8cd315b95
Revises: 2dc6f1b7c0a1
Create Date: 2018-05-08 12:38:56.871617

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '7db8cd315b95'
down_revision = '2dc6f1b7c0a1'
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    connection.execute("TRUNCATE TABLE consistencyhashes;")

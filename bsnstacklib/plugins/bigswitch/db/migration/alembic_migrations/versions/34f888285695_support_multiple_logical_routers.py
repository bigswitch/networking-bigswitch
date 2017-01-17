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
import sqlalchemy as sa


def upgrade():
    # add column tenant_id. allow nullable until we add values
    op.add_column('bsn_routerrules',
                  sa.Column('tenant_id', sa.String(255), nullable=True))

    # populate it with the correct tenant_id from upstream table routers
    connection = op.get_bind()
    connection.execute("UPDATE bsn_routerrules bsn "
                       "INNER JOIN routers upstream "
                       "ON bsn.router_id = upstream.id "
                       "SET bsn.tenant_id = upstream.tenant_id;")

    # set the tenant_id column nullable to false
    op.alter_column('bsn_routerrules', 'tenant_id',
                    existing_type=sa.String(length=255), nullable=False)

    # drop the existing unique key constraint
    op.drop_constraint('unique_prio_rid', 'bsn_routerrules', type_='unique')

    # create unique key constraint named 'unique_prio_tid' on table
    # 'bsn_routerrules' including columns 'tenant_id' and 'priority'
    op.create_index('unique_prio_tid', 'bsn_routerrules',
                    ['tenant_id', 'priority'], unique=True)


def downgrade():
    pass

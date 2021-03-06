"""Add password algo column

Revision ID: bf6f9ce1c34b
Revises: 8b7bfbb170e1
Create Date: 2016-04-02 23:41:15.579798

"""

# revision identifiers, used by Alembic.
revision = 'bf6f9ce1c34b'
down_revision = '8b7bfbb170e1'

from alembic import op
import sqlalchemy as sa
from shapr import config

def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('password_algo', sa.String(),
        nullable=False, server_default=config.PASSWORD_ALGO))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'password_algo')
    ### end Alembic commands ###

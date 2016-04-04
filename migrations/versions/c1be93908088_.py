"""Add totp field

Revision ID: c1be93908088
Revises: bf6f9ce1c34b
Create Date: 2016-04-03 22:23:07.112907

"""

# revision identifiers, used by Alembic.
revision = 'c1be93908088'
down_revision = 'bf6f9ce1c34b'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('totp_key', sa.String(), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'totp_key')
    ### end Alembic commands ###

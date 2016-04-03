"""Add password history validation

Revision ID: c6c882e27d89
Revises: 0b3323df59c6
Create Date: 2016-04-02 21:45:47.781436

"""

# revision identifiers, used by Alembic.
revision = 'c6c882e27d89'
down_revision = '0b3323df59c6'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_table('password_history',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('password', sa.String(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.add_column('settings', sa.Column('password_history', sa.Integer(),
                                        nullable=False, server_default='1'))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('settings', 'password_history')
    op.drop_table('password_history')
    ### end Alembic commands ###
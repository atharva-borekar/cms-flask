"""Added user and sslcertificate tables

Revision ID: 350f6cc3152e
Revises: 
Create Date: 2023-04-11 14:54:47.959640

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '350f6cc3152e'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('sslcertificate',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('certificate', sa.String(length=600), nullable=True),
    sa.Column('created_by', sa.Integer(), nullable=True),
    sa.Column('test', sa.String(length=200), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=50), nullable=False),
    sa.Column('username', sa.String(length=50), nullable=False),
    sa.Column('password', sa.String(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user')
    op.drop_table('sslcertificate')
    # ### end Alembic commands ###

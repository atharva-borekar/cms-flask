"""Added ssl certificate subject attributes in tab;e

Revision ID: 5a4e16a9513e
Revises: aa0b924faa2f
Create Date: 2023-04-24 11:10:20.855667

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5a4e16a9513e'
down_revision = 'aa0b924faa2f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('sslcertificate', schema=None) as batch_op:
        batch_op.add_column(sa.Column('country', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('state', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('locality', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('email', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('common_name', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('organization_unit', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('organization_name', sa.String(length=128), nullable=True))
        batch_op.drop_column('name')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('sslcertificate', schema=None) as batch_op:
        batch_op.add_column(sa.Column('name', sa.VARCHAR(length=128), autoincrement=False, nullable=True))
        batch_op.drop_column('organization_name')
        batch_op.drop_column('organization_unit')
        batch_op.drop_column('common_name')
        batch_op.drop_column('email')
        batch_op.drop_column('locality')
        batch_op.drop_column('state')
        batch_op.drop_column('country')

    # ### end Alembic commands ###
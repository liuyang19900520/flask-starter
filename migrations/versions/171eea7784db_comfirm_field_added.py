"""comfirm field added

Revision ID: 171eea7784db
Revises: 
Create Date: 2019-01-29 15:23:30.838673

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '171eea7784db'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('confirmed', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'confirmed')
    # ### end Alembic commands ###
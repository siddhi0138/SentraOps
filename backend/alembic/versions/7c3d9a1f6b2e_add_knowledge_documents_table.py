"""add knowledge_documents table

Revision ID: 7c3d9a1f6b2e
Revises: 5d265ff5e509
Create Date: 2026-07-31 06:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7c3d9a1f6b2e'
down_revision: Union[str, Sequence[str], None] = '5d265ff5e509'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('knowledge_documents',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('organization_id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('filename', sa.String(length=255), nullable=True),
    sa.Column('source', sa.String(length=20), nullable=False),
    sa.Column('chunk_count', sa.Integer(), nullable=False),
    sa.Column('uploaded_by_user_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['uploaded_by_user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_knowledge_documents_organization_id'), 'knowledge_documents', ['organization_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_knowledge_documents_organization_id'), table_name='knowledge_documents')
    op.drop_table('knowledge_documents')

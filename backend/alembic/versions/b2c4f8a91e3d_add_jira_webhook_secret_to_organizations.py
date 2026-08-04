"""add jira_webhook_secret to organizations

Revision ID: b2c4f8a91e3d
Revises: 9e1c5b7a3d4f
Create Date: 2026-08-05 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c4f8a91e3d'
down_revision: Union[str, Sequence[str], None] = '9e1c5b7a3d4f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('organizations', sa.Column('jira_webhook_secret', sa.String(length=64), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('organizations', 'jira_webhook_secret')

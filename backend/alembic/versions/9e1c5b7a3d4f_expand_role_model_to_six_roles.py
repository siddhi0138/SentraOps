"""expand role model to six roles (owner/admin/soc_manager/analyst/executive/auditor)

Revision ID: 9e1c5b7a3d4f
Revises: 7c3d9a1f6b2e
Create Date: 2026-07-31 07:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9e1c5b7a3d4f'
down_revision: Union[str, Sequence[str], None] = '7c3d9a1f6b2e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

users = sa.table("users", sa.column("role", sa.String))


def upgrade() -> None:
    """Upgrade schema."""
    # "admin" (the org creator, or anyone since promoted to it) becomes
    # "owner" - the new top role, since there was never a lower "admin"
    # tier for it to collide with. "viewer" becomes "auditor" - the closest
    # read-only equivalent in the new model. "analyst" is unchanged.
    op.execute(users.update().where(users.c.role == "admin").values(role="owner"))
    op.execute(users.update().where(users.c.role == "viewer").values(role="auditor"))


def downgrade() -> None:
    """Downgrade schema."""
    op.execute(users.update().where(users.c.role == "owner").values(role="admin"))
    op.execute(users.update().where(users.c.role == "auditor").values(role="viewer"))
    op.execute(users.update().where(users.c.role == "soc_manager").values(role="analyst"))
    op.execute(users.update().where(users.c.role == "executive").values(role="viewer"))

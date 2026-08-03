"""add organizations table and multi-tenant scoping

Revision ID: d5856d0e2f50
Revises: 24b27c0794be
Create Date: 2026-07-26 03:51:25.052297

"""
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd5856d0e2f50'
down_revision: Union[str, Sequence[str], None] = '24b27c0794be'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Tables that get an organization_id column in this migration.
_SCOPED_TABLES = ["agent_runs", "assets", "embeddings", "events", "incidents", "proposed_actions", "raw_logs", "users"]


def upgrade() -> None:
    """Adds multi-tenancy: an `organizations` table, plus an
    `organization_id` FK on every table holding org-specific data. Existing
    rows (if any) are backfilled into one "Legacy Organization" rather than
    adding the column as NOT NULL directly - a bare NOT NULL ADD COLUMN
    fails outright on Postgres with existing rows and has no default to
    fall back to, so this always has to be add-nullable -> backfill ->
    make-not-null, never a single-step add."""
    organizations = op.create_table(
        'organizations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=100), nullable=False),
        sa.Column('plan', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_organizations_slug'), 'organizations', ['slug'], unique=True)

    op.bulk_insert(
        organizations,
        [{"name": "Legacy Organization", "slug": "legacy", "plan": "free", "created_at": datetime.now(timezone.utc)}],
    )
    legacy_org_id = 1  # first (only) row in a fresh organizations table

    # Drop this *before* the assets table goes through batch_alter_table
    # below, not after: SQLite's batch mode rebuilds the whole table from
    # current model metadata once a NOT NULL/FK change forces a real
    # rebuild (not a plain ALTER TABLE ADD COLUMN), and Asset's model
    # already only declares the new composite index - so the rebuild
    # silently drops this one as a side effect before an explicit
    # drop_index() afterward would ever run, and "DROP INDEX" without
    # IF EXISTS then fails on an index that's already gone. Confirmed by
    # actually running this migration and hitting exactly that failure.
    op.execute("DROP INDEX IF EXISTS ix_assets_host_lower")

    for table in _SCOPED_TABLES:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.add_column(sa.Column('organization_id', sa.Integer(), nullable=True))

        op.execute(f"UPDATE {table} SET organization_id = {legacy_org_id} WHERE organization_id IS NULL")

        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.alter_column('organization_id', nullable=False)
            batch_op.create_index(batch_op.f(f'ix_{table}_organization_id'), ['organization_id'], unique=False)
            batch_op.create_foreign_key(f'fk_{table}_organization_id', 'organizations', ['organization_id'], ['id'])

    # The old single-column case-insensitive uniqueness on Asset.host allowed
    # only one "DC01" across the *entire* platform - now that multiple
    # organizations share this table, it has to be scoped per-org instead
    # (see db_models.py's ix_assets_org_host_lower comment).
    op.create_index('ix_assets_org_host_lower', 'assets', ['organization_id', sa.text('lower(host)')], unique=True)


def downgrade() -> None:
    """Downgrade schema."""
    # Same reasoning as upgrade(): drop this defensively before the assets
    # table's batch rebuild below, rather than after, since that rebuild
    # may already take it out as a side effect.
    op.execute("DROP INDEX IF EXISTS ix_assets_org_host_lower")

    for table in reversed(_SCOPED_TABLES):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_constraint(f'fk_{table}_organization_id', type_='foreignkey')
            batch_op.drop_index(batch_op.f(f'ix_{table}_organization_id'))
            batch_op.drop_column('organization_id')

    op.create_index('ix_assets_host_lower', 'assets', [sa.text('lower(host)')], unique=True)

    op.drop_index(op.f('ix_organizations_slug'), table_name='organizations')
    op.drop_table('organizations')

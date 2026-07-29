"""add threat_indicators table

Revision ID: b45d401b030d
Revises: a2ad6aa0d24e
Create Date: 2026-07-27 01:32:05.446068

"""
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b45d401b030d'
down_revision: Union[str, Sequence[str], None] = 'a2ad6aa0d24e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

threat_indicators = sa.table(
    "threat_indicators",
    sa.column("indicator", sa.String),
    sa.column("indicator_type", sa.String),
    sa.column("verdict", sa.String),
    sa.column("confidence", sa.Integer),
    sa.column("source", sa.String),
    sa.column("tags", sa.String),
    sa.column("first_seen", sa.DateTime),
    sa.column("last_seen", sa.DateTime),
)


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('threat_indicators',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('indicator', sa.String(length=512), nullable=False),
    sa.Column('indicator_type', sa.String(length=20), nullable=False),
    sa.Column('verdict', sa.String(length=255), nullable=False),
    sa.Column('confidence', sa.Integer(), nullable=False),
    sa.Column('source', sa.String(length=100), nullable=False),
    sa.Column('tags', sa.String(length=255), nullable=True),
    sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_threat_indicators_indicator'), 'threat_indicators', ['indicator'], unique=False)
    # Expression-based unique index (case-insensitive) - autogenerate can't
    # reflect these on SQLite (same known limitation as
    # ix_assets_org_host_lower in an earlier migration), so it's added by
    # hand rather than picked up automatically.
    op.create_index('ix_threat_indicators_indicator_lower', 'threat_indicators', [sa.text('lower(indicator)')], unique=True)

    # Seed one curated demo indicator so the built-in phishing_ransomware
    # simulate scenario keeps demonstrating a real threat-intel match out
    # of the box, now that correlation.py no longer has a hardcoded dict.
    # A real Python datetime, not sa.func.now() - a SQL function object
    # isn't a valid bind parameter value for SQLite's DateTime type
    # (bit this project once already, see the organizations migration).
    now = datetime.now(timezone.utc)
    op.bulk_insert(
        threat_indicators,
        [
            {
                "indicator": "185.220.101.45",
                "indicator_type": "ip",
                "verdict": "known Tor exit node / ransomware C2 infrastructure",
                "confidence": 98,
                "source": "SentraOps curated (demo seed)",
                "tags": "tor,c2",
                "first_seen": now,
                "last_seen": now,
            }
        ],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_threat_indicators_indicator_lower', table_name='threat_indicators')
    op.drop_index(op.f('ix_threat_indicators_indicator'), table_name='threat_indicators')
    op.drop_table('threat_indicators')

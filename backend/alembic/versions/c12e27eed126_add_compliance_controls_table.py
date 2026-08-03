"""add compliance_controls table

Revision ID: c12e27eed126
Revises: b45d401b030d
Create Date: 2026-07-27 02:45:41.288932

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c12e27eed126'
down_revision: Union[str, Sequence[str], None] = 'b45d401b030d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

compliance_controls = sa.table(
    "compliance_controls",
    sa.column("framework", sa.String),
    sa.column("control_id", sa.String),
    sa.column("title", sa.String),
    sa.column("description", sa.Text),
    sa.column("check_key", sa.String),
)

# Illustrative mappings inspired by common SOC2/ISO27001/GDPR practice, not
# a certified audit mapping - each description says so explicitly rather
# than implying this platform grants real compliance certification.
SEED_CONTROLS = [
    {
        "framework": "SOC2",
        "control_id": "CC6.1",
        "title": "Role-Based Access Control",
        "description": "Logical access is restricted by role (admin/analyst/viewer), not shared broadly. Illustrative mapping to SOC2's CC6.1 access-control criterion, not a certified audit result.",
        "check_key": "rbac_role_separation",
    },
    {
        "framework": "SOC2",
        "control_id": "CC6.3",
        "title": "Credential Protection",
        "description": "User passwords are stored as salted bcrypt hashes, never in plaintext or reversible form. Illustrative mapping to SOC2's CC6.3 criterion.",
        "check_key": "password_hashing",
    },
    {
        "framework": "SOC2",
        "control_id": "CC7.2",
        "title": "Incident Detection and Response",
        "description": "The platform's AI investigation pipeline has actually run and completed against real incidents, not just been documented as a plan. Illustrative mapping to SOC2's CC7.2 criterion.",
        "check_key": "incident_response_exercised",
    },
    {
        "framework": "SOC2",
        "control_id": "A1.2",
        "title": "Availability Monitoring",
        "description": "A metrics endpoint (Prometheus /metrics) is enabled for system availability/latency monitoring. Illustrative mapping to SOC2's A1.2 criterion.",
        "check_key": "availability_monitoring",
    },
    {
        "framework": "ISO27001",
        "control_id": "A.12.4",
        "title": "Event Logging and Audit Trail",
        "description": "Analyst comments and AI agent decision logs form a real, queryable audit trail. Illustrative mapping to ISO/IEC 27001:2022 Annex A.12.4.",
        "check_key": "audit_trail_exists",
    },
    {
        "framework": "ISO27001",
        "control_id": "A.5.24",
        "title": "Incident Response Planning",
        "description": "Every incident has documented recommended response actions, not just a detection alert. Illustrative mapping to ISO/IEC 27001:2022 Annex A.5.24.",
        "check_key": "incident_response_plans_documented",
    },
    {
        "framework": "ISO27001",
        "control_id": "A.8.32",
        "title": "Change Management - Human Approval Gate",
        "description": "Every executed response action was reviewed and approved by a human before execution - the AI never self-authorizes a change. Illustrative mapping to ISO/IEC 27001:2022 Annex A.8.32.",
        "check_key": "response_action_approval_gate",
    },
    {
        "framework": "GDPR",
        "control_id": "Art.33",
        "title": "Breach Notification Without Undue Delay",
        "description": "Every incident triggers an immediate responder notification at creation time - a real timing check against this platform's own notification records, not a manual attestation. Illustrative mapping to GDPR Article 33.",
        "check_key": "breach_notification_immediate",
    },
]


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('compliance_controls',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('framework', sa.String(length=50), nullable=False),
    sa.Column('control_id', sa.String(length=20), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('check_key', sa.String(length=50), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('check_key')
    )
    op.create_index(op.f('ix_compliance_controls_framework'), 'compliance_controls', ['framework'], unique=False)

    op.bulk_insert(compliance_controls, SEED_CONTROLS)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_compliance_controls_framework'), table_name='compliance_controls')
    op.drop_table('compliance_controls')

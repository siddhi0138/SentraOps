"""seed nist mitre cis pci compliance controls

Revision ID: 5d265ff5e509
Revises: c81764d494a4
Create Date: 2026-07-28 20:42:29.234291

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5d265ff5e509'
down_revision: Union[str, Sequence[str], None] = 'c81764d494a4'
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

# Same "illustrative mapping, not a certified audit result" disclosure
# convention as the original SOC2/ISO27001/GDPR seed in c12e27eed126.
NEW_SEED_CONTROLS = [
    {
        "framework": "NIST_CSF",
        "control_id": "PR.AC-1",
        "title": "Identity and Access Management",
        "description": "Logical access is restricted by role (admin/analyst/viewer). Illustrative mapping to NIST CSF's PR.AC-1 subcategory, not a certified assessment.",
        "check_key": "nist_rbac_role_separation",
    },
    {
        "framework": "NIST_CSF",
        "control_id": "DE.AE-1",
        "title": "Anomalies and Events Detected",
        "description": "The correlation engine has grouped raw events into real incidents, demonstrating an operating detection capability. Illustrative mapping to NIST CSF's DE.AE-1 subcategory.",
        "check_key": "nist_detection_capability_exercised",
    },
    {
        "framework": "NIST_CSF",
        "control_id": "RS.RP-1",
        "title": "Response Planning",
        "description": "Every incident has documented recommended response actions. Illustrative mapping to NIST CSF's RS.RP-1 subcategory.",
        "check_key": "nist_incident_response_plans_documented",
    },
    {
        "framework": "NIST_CSF",
        "control_id": "RC.RP-1",
        "title": "Recovery Planning",
        "description": "Incidents are tracked through to a recorded closure/recovery timestamp, not left open indefinitely. Illustrative mapping to NIST CSF's RC.RP-1 subcategory.",
        "check_key": "nist_recovery_planning",
    },
    {
        "framework": "MITRE_ATTACK",
        "control_id": "TA0004",
        "title": "Privilege Escalation Detection Coverage",
        "description": "At least one incident was classified as privilege escalation from real event data, not a generic alert. Illustrative mapping to MITRE ATT&CK tactic TA0004.",
        "check_key": "mitre_privilege_escalation_detected",
    },
    {
        "framework": "MITRE_ATTACK",
        "control_id": "TA0010",
        "title": "Exfiltration Detection Coverage",
        "description": "At least one incident was classified as a ransomware/data-exfiltration chain from real event data. Illustrative mapping to MITRE ATT&CK tactic TA0010 (Exfiltration) / TA0040 (Impact).",
        "check_key": "mitre_exfiltration_detected",
    },
    {
        "framework": "MITRE_ATTACK",
        "control_id": "TA0001",
        "title": "Known-Infrastructure Detection Coverage",
        "description": "At least one incident matched a known indicator in the Threat Intel Hub, identifying real attacker infrastructure rather than only an internal anomaly. Illustrative mapping to MITRE ATT&CK tactic TA0001.",
        "check_key": "mitre_threat_intel_matched",
    },
    {
        "framework": "CIS",
        "control_id": "CIS-5",
        "title": "Account Management",
        "description": "User passwords are stored as salted bcrypt hashes, never in plaintext. Illustrative mapping to CIS Controls v8, Control 5.",
        "check_key": "cis_password_hashing",
    },
    {
        "framework": "CIS",
        "control_id": "CIS-8",
        "title": "Audit Log Management",
        "description": "Analyst comments and AI agent decision logs form a real, queryable audit trail. Illustrative mapping to CIS Controls v8, Control 8.",
        "check_key": "cis_audit_trail_exists",
    },
    {
        "framework": "CIS",
        "control_id": "CIS-13",
        "title": "Network Monitoring and Defense",
        "description": "Firewall/network-layer events have been ingested for this organization, not just endpoint/application sources. Illustrative mapping to CIS Controls v8, Control 13.",
        "check_key": "cis_network_monitoring",
    },
    {
        "framework": "PCI_DSS",
        "control_id": "Req-8",
        "title": "Identify and Authenticate Access",
        "description": "User passwords are stored as salted bcrypt hashes, never in plaintext. Illustrative mapping to PCI DSS v4.0 Requirement 8.",
        "check_key": "pci_password_hashing",
    },
    {
        "framework": "PCI_DSS",
        "control_id": "Req-10",
        "title": "Log and Monitor All Access",
        "description": "Analyst comments and AI agent decision logs form a real, queryable audit trail. Illustrative mapping to PCI DSS v4.0 Requirement 10.",
        "check_key": "pci_audit_trail_exists",
    },
    {
        "framework": "PCI_DSS",
        "control_id": "Req-6",
        "title": "Vulnerability and Threat Management",
        "description": "Indicators from a real external threat feed sync (URLhaus) are present in the shared Threat Intel Hub, beyond the built-in demo seed. Illustrative mapping to PCI DSS v4.0 Requirement 6.",
        "check_key": "pci_vulnerability_management",
    },
]


def upgrade() -> None:
    """Upgrade schema."""
    op.bulk_insert(compliance_controls, NEW_SEED_CONTROLS)


def downgrade() -> None:
    """Downgrade schema."""
    keys = [c["check_key"] for c in NEW_SEED_CONTROLS]
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM compliance_controls WHERE check_key IN :keys").bindparams(
            sa.bindparam("keys", expanding=True)
        ),
        {"keys": keys},
    )

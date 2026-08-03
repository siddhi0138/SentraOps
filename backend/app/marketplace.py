from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db_models import OrgPlaybookInstall, PlaybookTemplate


def list_playbooks(db: Session) -> list[PlaybookTemplate]:
    return db.query(PlaybookTemplate).order_by(PlaybookTemplate.category, PlaybookTemplate.name).all()


def list_installed(db: Session, organization_id: int) -> list[PlaybookTemplate]:
    return (
        db.query(PlaybookTemplate)
        .join(OrgPlaybookInstall, OrgPlaybookInstall.playbook_id == PlaybookTemplate.id)
        .filter(OrgPlaybookInstall.organization_id == organization_id)
        .order_by(PlaybookTemplate.category, PlaybookTemplate.name)
        .all()
    )


def install_playbook(db: Session, organization_id: int, playbook_id: int) -> OrgPlaybookInstall:
    existing = (
        db.query(OrgPlaybookInstall)
        .filter(OrgPlaybookInstall.organization_id == organization_id, OrgPlaybookInstall.playbook_id == playbook_id)
        .first()
    )
    if existing:
        return existing

    # Race-safe the same way ingestion.py's asset upsert and
    # threat_intel_hub's indicator upsert are: the unique index on
    # (organization_id, playbook_id) turns a concurrent double-install
    # into a clean IntegrityError instead of a duplicate row.
    try:
        with db.begin_nested():
            install = OrgPlaybookInstall(organization_id=organization_id, playbook_id=playbook_id)
            db.add(install)
            db.flush()
        return install
    except IntegrityError:
        return (
            db.query(OrgPlaybookInstall)
            .filter(OrgPlaybookInstall.organization_id == organization_id, OrgPlaybookInstall.playbook_id == playbook_id)
            .one()
        )


def uninstall_playbook(db: Session, organization_id: int, playbook_id: int) -> bool:
    existing = (
        db.query(OrgPlaybookInstall)
        .filter(OrgPlaybookInstall.organization_id == organization_id, OrgPlaybookInstall.playbook_id == playbook_id)
        .first()
    )
    if not existing:
        return False
    db.delete(existing)
    db.commit()
    return True


def get_installed_prompt_addition(db: Session, organization_id: int) -> str:
    """Concatenates every installed playbook's prompt guidance - fed into
    AI incident explanations (see app/ai.py's explain_incident) as the
    marketplace's actual real effect, not just a UI toggle with nothing
    behind it."""
    installed = list_installed(db, organization_id)
    return "\n".join(p.prompt_addition for p in installed)

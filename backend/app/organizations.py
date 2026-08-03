import re
import secrets

from sqlalchemy.orm import Session

from app.db_models import Organization


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "org"


def unique_slug(db: Session, name: str) -> str:
    """Appends -2, -3, ... on collision rather than rejecting the signup -
    "Acme Corp" and a later unrelated "Acme Corp" (different company,
    same name) both need to be able to sign up."""
    base = slugify(name)
    slug = base
    suffix = 1
    while db.query(Organization).filter(Organization.slug == slug).first() is not None:
        suffix += 1
        slug = f"{base}-{suffix}"
    return slug


def rotate_invite_code(db: Session, org: Organization) -> str:
    """Generates a fresh, unpredictable invite slug - for invalidating a
    leaked/overshared code without renaming the organization itself. Random
    suffix (not a simple incrementing counter like unique_slug's collision
    handling) since predictability here is the actual security property
    being rotated away from."""
    base = slugify(org.name)
    while True:
        candidate = f"{base}-{secrets.token_hex(3)}"
        if db.query(Organization).filter(Organization.slug == candidate).first() is None:
            return candidate

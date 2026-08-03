import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

import bcrypt
import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import ApiKey, User

SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-only-insecure-secret-key-change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# auto_error=False: an API-key-only request has no Authorization header at
# all, and HTTPBearer's default auto_error=True would reject it before
# get_current_user() below ever gets a chance to check X-API-Key instead.
bearer_scheme = HTTPBearer(auto_error=False)


class Role(str, Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class UserCreate(BaseModel):
    email: EmailStr
    # Only enforced at registration, not login - an existing account created
    # before this constraint (or via direct DB seeding) must still be able
    # to sign in with whatever password it already has.
    password: str = Field(min_length=8)
    # Joining an existing organization - the "invite code" a teammate types
    # in. Creating a brand new organization is a separate endpoint
    # (POST /organizations), since that flow also needs an org display name
    # and makes the creator an admin rather than a viewer.
    organization_slug: str = Field(min_length=1)


class OrganizationCreate(BaseModel):
    organization_name: str = Field(min_length=2, max_length=255)
    email: EmailStr
    password: str = Field(min_length=8)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    organization_id: int
    organization_name: str
    organization_slug: str


class RoleUpdate(BaseModel):
    role: Role


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def _create_token(subject: str, token_type: str, expires_delta: timedelta) -> str:
    payload = {
        "sub": subject,
        "type": token_type,
        "exp": datetime.now(timezone.utc) + expires_delta,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_access_token(user_id: int) -> str:
    return _create_token(str(user_id), "access", timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))


def create_refresh_token(user_id: int) -> str:
    return _create_token(str(user_id), "refresh", timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))


def decode_token(token: str, expected_type: str) -> int:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    if payload.get("type") != expected_type:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Expected a {expected_type} token")

    return int(payload["sub"])


def _resolve_api_key(db: Session, raw_key: str) -> User:
    # Imported here (not at module top) to avoid a circular import - see
    # app/admin.py's own docstring for why API keys deliberately act as a
    # real User row instead of a synthetic principal.
    from app.admin import hash_api_key

    api_key = db.query(ApiKey).filter(ApiKey.key_hash == hash_api_key(raw_key), ApiKey.revoked_at.is_(None)).first()
    if api_key is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked API key")

    user = db.get(User, api_key.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="This API key's user is inactive")

    api_key.last_used_at = datetime.now(timezone.utc)
    db.commit()
    return user


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> User:
    if x_api_key:
        return _resolve_api_key(db, x_api_key)

    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    user_id = decode_token(credentials.credentials, "access")
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


def require_roles(*roles: Role):
    allowed = {r.value for r in roles}

    def _check(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {sorted(allowed)}",
            )
        return user

    return _check

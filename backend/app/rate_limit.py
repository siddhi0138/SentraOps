import jwt
from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.auth import ALGORITHM, SECRET_KEY
from app.redis_client import REDIS_URL


def _client_ip(request: Request) -> str:
    """slowapi's own get_remote_address() only ever reads request.client.host
    - behind a reverse proxy (this app sits behind Render's, in front of a
    Kubernetes ingress) that's the proxy's own hop, not the real caller, and
    isn't guaranteed stable across requests if the proxy fronting this
    service is itself a pool of edge nodes. X-Forwarded-For's first hop is
    the original client and is what actually stays stable per caller -
    found this the hard way on IntelliVerse's identical helper, where relying
    on request.client.host silently made per-IP rate limiting never
    accumulate in production despite working perfectly in local tests."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return get_remote_address(request)


def _rate_limit_key(request: Request) -> str:
    """Key by the calling user when a valid JWT is present, else by IP.

    Deliberately re-decodes the token here rather than depending on
    get_current_user: slowapi's key_func only ever receives the raw Request
    (it runs before FastAPI resolves endpoint dependencies), and it must
    never raise - an invalid/missing token here just means the caller isn't
    authenticated yet (e.g. /auth/login itself), not a rate-limit error.
    """
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id = payload.get("sub")
            if user_id:
                return f"user:{user_id}"
        except jwt.PyJWTError:
            pass
    return f"ip:{_client_ip(request)}"


# Redis-backed (not in-memory) since this app runs as multiple pods in
# Kubernetes - an in-memory limiter would let each pod count independently
# and silently allow N times the intended limit. swallow_errors=True: a
# Redis outage should degrade to "no rate limiting" rather than 500ing
# every request on this app's most-hit endpoints (login, chat).
limiter = Limiter(key_func=_rate_limit_key, storage_uri=REDIS_URL, swallow_errors=True)

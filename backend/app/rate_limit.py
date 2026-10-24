import asyncio
import logging
from functools import wraps

import jwt
from fastapi import HTTPException, Request
from limits import parse
from limits.storage import storage_from_string
from limits.strategies import MovingWindowRateLimiter

from app.auth import ALGORITHM, SECRET_KEY
from app.redis_client import REDIS_URL

logger = logging.getLogger(__name__)


def _client_ip(request: Request) -> str:
    """Prefers X-Forwarded-For's first hop over request.client.host -
    behind a reverse proxy (this app sits behind Render's, in front of a
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
    return request.client.host if request.client else "unknown"


def _rate_limit_key(request: Request) -> str:
    """Key by the calling user when a valid JWT is present, else by IP."""
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


# Lazy singleton: constructing the storage client doesn't connect to Redis
# (that only happens on the first real .hit() call), so a Redis outage at
# import time can't crash app startup either way - but building it lazily
# still keeps the import-time cost at zero for any process that never
# serves a rate-limited request (tests, one-off scripts).
_strategy: MovingWindowRateLimiter | None = None


def _get_strategy() -> MovingWindowRateLimiter:
    global _strategy
    if _strategy is None:
        _strategy = MovingWindowRateLimiter(storage_from_string(REDIS_URL))
    return _strategy


def _check(spec_key: str, request: Request | None) -> None:
    if not limiter.enabled or request is None:
        return
    key = _rate_limit_key(request)
    try:
        allowed = _get_strategy().hit(parse(spec_key), key)
    except Exception as exc:
        # A dead/unreachable Redis (e.g. a free-tier instance that expired
        # from inactivity - confirmed the actual trigger here: the
        # configured Upstash hostname no longer resolves in DNS at all)
        # must degrade to "no rate limiting" rather than failing every
        # request on this app's most-hit endpoints (login, chat, signup).
        # This replaces slowapi, whose own swallow_errors=True didn't
        # actually protect this path - it swallowed the exception in its
        # middleware but left request.state.view_rate_limit unset, which
        # then raised AttributeError when the decorator tried to read it
        # back. That's a real bug this project hit in production, not a
        # hypothetical - confirmed by reproducing it against the real
        # database and the real (now-dead) Redis URL.
        logger.warning(f"Rate limiter storage unavailable ({exc!r}); allowing request through.")
        return
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many requests - please slow down and try again shortly.")


def _find_request(args: tuple, kwargs: dict) -> Request | None:
    request = kwargs.get("request")
    if request is not None:
        return request
    for arg in args:
        if isinstance(arg, Request):
            return arg
    return None


def rate_limit(spec: str):
    """Decorator replacing slowapi's @limiter.limit(spec) - same call-site
    syntax (every `@limiter.limit("N/minute")` call site in main.py stays
    unchanged), built directly on the `limits` library (which slowapi
    itself only ever wrapped) instead of slowapi's middleware +
    request.state coordination. Preserves whether the wrapped endpoint is
    sync or async, since FastAPI runs sync endpoints in a threadpool and
    async ones directly on the event loop - wrapping a sync endpoint in an
    async wrapper would silently change that and block the event loop on
    every sync DB call inside it.
    """

    def decorator(func):
        if asyncio.iscoroutinefunction(func):

            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                _check(spec, _find_request(args, kwargs))
                return await func(*args, **kwargs)

            return async_wrapper

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            _check(spec, _find_request(args, kwargs))
            return func(*args, **kwargs)

        return sync_wrapper

    return decorator


class _LimiterShim:
    """Keeps the `limiter.limit(...)` call-site syntax (and the
    `limiter.enabled` toggle the test suite already relies on - see
    tests/conftest.py and tests/test_rate_limiting.py) identical to
    slowapi's, so only this module's internals changed, not every
    decorated endpoint in main.py nor the existing tests built around the
    old slowapi-based limiter's interface."""

    enabled = True

    def limit(self, spec: str):
        return rate_limit(spec)


limiter = _LimiterShim()

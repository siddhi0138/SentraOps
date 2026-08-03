import redis
import pytest
from starlette.requests import Request

from app.auth import create_access_token
from app.rate_limit import _rate_limit_key, limiter
from app.redis_client import REDIS_URL


def _redis_reachable() -> bool:
    try:
        redis.Redis.from_url(REDIS_URL, socket_connect_timeout=1).ping()
        return True
    except redis.exceptions.RedisError:
        return False


# The key-func tests below are pure logic and always run. The two
# real-429 tests need an actual reachable Redis (the limiter is
# storage_uri=REDIS_URL, swallow_errors=True - without Redis it silently
# stops enforcing limits rather than raising, so there'd be nothing to
# assert). Same split this project uses elsewhere for infra-dependent
# behavior (Neo4j Cypher, Celery worker registration, Redis Streams): a
# fake/logic-only test in the checked-in suite, real-infra proof run by
# hand against a real container - not wired into the default `pytest` run
# so CI doesn't need a Redis service container.
requires_redis = pytest.mark.skipif(not _redis_reachable(), reason="no Redis reachable at REDIS_URL")


@pytest.fixture()
def rate_limiting_enabled():
    """The rest of the suite runs with limiter.enabled = False (set in
    conftest.py) since most tests log in/register far more than the real
    per-minute limits allow. Tests in this file need it genuinely on to
    prove real 429 behavior, not mocked - restored afterward so it can't
    leak into other test files."""
    limiter.enabled = True
    yield
    limiter.enabled = False


def _fake_request(headers: list[tuple[bytes, bytes]]) -> Request:
    scope = {
        "type": "http",
        "headers": headers,
        "client": ("203.0.113.5", 12345),
    }
    return Request(scope)


def test_rate_limit_key_uses_ip_when_unauthenticated():
    request = _fake_request([])
    assert _rate_limit_key(request) == "ip:203.0.113.5"


def test_rate_limit_key_uses_user_id_from_valid_token():
    token = create_access_token(42)
    request = _fake_request([(b"authorization", f"Bearer {token}".encode())])
    assert _rate_limit_key(request) == "user:42"


def test_rate_limit_key_falls_back_to_ip_on_garbage_token():
    request = _fake_request([(b"authorization", b"Bearer not-a-real-jwt")])
    assert _rate_limit_key(request) == "ip:203.0.113.5"


@requires_redis
def test_login_endpoint_returns_429_after_exceeding_the_real_limit(client, rate_limiting_enabled):
    # /auth/login is limited to 10/minute (app/main.py). Wrong credentials
    # is fine - the rate-limit check runs before the handler body, so it
    # never needs to reach the DB.
    responses = [
        client.post("/auth/login", json={"email": "nobody@example.com", "password": "wrong"}) for _ in range(11)
    ]
    statuses = [r.status_code for r in responses]
    assert statuses[:10] == [401] * 10
    assert statuses[10] == 429
    # Custom handler in main.py reshapes slowapi's default {"error": ...}
    # into this API's usual {"detail": ...} error shape.
    assert "detail" in responses[10].json()


@requires_redis
def test_create_organization_endpoint_returns_429_after_exceeding_the_real_limit(client, rate_limiting_enabled):
    # /organizations is limited to 5/minute.
    responses = [
        client.post(
            "/organizations",
            json={"organization_name": f"Rate Ltd {i}", "email": f"rl{i}@example.com", "password": "Secret123!"},
        )
        for i in range(6)
    ]
    statuses = [r.status_code for r in responses]
    assert statuses[:5] == [200] * 5
    assert statuses[5] == 429

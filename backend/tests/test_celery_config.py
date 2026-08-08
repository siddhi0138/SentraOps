import ssl

from app.celery_app import redis_ssl_conf


def test_rediss_url_gets_explicit_ssl_cert_reqs():
    """Regression test for a real production crash: a managed Redis
    provider's rediss:// URL made the celery worker crash-loop on every
    startup with "A rediss:// URL must have parameter ssl_cert_reqs",
    since redis-py refuses to infer a default. If this ever regresses,
    the worker fails immediately on boot, not on some rarely-hit code
    path - this test exists so that failure shows up in CI instead of
    only in a live deploy's crash logs."""
    conf = redis_ssl_conf("rediss://default:secret@example.upstash.io:6379")
    assert conf["broker_use_ssl"] == {"ssl_cert_reqs": ssl.CERT_NONE}
    assert conf["redis_backend_use_ssl"] == {"ssl_cert_reqs": ssl.CERT_NONE}


def test_plain_redis_url_gets_no_ssl_conf():
    """The unauthenticated local/dev redis:// broker must stay untouched -
    passing ssl_cert_reqs to a non-TLS connection is itself an error."""
    assert redis_ssl_conf("redis://localhost:6379/0") == {}

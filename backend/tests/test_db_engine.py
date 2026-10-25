from app.db import engine_options


def test_hosted_postgres_gets_connection_health_checks_and_recycling():
    options = engine_options("postgresql://user:pw@host.example.com/db?sslmode=require")
    assert options == {"pool_pre_ping": True, "pool_recycle": 240}


def test_sqlite_is_left_alone():
    assert engine_options("sqlite:///./sentraops.db") == {}

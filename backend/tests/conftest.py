import base64
import os
import tempfile
from contextlib import contextmanager

# Test-only auth secrets, set before the app is imported (create_app checks
# them at import time). Assigned, not defaulted, so tests never run with the
# real secrets from backend/.env.
os.environ["JWT_SECRET_KEY"] = "test-only-jwt-secret-" + "0" * 64
os.environ["APP_ENCRYPTION_KEY"] = base64.urlsafe_b64encode(b"t" * 32).decode()
# Raw scan output from tests goes to a throwaway directory, never S3.
os.environ["STORAGE_BACKEND"] = "local"
# A developer's .env may still name a retired AI provider.
os.environ["AI_PROVIDER"] = "huggingface"
os.environ["STORAGE_LOCAL_DIRECTORY"] = tempfile.mkdtemp(prefix="avap-test-store-")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, event  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

# Import all models so Base.metadata registers every table for create_all.
# The FastAPI instance is imported under an alias so `import app.models`
# (which binds the top-level `app` package name in this module's namespace)
# cannot shadow it.
import app.models  # noqa: E402, F401
from app.api.dependencies.auth import (  # noqa: E402
    get_auth_throttles,
    get_current_user,
)
from app.api.dependencies.database import get_db  # noqa: E402
from app.database.base import Base  # noqa: E402
from app.main import app as fastapi_app  # noqa: E402
from app.models.user import User  # noqa: E402
from tests.auth_helpers import TEST_USER_EMAIL, TEST_USER_ID  # noqa: E402

# SQLite database URL for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

# Create test engine using StaticPool to maintain state in memory
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session")
def db_engine():
    """Create database schema for tests."""
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def db_session(db_engine):
    """Provide a transactional scope around a series of operations.

    Uses a SAVEPOINT (nested transaction) so that application code calling
    session.commit() (as production services do) commits only the savepoint,
    never the outer transaction. Without this, a service's session.commit()
    would end the outer transaction directly on this shared connection, and
    any later session.rollback() (e.g. an error-handling rollback further
    into the same test) would discard all prior "committed" data instead of
    only the failed operation's own uncommitted work. The final teardown
    rollback still discards everything, keeping tests isolated.
    """
    connection = db_engine.connect()
    # Begin a non-ORM transaction
    transaction = connection.begin()
    # Bind an individual Session to the connection
    session = TestingSessionLocal(bind=connection)

    nested = connection.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def _restart_savepoint(session, transaction):
        nonlocal nested
        if not nested.is_active:
            nested = connection.begin_nested()

    yield session

    # Rollback - everything that happened with the Session above
    # is rolled back, leaving the DB clean
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture(scope="function")
def test_user(db_session):
    """The user that owns test data, persisted in the test session."""
    user = db_session.get(User, TEST_USER_ID)
    if user is None:
        user = User(
            id=TEST_USER_ID,
            email=TEST_USER_EMAIL,
            password_hash="not-a-real-hash",  # noqa: S106 -- never verified
        )
        db_session.add(user)
        db_session.flush()
    return user


@contextmanager
def _app_bound_to(db_session):
    """Point the app's DB dependency and startup recovery at db_session."""

    def override_get_db():
        yield db_session

    @contextmanager
    def test_session_scope():
        yield db_session

    fastapi_app.dependency_overrides[get_db] = override_get_db
    # Startup scan recovery runs in the app lifespan; point it at the test
    # session so it never reaches the database configured in .env.
    fastapi_app.state.session_scope = test_session_scope
    try:
        yield
    finally:
        fastapi_app.dependency_overrides.clear()
        del fastapi_app.state.session_scope


@pytest.fixture(scope="function")
def client(db_session, test_user):
    """A TestClient authenticated as `test_user`.

    get_current_user is overridden so existing API tests exercise business
    behavior; real token handling is covered with `anonymous_client`.
    """
    with _app_bound_to(db_session):
        fastapi_app.dependency_overrides[get_current_user] = lambda: test_user
        with TestClient(fastapi_app) as c:
            yield c


@pytest.fixture(scope="function")
def anonymous_client(db_session):
    """A TestClient with real authentication (no identity override)."""
    # https base URL: the refresh cookie is Secure, so it is only sent back
    # over HTTPS, exactly as in a browser.
    with (
        _app_bound_to(db_session),
        TestClient(fastapi_app, base_url="https://testserver") as c,
    ):
        yield c


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    """Cached Settings and the process-wide auth throttles must not leak
    across tests."""
    from app.core.config import get_settings

    get_settings.cache_clear()
    get_auth_throttles.cache_clear()
    yield
    get_settings.cache_clear()
    get_auth_throttles.cache_clear()

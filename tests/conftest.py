import pytest
from fastapi.testclient import TestClient

from Backend.main import create_app
from Backend.auth import Credentials, UserCreate, authenticate, create_user, COOKIE_NAME

TEST_PASSWORD = "test-only long password 42!"


@pytest.fixture
def client(tmp_path):
    app = create_app(database_path=tmp_path / "test.db")
    with TestClient(app) as test_client:
        path = app.state.database_path
        create_user(path, UserCreate(username="neehal", password=TEST_PASSWORD, role="admin"), bootstrap=True)
        create_user(path, UserCreate(username="analyst-a", password=TEST_PASSWORD, role="analyst"))
        create_user(path, UserCreate(username="analyst-b", password=TEST_PASSWORD, role="analyst"))
        token, session = authenticate(path, Credentials(username="neehal", password=TEST_PASSWORD), "testclient")
        test_client.cookies.set(COOKIE_NAME, token)
        test_client.headers["X-CSRF-Token"] = session["csrf_token"]
        test_client.headers["X-TethysGuard-Request"] = "1"
        yield test_client

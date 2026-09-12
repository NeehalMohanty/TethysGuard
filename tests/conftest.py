import pytest
from fastapi.testclient import TestClient

from Backend.main import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(database_path=tmp_path / "test.db")
    with TestClient(app) as test_client:
        yield test_client

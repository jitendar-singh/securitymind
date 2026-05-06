import os
import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture
def tmp_memory_manager(tmp_path):
    from secmind.memory_manager import MemoryManager
    return MemoryManager(db_path=str(tmp_path))


@pytest.fixture
def mock_http_client():
    mock = MagicMock()
    mock.session = MagicMock()
    return mock


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    monkeypatch.setenv("SECMIND_ENV", "development")
    monkeypatch.setenv("SECMIND_JWT_SECRET", "test-secret-for-pytest-must-be-at-least-32-bytes-long")

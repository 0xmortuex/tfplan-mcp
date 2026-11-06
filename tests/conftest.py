import os

import pytest

from tfplan_mcp import loader

FIXDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "plans")
SECRET = "PLANTED-hunter2-SECRET-9f3a"


@pytest.fixture(autouse=True)
def sandbox_root():
    """Every test starts with the fixtures directory as the sandbox and default limits."""
    loader.settings.root = loader.real(FIXDIR)
    loader.settings.max_bytes = loader.DEFAULT_MAX_MB * 1024 * 1024
    loader._cache.clear()
    yield
    loader.settings.root = loader.real(FIXDIR)
    loader._cache.clear()


@pytest.fixture
def anyio_backend():
    return "asyncio"


def fx(name: str) -> str:
    return os.path.join(FIXDIR, name + ".json")

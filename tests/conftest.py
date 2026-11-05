import os
import tempfile
from pathlib import Path

import pytest

_test_dir = tempfile.TemporaryDirectory(prefix="aegisvault_tests_")

os.environ["DATABASE_URL"] = (
    f"sqlite:///{Path(_test_dir.name) / 'test.db'}"
)

from app.db import Base, engine
import app.models

Base.metadata.create_all(bind=engine)


@pytest.fixture(autouse=True)
def reset_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    yield

    Base.metadata.drop_all(bind=engine)


def pytest_unconfigure(config):
    engine.dispose()
    _test_dir.cleanup()
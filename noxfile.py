import os
from pathlib import Path

import nox

BASE_DIR = Path(__file__).parent.absolute()
SOURCE_FILES = ("noxfile.py", "src/", "test_truststore.py")


def iter_source_paths():
    for source in SOURCE_FILES:
        for root, _, filenames in sorted(os.walk(source)):
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                yield os.path.join(root, filename)


@nox.session(python="3.10")
def format(session):
    session.install("black", "isort", "pyupgrade")
    session.run("black", *SOURCE_FILES)
    session.run("isort", "--profile=black", *SOURCE_FILES)

    for path in iter_source_paths():
        session.run("pyupgrade", "--py310-plus", "--exit-zero-even-if-changed", path)

    lint(session)


@nox.session(python="3.10")
def lint(session):
    session.install("black", "isort", "flake8", "mypy", "types-certifi")
    session.run("flake8", "--ignore=E501,W503", *SOURCE_FILES)
    session.run("black", "--check", *SOURCE_FILES)
    session.run("isort", "--check", "--profile=black", *SOURCE_FILES)
    session.run("mypy", "--strict", "--show-error-codes", "src/")


@nox.session(python="3.10")
def test(session):
    session.install("-rdev-requirements.txt", ".")
    session.run("pytest", *(session.posargs or ("test_truststore.py",)))

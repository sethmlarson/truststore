import glob

import nox

SOURCE_PATHS = glob.glob("*.py") + ["src/"]
SOURCE_FILES = glob.glob("*.py") + glob.glob("src/**/*.py", recursive=True)


@nox.session
def format(session):
    session.install("black", "isort", "pyupgrade")
    session.run("black", *SOURCE_PATHS)
    session.run("isort", "--profile=black", *SOURCE_PATHS)
    session.run(
        "pyupgrade", "--py310-plus", "--exit-zero-even-if-changed", *SOURCE_FILES
    )

    lint(session)


@nox.session
def lint(session):
    session.install("black", "isort", "flake8", "mypy", "types-certifi")
    session.run("flake8", "--ignore=E501,W503", *SOURCE_PATHS)
    session.run("black", "--check", *SOURCE_PATHS)
    session.run("isort", "--check", "--profile=black", *SOURCE_PATHS)
    session.run("mypy", "--strict", "--show-error-codes", "src/")


@nox.session
def test(session):
    session.install("-rdev-requirements.txt", ".")
    session.run("pip", "freeze")
    session.run("pytest", "-v", "-s", "-rs", *(session.posargs or ("tests/",)))

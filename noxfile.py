import glob

import nox

SOURCE_PATHS = glob.glob("*.py") + ["src/"] + ["tests/"]
SOURCE_FILES = (
    glob.glob("*.py")
    + glob.glob("src/**/*.py", recursive=True)
    + glob.glob("tests/**/*.py", recursive=True)
)


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


@nox.session(python=["3.10", "3.11"])
def test(session):
    # work around issues building Cython-based extensions for prerelease Python versions
    session.env["AIOHTTP_NO_EXTENSIONS"] = "1"
    session.env["YARL_NO_EXTENSIONS"] = "1"
    session.env["FROZENLIST_NO_EXTENSIONS"] = "1"

    session.install("-rdev-requirements.txt", ".")
    session.run("pip", "freeze")
    session.run("pytest", "-v", "-s", "-rs", *(session.posargs or ("tests/",)))

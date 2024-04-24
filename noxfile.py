import glob
import os

import nox

SOURCE_PATHS = glob.glob("*.py") + ["src/"] + ["tests/"]
SOURCE_FILES = (
    glob.glob("*.py")
    + glob.glob("src/**/*.py", recursive=True)
    + glob.glob("tests/**/*.py", recursive=True)
)
# Run in the current Python environment on CI
# (where there's a matrix of jobs using different Pythons)
# but test multiple versions locally
PYTHONS = None if os.environ.get("CI") else ["3.10", "3.11", "3.12", "3.13"]


@nox.session
def format(session):
    session.install("black", "isort", "pyupgrade", "tomli")
    session.run("black", *SOURCE_PATHS)
    session.run("isort", "--profile=black", *SOURCE_PATHS)
    session.run(
        "pyupgrade", "--py37-plus", "--exit-zero-even-if-changed", *SOURCE_FILES
    )

    lint(session)


@nox.session
def lint(session):
    session.install(
        "black", "isort", "flake8", "mypy", "types-certifi", "tomli", "urllib3"
    )
    session.run("flake8", "--ignore=E501,W503,E704", *SOURCE_PATHS)
    session.run("black", "--check", *SOURCE_PATHS)
    session.run("isort", "--check", "--profile=black", *SOURCE_PATHS)
    session.run(
        "mypy",
        "--strict",
        "--show-error-codes",
        "--install-types",
        "--non-interactive",
        "src/",
    )


@nox.session(python=PYTHONS)
def test(session):
    # work around issues building Cython-based extensions for prerelease Python versions
    session.env["AIOHTTP_NO_EXTENSIONS"] = "1"
    session.env["YARL_NO_EXTENSIONS"] = "1"
    session.env["FROZENLIST_NO_EXTENSIONS"] = "1"

    session.install("-rdev-requirements.txt", ".")
    session.run("pip", "freeze")
    session.run(
        "pytest",
        "-v",
        "-s",
        "-rs",
        "--no-flaky-report",
        "--max-runs=3",
        *(session.posargs or ("tests/",)),
    )


@nox.session
def docs(session):
    session.install("-rdocs/requirements.txt", ".")
    session.run("sphinx-build", "-W", "-b", "html", "docs/source", "docs/_build")

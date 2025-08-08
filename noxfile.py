import os
import sys

import nox

# Run in the current Python environment on CI
# (where there's a matrix of jobs using different Pythons)
# but test multiple versions locally
PYTHONS = None if os.environ.get("CI") else ["3.10", "3.11", "3.12", "3.13", "3.14"]


@nox.session(python=PYTHONS)
def test(session):
    # work around issues building Cython-based extensions for prerelease Python versions
    session.env["AIOHTTP_NO_EXTENSIONS"] = "1"
    session.env["YARL_NO_EXTENSIONS"] = "1"
    session.env["FROZENLIST_NO_EXTENSIONS"] = "1"

    # This would need to be updated if we added PyPy
    # to our default Python versions above. Right now
    # PyPy is only used on CI.
    pypy = session.python is None and sys.implementation.name == "pypy"

    session.install("-rdev-requirements.txt", ".")
    session.run("pip", "freeze")
    session.run(
        "pytest",
        "-v",
        "-s",
        "-rs",
        "--no-flaky-report",
        *(("--config-file=pypy-pytest.ini",) if pypy else ()),
        "--max-runs=3",
        *(session.posargs or ("tests/",)),
    )


@nox.session
def docs(session):
    session.install("-rdocs/requirements.txt", ".")
    session.run("sphinx-build", "-W", "-b", "html", "docs/source", "docs/_build")

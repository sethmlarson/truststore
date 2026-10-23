import os

import nox

# Run in the current Python environment on CI
# (where there's a matrix of jobs using different Pythons)
# but test multiple versions locally
PYTHONS = (
    None if os.environ.get("CI") else ["3.10", "3.11", "3.12", "3.13", "3.14", "3.15"]
)


@nox.session(python=PYTHONS)
def test(session):
    # work around issues building Cython-based extensions for prerelease Python versions
    session.env["AIOHTTP_NO_EXTENSIONS"] = "1"
    session.env["YARL_NO_EXTENSIONS"] = "1"
    session.env["FROZENLIST_NO_EXTENSIONS"] = "1"

    session.run_install(
        "python",
        "-m",
        "pip",
        "install",
        "--upgrade",
        "--only-binary",
        ":all:",
        "pip>=26.2.1",
    )
    session.run_install(
        "python",
        "-m",
        "pip",
        "install",
        "--only-binary",
        ":all:",
        "-r",
        "pylock.dev.toml",
    )
    session.run_install("python", "-m", "pip", "install", "--no-deps", "-e", ".")

    session.run("python", "-m", "pip", "freeze")
    session.run(
        "pytest",
        "-v",
        "-s",
        "-rs",
        "--no-flaky-report",
        *(session.posargs or ("tests/",)),
    )


@nox.session
def docs(session):
    session.install("-rdocs/requirements.txt", ".")
    session.run("sphinx-build", "-W", "-b", "html", "docs/source", "docs/_build")

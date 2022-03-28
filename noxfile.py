import nox

SOURCE_FILES = ("noxfile.py", "src/", "test_truststore.py")


@nox.session
def format(session):
    session.install("black", "isort")
    session.run("black", *SOURCE_FILES)
    session.run("isort", "--profile=black", *SOURCE_FILES)

    lint(session)


@nox.session
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

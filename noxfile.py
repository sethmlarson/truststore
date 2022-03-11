import nox

SOURCE_FILES = ("noxfile.py", "truststore.py", "test_truststore.py")


@nox.session
def format(session):
    session.install("black", "isort")
    session.run("black", *SOURCE_FILES)
    session.run("isort", "--profile=black", *SOURCE_FILES)


@nox.session
def test(session):
    session.install("-r", "dev-requirements.txt")
    session.run("pytest", *(session.posargs or ("test_truststore.py",)))

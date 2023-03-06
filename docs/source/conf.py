import datetime
import truststore

project = "Truststore"
author = "Seth Michael Larson, David Glick"
copyright = f"{datetime.date.today().year}"
release = version = truststore.__version__

extensions = [
    "myst_parser",
    "sphinx.ext.intersphinx",
]

html_theme = "furo"
html_context = {
    "display_github": True,
    "github_user": "sethmlarson",
    "github_repo": "truststore",
    "github_version": "main",
    "conf_py_path": "/docs/source/",
}

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "urllib3": ("https://urllib3.readthedocs.io/en/stable", None),
}

nitpicky = True

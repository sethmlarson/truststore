import ast
import os

import truststore


def test_syntax():
    # Tests that the syntax used by truststore is compatible with
    # Python versions that pip supports, currently Python 3.7+
    for root, _, filenames in os.walk(truststore.__path__[0]):
        for filename in filenames:
            if not filename.endswith(".py"):
                continue
            with open(os.path.join(root, filename)) as f:
                ast.parse(f.read(), feature_version=(3, 7))

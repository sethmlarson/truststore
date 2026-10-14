#!/usr/bin/env bash
set -euo pipefail

python -m pip install --upgrade --only-binary :all: 'pip>=26.2.1'
python -m pip install --only-binary :all: -r .github/workflows/pylock.deploy.toml

SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
export SOURCE_DATE_EPOCH
python -m build --no-isolation

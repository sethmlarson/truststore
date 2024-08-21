# Used by the test: test_inject.py::test_requests_work_with_inject

import truststore

truststore.inject_into_ssl()

import requests  # noqa: E402

resp = requests.request("GET", "https://example.com")
assert resp.status_code == 200

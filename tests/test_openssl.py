import types

import truststore._openssl as openssl_backend


class _SSLContext:
    def __init__(self) -> None:
        self.default_verify_paths_calls = 0
        self.loaded_cafiles: list[str] = []

    def set_default_verify_paths(self) -> None:
        self.default_verify_paths_calls += 1

    def load_verify_locations(self, cafile: str) -> None:
        self.loaded_cafiles.append(cafile)


def test_configure_context_uses_default_paths_once(monkeypatch) -> None:
    get_default_verify_paths_calls = 0
    ctx = _SSLContext()

    def get_default_verify_paths() -> types.SimpleNamespace:
        nonlocal get_default_verify_paths_calls
        get_default_verify_paths_calls += 1
        return types.SimpleNamespace(cafile="/tmp/cafile.pem", capath=None)

    monkeypatch.setattr(
        openssl_backend.ssl,
        "get_default_verify_paths",
        get_default_verify_paths,
    )

    with openssl_backend._configure_context(ctx):  # type: ignore[arg-type]
        pass
    with openssl_backend._configure_context(ctx):  # type: ignore[arg-type]
        pass

    assert get_default_verify_paths_calls == 1
    assert ctx.default_verify_paths_calls == 1
    assert ctx.loaded_cafiles == []


def test_configure_context_checks_capath_once(monkeypatch) -> None:
    get_default_verify_paths_calls = 0
    capath_contains_certs_calls = []
    ctx = _SSLContext()
    capath = "/tmp/certs"

    def get_default_verify_paths() -> types.SimpleNamespace:
        nonlocal get_default_verify_paths_calls
        get_default_verify_paths_calls += 1
        return types.SimpleNamespace(cafile=None, capath=capath)

    def capath_contains_certs(path: str) -> bool:
        capath_contains_certs_calls.append(path)
        return True

    monkeypatch.setattr(
        openssl_backend.ssl,
        "get_default_verify_paths",
        get_default_verify_paths,
    )
    monkeypatch.setattr(
        openssl_backend,
        "_capath_contains_certs",
        capath_contains_certs,
    )

    with openssl_backend._configure_context(ctx):  # type: ignore[arg-type]
        pass
    with openssl_backend._configure_context(ctx):  # type: ignore[arg-type]
        pass

    assert get_default_verify_paths_calls == 1
    assert capath_contains_certs_calls == [capath]
    assert ctx.default_verify_paths_calls == 1
    assert ctx.loaded_cafiles == []


def test_configure_context_loads_fallback_cafile_once(monkeypatch) -> None:
    get_default_verify_paths_calls = 0
    isfile_calls = []
    ctx = _SSLContext()
    fallback_cafile = openssl_backend._CA_FILE_CANDIDATES[0]

    def get_default_verify_paths() -> types.SimpleNamespace:
        nonlocal get_default_verify_paths_calls
        get_default_verify_paths_calls += 1
        return types.SimpleNamespace(cafile=None, capath=None)

    def isfile(path: str) -> bool:
        isfile_calls.append(path)
        return path == fallback_cafile

    monkeypatch.setattr(
        openssl_backend.ssl,
        "get_default_verify_paths",
        get_default_verify_paths,
    )
    monkeypatch.setattr(openssl_backend.os.path, "isfile", isfile)

    with openssl_backend._configure_context(ctx):  # type: ignore[arg-type]
        pass
    with openssl_backend._configure_context(ctx):  # type: ignore[arg-type]
        pass

    assert get_default_verify_paths_calls == 1
    assert isfile_calls == [fallback_cafile]
    assert ctx.default_verify_paths_calls == 0
    assert ctx.loaded_cafiles == [fallback_cafile]


def test_configure_context_caches_when_no_locations_found(monkeypatch) -> None:
    get_default_verify_paths_calls = 0
    isfile_calls = []
    ctx = _SSLContext()

    def get_default_verify_paths() -> types.SimpleNamespace:
        nonlocal get_default_verify_paths_calls
        get_default_verify_paths_calls += 1
        return types.SimpleNamespace(cafile=None, capath=None)

    def isfile(path: str) -> bool:
        isfile_calls.append(path)
        return False

    monkeypatch.setattr(
        openssl_backend.ssl,
        "get_default_verify_paths",
        get_default_verify_paths,
    )
    monkeypatch.setattr(openssl_backend.os.path, "isfile", isfile)

    with openssl_backend._configure_context(ctx):  # type: ignore[arg-type]
        pass
    with openssl_backend._configure_context(ctx):  # type: ignore[arg-type]
        pass

    assert get_default_verify_paths_calls == 1
    assert isfile_calls == openssl_backend._CA_FILE_CANDIDATES
    assert ctx.default_verify_paths_calls == 0
    assert ctx.loaded_cafiles == []

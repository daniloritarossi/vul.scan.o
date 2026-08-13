"""
Check aggiornamenti: si basa sulle RELEASE pubblicate, non sui tag.

Prima il controllo leggeva l'elenco dei tag: 27 tag di questo repository non
hanno mai avuto una release, e ognuno di essi veniva annunciato agli utenti
come aggiornamento disponibile. Qui si verifica che a contare sia la release,
che una versione locale sconosciuta non produca un banner permanente e che una
copia piu' avanti dell'ultima release non venga invitata a retrocedere.

Nessuna rete: la risposta di GitHub e' simulata.
"""

import pytest

import app as app_module


# Come risponde GitHub a /releases: una release pubblicata, una bozza (non
# pubblica) e una prerelease piu' recente — lo scenario reale del progetto.
RELEASES = [
    {"tag_name": "v1.0.60-beta", "name": "wip", "draft": True, "prerelease": True,
     "html_url": "https://example.invalid/draft", "published_at": None},
    {"tag_name": "v1.0.59-beta", "name": "v1.0.59-beta", "draft": False,
     "prerelease": True, "html_url": "https://example.invalid/59",
     "published_at": "2026-08-13T22:32:18Z"},
    {"tag_name": "v1.0.57-beta", "name": "v1.0.57-beta", "draft": False,
     "prerelease": True, "html_url": "https://example.invalid/57",
     "published_at": "2026-08-13T15:07:22Z"},
]


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


@pytest.fixture
def fake_releases(monkeypatch):
    """Sostituisce la chiamata a GitHub e azzera la cache di 6 ore."""
    calls = []

    def _fake_get(url, **kw):
        calls.append(url)
        return _Resp(RELEASES)

    import requests
    monkeypatch.setattr(requests, "get", _fake_get)
    app_module._version_cache.update({"at": 0.0, "release": None})
    yield calls
    app_module._version_cache.update({"at": 0.0, "release": None})


# --------------------------------------------------------------- quale endpoint

def test_it_asks_github_for_releases_not_tags(fake_releases):
    app_module._fetch_latest_release()
    assert fake_releases, "nessuna chiamata a GitHub"
    assert fake_releases[0].endswith("/releases")
    assert "/tags" not in fake_releases[0]


def test_latest_is_the_newest_published_release(fake_releases):
    rel = app_module._fetch_latest_release()
    assert rel["tag"] == "v1.0.59-beta"
    assert rel["url"] == "https://example.invalid/59"
    assert rel["prerelease"] is True


def test_drafts_are_not_offered(fake_releases):
    """Una bozza non e' pubblica: proporla manderebbe l'utente su un 404."""
    assert app_module._fetch_latest_release()["tag"] != "v1.0.60-beta"


def test_a_stable_release_wins_over_a_prerelease_of_the_same_version(monkeypatch):
    import requests
    same = [
        {"tag_name": "v1.1.0-beta", "draft": False, "prerelease": True,
         "html_url": "https://example.invalid/beta", "published_at": "x"},
        {"tag_name": "v1.1.0", "draft": False, "prerelease": False,
         "html_url": "https://example.invalid/stable", "published_at": "y"},
    ]
    monkeypatch.setattr(requests, "get", lambda url, **kw: _Resp(same))
    app_module._version_cache.update({"at": 0.0, "release": None})
    try:
        rel = app_module._fetch_latest_release()
        assert rel["tag"] == "v1.1.0" and rel["prerelease"] is False
    finally:
        app_module._version_cache.update({"at": 0.0, "release": None})


def test_github_unreachable_is_not_an_update(monkeypatch):
    import requests

    def _boom(url, **kw):
        raise requests.RequestException("offline")

    monkeypatch.setattr(requests, "get", _boom)
    app_module._version_cache.update({"at": 0.0, "release": None})
    try:
        assert app_module._fetch_latest_release() is None
    finally:
        app_module._version_cache.update({"at": 0.0, "release": None})


# ------------------------------------------------------------------- l'endpoint

def _check(client, monkeypatch, local):
    monkeypatch.setattr(app_module, "_git_version", lambda: local)
    r = client.get("/api/version/check")
    assert r.status_code == 200, r.text
    return r.json()


def test_older_install_is_told_to_update(role_clients, monkeypatch, fake_releases):
    body = _check(role_clients["viewer"], monkeypatch, "v1.0.57-beta")
    assert body["current"] == "v1.0.57-beta"
    assert body["latest"] == "v1.0.59-beta"
    assert body["update_available"] is True
    # Il banner punta alla release, non all'elenco generico.
    assert body["latest_url"] == "https://example.invalid/59"
    assert body["prerelease"] is True


def test_current_release_is_not_an_update(role_clients, monkeypatch, fake_releases):
    body = _check(role_clients["viewer"], monkeypatch, "v1.0.59-beta")
    assert body["update_available"] is False


def test_a_tag_without_a_release_is_not_an_update(role_clients, monkeypatch,
                                                  fake_releases):
    """
    Il caso che ha motivato il cambiamento: la copia locale sta su un tag piu'
    avanti dell'ultima release. Non c'e' niente da installare, e col vecchio
    confronto per stringa l'utente si sentiva dire di "aggiornare" a una
    versione precedente.
    """
    body = _check(role_clients["viewer"], monkeypatch, "v1.0.60-beta")
    assert body["latest"] == "v1.0.59-beta"
    assert body["update_available"] is False


def test_unknown_local_version_never_shows_a_permanent_banner(role_clients,
                                                              monkeypatch,
                                                              fake_releases):
    """
    Installazione da zip senza tag ne' .vfa_version: la versione non e'
    confrontabile. Prima 'dev' != '<tag>' bastava ad accendere il banner, che
    restava acceso per sempre anche sull'ultima versione.
    """
    body = _check(role_clients["viewer"], monkeypatch, "dev")
    assert body["current"] == "dev"
    assert body["current_known"] is False
    assert body["update_available"] is False


def test_describe_suffix_is_stripped_before_comparing(role_clients, monkeypatch,
                                                      fake_releases):
    """'v1.0.59-beta-3-gabc1234' (HEAD oltre il tag) e' comunque la 59."""
    body = _check(role_clients["viewer"], monkeypatch, "v1.0.59-beta-3-gabc1234")
    assert body["current"] == "v1.0.59-beta"
    assert body["update_available"] is False


# ------------------------------------------------- versione locale senza git

def test_version_falls_back_to_the_file_written_by_the_updater(monkeypatch, tmp_path):
    """
    Senza git (installazione da tarball) la versione si legge da .vfa_version,
    che start.sh scrive quando applica una release.
    """
    import subprocess

    def _no_git(*a, **kw):
        raise FileNotFoundError("git")

    vfile = tmp_path / ".vfa_version"
    vfile.write_text("v1.0.59-beta\n", encoding="utf-8")
    monkeypatch.setattr(subprocess, "run", _no_git)
    monkeypatch.setattr(app_module, "VERSION_FILE", vfile)
    assert app_module._git_version() == "v1.0.59-beta"


def test_version_is_dev_when_nothing_is_known(monkeypatch, tmp_path):
    import subprocess

    def _no_git(*a, **kw):
        raise FileNotFoundError("git")

    monkeypatch.setattr(subprocess, "run", _no_git)
    monkeypatch.setattr(app_module, "VERSION_FILE", tmp_path / "missing")
    assert app_module._git_version() == "dev"

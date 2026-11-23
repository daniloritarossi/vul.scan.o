"""
XSS salvato da editor ad admin attraverso ip/username di un asset.

Un editor sceglie ip e username degli asset che crea; la dashboard di ogni
utente che vede quell'asset, admin compreso, li mostrava via innerHTML senza
escape. Due difese, testate qui entrambe:
  - il server rifiuta ip/username che non sono un host o un account reali
    (stesse regole dell'import, che prima valevano solo li');
  - la dashboard escapa comunque cio' che mostra (dati legacy gia' in DB).
"""
import re
from pathlib import Path

import pytest

import asset_import

PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '"><svg onload=alert(1)>',
    "x' onmouseover='alert(1)",
    "root<script>",
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_editor_cannot_create_asset_with_html_username(role_clients, payload):
    r = role_clients["editor"].post("/api/assets", json={
        "ip": "10.99.0.50", "os_type": "linux", "username": payload, "password": "x"})
    assert r.status_code == 400, r.text
    assert r.json()["code"] == "username_invalid"


@pytest.mark.parametrize("payload", PAYLOADS)
def test_editor_cannot_create_asset_with_html_ip(role_clients, payload):
    r = role_clients["editor"].post("/api/assets", json={
        "ip": payload, "os_type": "linux"})
    assert r.status_code == 400, r.text


@pytest.mark.parametrize("payload", PAYLOADS)
def test_editor_cannot_rewrite_own_asset_with_html(role_clients, cone_fixture, payload):
    c = role_clients["editor"]
    a = cone_fixture["asset_in"]
    assert c.put(f"/api/assets/{a}", json={
        "ip": "10.99.0.1", "os_type": "linux", "username": payload}).status_code == 400
    assert c.put(f"/api/assets/{a}", json={
        "ip": payload, "os_type": "linux"}).status_code == 400


@pytest.mark.parametrize("username", [
    "root", "svc_scanner", "CORP\\scanner", "scan@corp.local", "WIN-HOST$", "a.b-c",
])
def test_real_account_names_are_accepted(username):
    assert asset_import.username_error(username) is None


@pytest.mark.parametrize("payload", PAYLOADS + ["with space", "x" * 129])
def test_import_rejects_the_same_usernames(payload):
    _, errors = asset_import.normalize({
        "ip": "10.99.0.51", "os_type": "linux", "username": payload, "password": "x"})
    assert "username_invalid" in errors


def test_dashboard_escapes_asset_fields():
    """Difesa in profondita': i dati legacy gia' salvati non devono eseguire."""
    src = (Path(__file__).parent.parent / "templates" / "index.html").read_text()
    assert "${escHtml(a.ip)}" in src
    assert "escHtml(a.username.toUpperCase())" in src
    # escHtml e' una dichiarazione di funzione (hoisted), non un const in TDZ.
    assert re.search(r"\bfunction escHtml\(", src)
    # Nessuna interpolazione grezza dei campi asset rimasta nella riga asset.
    start = src.index("function assetRow(a)")
    row = src[start:src.index("\n    function ", start + 1)]
    assert "${a.ip}" not in row
    assert not re.search(r"\$\{a\.username(?!\s*\?\s*escHtml)", row)

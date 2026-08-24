"""
test_login_ratelimit.py
------------------------
Funzionale: freno al password guessing su /api/login.

Copre le proprieta' che rendono il freno utile e non dannoso:
  - dopo N fallimenti il login viene rifiutato con 429 + Retry-After
  - l'username INESISTENTE viene frenato allo stesso modo (nessuna
    enumerazione per differenza di risposta)
  - le credenziali giuste azzerano il contatore dell'account
  - l'admin puo' sbloccare subito; gli altri ruoli no
  - lo stato del blocco e' leggibile in /api/users (lucchetto della UI)
"""
import time

import pytest
import ratelimit
from fastapi.testclient import TestClient

import app as app_module
from conftest import ROLE_PASSWORD, USERNAME

CFG = {"max_attempts": 5, "ip_max_attempts": 20, "window_seconds": 900}


def _fail_login(c: TestClient, username: str, times: int):
    out = []
    for _ in range(times):
        out.append(c.post("/api/login", json={"username": username,
                                              "password": "wrong-on-purpose"}))
    return out


def test_failed_logins_are_throttled_after_threshold(role_user_ids):
    c = TestClient(app_module.app)
    codes = [r.status_code for r in _fail_login(c, USERNAME(role="viewer"), 5)]
    assert codes == [401] * 5, codes

    r = c.post("/api/login", json={"username": USERNAME(role="viewer"),
                                   "password": "wrong-on-purpose"})
    assert r.status_code == 429, r.text
    assert int(r.headers["Retry-After"]) > 0
    assert r.json()["code"] == "too_many_attempts"


def test_throttle_blocks_even_the_correct_password(role_user_ids):
    """Il blocco vale per l'account, non per il tentativo: altrimenti chi
    indovina alla sesta prova passerebbe comunque."""
    c = TestClient(app_module.app)
    _fail_login(c, USERNAME(role="viewer"), 5)
    r = c.post("/api/login", json={"username": USERNAME(role="viewer"),
                                   "password": ROLE_PASSWORD})
    assert r.status_code == 429


def test_unknown_username_is_throttled_the_same_way(role_user_ids):
    """Se solo gli account reali finissero in blocco, la differenza di
    risposta direbbe quali username esistono."""
    c = TestClient(app_module.app)
    real = [r.status_code for r in _fail_login(c, USERNAME(role="editor"), 6)]

    ratelimit.reset_all()
    ratelimit._WARMED = True
    fake = [r.status_code for r in _fail_login(c, "_ftest_does_not_exist", 6)]
    assert real == fake == [401] * 5 + [429]


def test_successful_login_clears_the_account_counter(role_user_ids):
    c = TestClient(app_module.app)
    _fail_login(c, USERNAME(role="manager"), 4)
    assert ratelimit.user_status(USERNAME(role="manager"), CFG)["failures"] == 4

    r = c.post("/api/login", json={"username": USERNAME(role="manager"),
                                   "password": ROLE_PASSWORD})
    assert r.status_code == 200
    assert ratelimit.user_status(USERNAME(role="manager"), CFG)["failures"] == 0


def test_window_expiry_releases_the_lock(role_user_ids):
    """Finestra di 1 secondo: scaduta, l'account torna libero da solo."""
    short = {"max_attempts": 2, "ip_max_attempts": 99, "window_seconds": 1}
    ratelimit.record_failure("_ftest_expiry", "1.2.3.4", short)
    ratelimit.record_failure("_ftest_expiry", "1.2.3.4", short)
    assert ratelimit.retry_after("_ftest_expiry", "1.2.3.4", short) > 0
    time.sleep(1.1)
    assert ratelimit.retry_after("_ftest_expiry", "1.2.3.4", short) == 0


def test_admin_can_unlock_and_others_cannot(role_user_ids, role_clients):
    victim = USERNAME(role="stakeholder")
    c = TestClient(app_module.app)
    _fail_login(c, victim, 5)
    assert c.post("/api/login", json={"username": victim,
                                      "password": ROLE_PASSWORD}).status_code == 429

    uid = role_user_ids["stakeholder"]
    for role in ("manager", "editor", "auditor", "viewer", "stakeholder"):
        r = role_clients[role].post(f"/api/users/{uid}/unlock")
        assert r.status_code == 403, f"{role}: {r.status_code}"

    r = role_clients["admin"].post(f"/api/users/{uid}/unlock")
    assert r.status_code == 200, r.text
    assert r.json()["cleared_failures"] == 5
    assert r.json()["lock"]["locked"] is False

    r = c.post("/api/login", json={"username": victim, "password": ROLE_PASSWORD})
    assert r.status_code == 200, r.text


def test_user_list_exposes_lock_state_for_the_admin_console(role_user_ids, role_clients):
    victim = USERNAME(role="auditor")
    c = TestClient(app_module.app)
    _fail_login(c, victim, 5)

    users = role_clients["admin"].get("/api/users").json()["users"]
    row = next(u for u in users if u["username"] == victim)
    assert row["lock"]["locked"] is True
    assert row["lock"]["failures"] == 5
    assert row["lock"]["retry_after"] > 0
    assert row["lock"]["max_attempts"] == 5

    free = next(u for u in users if u["username"] == USERNAME(role="admin"))
    assert free["lock"]["locked"] is False


def test_throttled_attempt_is_recorded_in_the_activity_ledger(role_user_ids, role_clients):
    victim = USERNAME(role="viewer")
    c = TestClient(app_module.app)
    _fail_login(c, victim, 6)          # il 6o e' gia' respinto dal freno

    events = role_clients["admin"].get("/api/audit/events?page_size=50").json()["events"]
    throttled = [e for e in events if e["action"] == "auth.throttled"]
    assert throttled, "il blocco non e' finito nel registro attivita'"
    assert throttled[0]["outcome"] == "denied"
    assert throttled[0]["detail"]["reason"] == "too_many_failed_logins"


def test_forwarded_for_is_ignored_unless_a_proxy_is_trusted(role_user_ids, monkeypatch):
    """L'header e' scrivibile dal client: se ci si fidasse sempre, basterebbe
    cambiarlo a ogni richiesta per falsificare il 'da dove' del registro."""
    c = TestClient(app_module.app)
    monkeypatch.setattr(app_module, "TRUST_PROXY", False)
    r = c.post("/api/login", json={"username": USERNAME(role="viewer"),
                                   "password": "wrong-on-purpose"},
               headers={"X-Forwarded-For": "9.9.9.9"})
    assert r.status_code == 401
    assert not ratelimit._HITS.get(("ip", "9.9.9.9"))

    ratelimit.reset_all()
    ratelimit._WARMED = True
    monkeypatch.setattr(app_module, "TRUST_PROXY", True)
    c.post("/api/login", json={"username": USERNAME(role="viewer"),
                               "password": "wrong-on-purpose"},
           headers={"X-Forwarded-For": "9.9.9.9"})
    assert ratelimit._HITS.get(("ip", "9.9.9.9"))

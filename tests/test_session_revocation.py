"""
Logout = revoca lato server della sessione.

Prima il logout cancellava solo il cookie dal browser: il token firmato restava
valido fino alla scadenza (12 ore) per chiunque l'avesse copiato. Ora ogni
token porta un 'jti' e il logout ne registra l'hash in 'revoked_sessions'.
"""
import hashlib
import hmac
import time

from fastapi.testclient import TestClient

import app as app_module
import auth
import db
from conftest import ROLE_PASSWORD, USERNAME


def _fresh_login(role="viewer"):
    c = TestClient(app_module.app)
    r = c.post("/api/login", json={"username": USERNAME(role=role),
                                    "password": ROLE_PASSWORD})
    assert r.status_code == 200, r.text
    return c, c.cookies.get(auth.SESSION_COOKIE)


def _with_cookie(token):
    c = TestClient(app_module.app)
    c.cookies.set(auth.SESSION_COOKIE, token)
    return c


def test_copied_token_is_dead_after_logout(role_user_ids):
    c, token = _fresh_login()
    thief = _with_cookie(token)
    assert thief.get("/api/me").status_code == 200
    c.get("/logout", follow_redirects=False)
    assert thief.get("/api/me").status_code == 401


def test_logout_closes_only_that_session(role_user_ids):
    """Un logout dal portatile non butta fuori lo stesso utente dal desktop."""
    laptop, laptop_tok = _fresh_login()
    _, desktop_tok = _fresh_login()
    laptop.get("/logout", follow_redirects=False)
    assert _with_cookie(laptop_tok).get("/api/me").status_code == 401
    assert _with_cookie(desktop_tok).get("/api/me").status_code == 200


def test_every_login_gets_its_own_session_id(role_user_ids):
    _, a = _fresh_login()
    _, b = _fresh_login()
    assert auth.parse_session_token(a).jti != auth.parse_session_token(b).jti


def test_double_logout_is_harmless(role_user_ids):
    c, token = _fresh_login()
    assert auth.revoke_session(token) is True
    assert auth.revoke_session(token) is True
    assert _with_cookie(token).get("/api/me").status_code == 401


def test_revocation_stores_only_a_hash(role_user_ids):
    _, token = _fresh_login()
    st = auth.parse_session_token(token)
    auth.revoke_session(token)
    rows = (db._get_client().table("revoked_sessions").select("*")
            .eq("user_id", st.user_id).execute().data)
    assert rows and all(st.jti not in str(r) for r in rows)
    assert any(r["jti_hash"] == st.jti_hash for r in rows)


def test_swapping_the_session_id_breaks_the_signature(role_user_ids):
    _, token = _fresh_login()
    uid, exp, iat, jti, sig = token.split(".")
    forged = f"{uid}.{exp}.{iat}.{'x' * len(jti)}.{sig}"
    assert _with_cookie(forged).get("/api/me").status_code == 401


def test_previous_token_format_is_rejected(role_user_ids):
    """Token a 4 parti (pre-jti): anche se firmato bene non si potrebbe mai
    revocare, quindi non vale piu'."""
    uid = role_user_ids["viewer"]
    now = int(time.time())
    payload = f"{uid}.{now + 3600}.{now}"
    sig = hmac.new(auth._secret(), payload.encode(), hashlib.sha256).hexdigest()
    assert _with_cookie(f"{payload}.{sig}").get("/api/me").status_code == 401


def test_unknown_revocation_state_fails_closed(role_user_ids, monkeypatch):
    _, token = _fresh_login()
    monkeypatch.setattr(db, "is_session_revoked", lambda h: None)
    assert _with_cookie(token).get("/api/me").status_code == 401


def test_logout_revokes_even_a_session_stuck_on_password_change(role_user_ids):
    uid = db.insert_user({"username": "_ftest_revoke_forced", "role": "viewer",
                          "password_hash": auth.hash_password(ROLE_PASSWORD),
                          "is_active": True, "must_change_password": True})
    try:
        c = TestClient(app_module.app)
        assert c.post("/api/login", json={"username": "_ftest_revoke_forced",
                                          "password": ROLE_PASSWORD}).status_code == 200
        token = c.cookies.get(auth.SESSION_COOKIE)
        c.get("/logout", follow_redirects=False)
        assert db.is_session_revoked(auth.parse_session_token(token).jti_hash) is True
    finally:
        db.delete_user(uid)


def test_expired_revocations_are_purged_on_next_logout(role_user_ids):
    st_uid = role_user_ids["viewer"]
    stale = "_ftest_stale_" + str(time.time())
    db._get_client().table("revoked_sessions").insert({
        "jti_hash": stale, "user_id": st_uid,
        "expires_at": "2000-01-01T00:00:00+00:00"}).execute()
    _, token = _fresh_login()
    auth.revoke_session(token)
    left = (db._get_client().table("revoked_sessions").select("jti_hash")
            .eq("jti_hash", stale).execute().data)
    assert left == []


def test_logout_is_audited_with_the_revocation_outcome(role_clients, role_user_ids):
    c, _ = _fresh_login("viewer")
    c.get("/logout", follow_redirects=False)
    ev = role_clients["admin"].get("/api/audit/events",
                                   params={"action": "auth.logout", "page_size": 5}).json()
    rows = ev.get("rows") or ev.get("events") or []
    mine = [r for r in rows if r.get("actor_name") == USERNAME(role="viewer")]
    assert mine and mine[0].get("detail", {}).get("session_revoked") is True

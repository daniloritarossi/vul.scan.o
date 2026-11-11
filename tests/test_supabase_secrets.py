"""
Segreti Supabase per installazione (supabase/gen_secrets.py).

Unitari puri: niente DB, niente Docker. Verificano che ogni installazione
riceva segreti propri, che i valori demo un tempo versionati vengano
riconosciuti e sostituiti, e che le chiavi siano JWT validi per PostgREST.
"""
import hashlib
import importlib.util
import os
import stat
from pathlib import Path

import pytest

_PATH = Path(__file__).parent.parent / "supabase" / "gen_secrets.py"
_spec = importlib.util.spec_from_file_location("gen_secrets", _PATH)
gs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gs)


def _read(p):
    return gs.parse_env(Path(p).read_text())


def test_fresh_install_generates_all_secrets_with_private_mode(tmp_path):
    env = tmp_path / ".env"
    assert gs.main(str(env)) == "generated"
    v = _read(env)
    assert len(v["JWT_SECRET"]) == 64 and len(v["POSTGRES_PASSWORD"]) == 48
    assert gs.jwt_role(v["ANON_KEY"], v["JWT_SECRET"]) == "anon"
    assert gs.jwt_role(v["SERVICE_ROLE_KEY"], v["JWT_SECRET"]) == "service_role"
    assert v["DEFAULT_PROJECT_NAME"] == "VulnFeedAggregator"
    assert stat.S_IMODE(os.stat(env).st_mode) == 0o600


def test_two_installations_never_share_secrets(tmp_path):
    a, b = tmp_path / "a.env", tmp_path / "b.env"
    gs.main(str(a)), gs.main(str(b))
    va, vb = _read(a), _read(b)
    for k in gs.SECRET_KEYS:
        assert va[k] != vb[k], k
    # La chiave di un'installazione non vale sull'altra.
    assert gs.jwt_role(va["SERVICE_ROLE_KEY"], vb["JWT_SECRET"]) is None


def test_rerun_is_idempotent(tmp_path):
    env = tmp_path / ".env"
    gs.main(str(env))
    before = env.read_text()
    assert gs.main(str(env)) == "ok"
    assert env.read_text() == before


@pytest.mark.parametrize("name", ["JWT_SECRET", "POSTGRES_PASSWORD"])
def test_demo_secret_is_replaced_and_other_settings_kept(tmp_path, monkeypatch, name):
    demo = "public-demo-value-from-the-repository"
    monkeypatch.setitem(gs.DEMO_FINGERPRINTS, name,
                        {hashlib.sha256(demo.encode()).hexdigest()})
    secret = "a" * 64
    env = tmp_path / ".env"
    env.write_text(
        f"POSTGRES_PASSWORD={demo if name == 'POSTGRES_PASSWORD' else 'x' * 48}\n"
        f"JWT_SECRET={demo if name == 'JWT_SECRET' else secret}\n"
        f"ANON_KEY={gs.make_key('anon', secret)}\n"
        f"SERVICE_ROLE_KEY={gs.make_key('service_role', secret)}\n"
        "DEFAULT_PROJECT_NAME=Custom\n")
    assert gs.main(str(env)) == "generated"
    v = _read(env)
    assert demo not in env.read_text()
    assert v["DEFAULT_PROJECT_NAME"] == "Custom"
    assert gs.jwt_role(v["SERVICE_ROLE_KEY"], v["JWT_SECRET"]) == "service_role"


def test_keys_not_matching_secret_are_resigned_without_touching_password(tmp_path):
    env = tmp_path / ".env"
    gs.main(str(env))
    v = _read(env)
    stale = gs.make_key("service_role", "b" * 64)
    env.write_text(env.read_text().replace(v["SERVICE_ROLE_KEY"], stale))
    assert gs.main(str(env)) == "resigned"
    w = _read(env)
    assert w["JWT_SECRET"] == v["JWT_SECRET"]
    assert w["POSTGRES_PASSWORD"] == v["POSTGRES_PASSWORD"]
    assert gs.jwt_role(w["SERVICE_ROLE_KEY"], w["JWT_SECRET"]) == "service_role"


def test_status_output_never_contains_a_secret(tmp_path, capsys):
    env = tmp_path / ".env"
    status = gs.main(str(env))
    v = _read(env)
    assert all(v[k] not in status for k in gs.SECRET_KEYS)


def test_repository_ships_no_supabase_secret():
    root = Path(__file__).parent.parent
    import subprocess
    tracked = subprocess.run(["git", "ls-files", "supabase/.env"], cwd=root,
                             capture_output=True, text=True).stdout.strip()
    assert tracked == "", "supabase/.env non deve essere versionato"
    src = (root / "db.py").read_text()
    assert "eyJ" not in src, "db.py non deve contenere una chiave JWT"

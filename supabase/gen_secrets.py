"""
gen_secrets.py
--------------
Genera i segreti dello stack Supabase locale, DIVERSI per ogni installazione.

Prima di questo script supabase/.env era versionato: JWT secret, chiavi
anon/service_role e password Postgres erano gli stessi in ogni copia del
progetto, cioe' pubblici. Chiunque raggiungesse il gateway (8001) o Postgres
(5432) di un'installazione qualsiasi poteva leggere e riscrivere tutto,
password_hash degli utenti compresi.

Uso (da supabase/setup.sh):  python3 -I gen_secrets.py .env

Idempotente. Rigenera SOLO se serve:
  - .env assente o senza uno dei segreti                -> genera tutto
  - JWT_SECRET o POSTGRES_PASSWORD sono quelli demo     -> genera tutto
    (installazioni create quando .env era versionato)
  - chiavi non firmate con il JWT_SECRET attuale        -> rifirma le chiavi
Le altre variabili (DEFAULT_ORGANIZATION_NAME, ...) restano intatte.

Stampa su stdout una sola parola, mai un segreto:
  generated  segreti nuovi (password Postgres cambiata: setup.sh la applica ai ruoli)
  resigned   rifirmate le sole chiavi JWT
  ok         niente da fare
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
import time

# SHA-256 dei valori demo che erano versionati in supabase/.env (8fa9e47).
# Si confronta l'impronta e non il valore: il segreto pubblico non torna nel
# codice, e un'installazione che lo usa ancora viene comunque riconosciuta.
DEMO_FINGERPRINTS = {
    "JWT_SECRET": {"a064b502e61d27e94b8717290e5e1b32e36720e9fbdf952ec81a84c07128cb37"},
    "POSTGRES_PASSWORD": {"95ad77275e9a455e150f73bbd8619e4324b42626ef71aa96ef16991f4b4082c1"},
}

SECRET_KEYS = ("POSTGRES_PASSWORD", "JWT_SECRET", "ANON_KEY", "SERVICE_ROLE_KEY")

DEFAULTS = {
    "DEFAULT_ORGANIZATION_NAME": "Local",
    "DEFAULT_PROJECT_NAME": "VulnFeedAggregator",
}

# Chiavi a lunga durata: le usano solo l'app e gli script locali, e cambiarle
# richiede di rilanciare setup.sh. Dieci anni come le chiavi demo di Supabase.
KEY_TTL = 10 * 365 * 24 * 3600

HEADER = """\
# Supabase locale — segreti di QUESTA installazione.
# Generato da supabase/gen_secrets.py (chiamato da setup.sh). NON versionare,
# NON copiare su un'altra installazione: ognuna deve avere i propri.
# Per rigenerare: cancella questo file e rilancia ./setup.sh (la password dei
# ruoli Postgres viene riallineata, i dati restano).
"""


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_jwt(payload: dict, secret: str) -> str:
    """JWT HS256 (quello che PostgREST verifica con PGRST_JWT_SECRET)."""
    head = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"},
                              separators=(",", ":")).encode())
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64url(sig)}"


def jwt_role(token: str, secret: str):
    """Ruolo del token se la firma combacia con 'secret', altrimenti None."""
    try:
        head, body, sig = token.split(".")
        expect = hmac.new(secret.encode(), f"{head}.{body}".encode(),
                          hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_decode(sig), expect):
            return None
        return json.loads(_b64url_decode(body)).get("role")
    except Exception:
        return None


def make_key(role: str, secret: str, now: int | None = None) -> str:
    now = int(time.time()) if now is None else now
    return sign_jwt({"role": role, "iss": "vfa-local", "iat": now,
                     "exp": now + KEY_TTL}, secret)


def _is_demo(name: str, value: str) -> bool:
    digest = hashlib.sha256(value.encode()).hexdigest()
    return digest in DEMO_FINGERPRINTS.get(name, set())


def parse_env(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip("'\"")
    return out


def render_env(values: dict) -> str:
    lines = [HEADER]
    for k in SECRET_KEYS:
        lines.append(f"{k}={values[k]}")
    lines.append("")
    for k, v in values.items():
        if k not in SECRET_KEYS:
            lines.append(f"{k}={v}")
    return "\n".join(lines) + "\n"


def ensure(values: dict) -> tuple[dict, str]:
    """Ritorna (valori aggiornati, stato). Funzione pura: niente I/O."""
    values = {**DEFAULTS, **values}
    missing = any(not values.get(k) for k in ("POSTGRES_PASSWORD", "JWT_SECRET"))
    demo = any(_is_demo(k, values.get(k, "")) for k in ("POSTGRES_PASSWORD", "JWT_SECRET"))
    if missing or demo:
        values["POSTGRES_PASSWORD"] = secrets.token_hex(24)
        values["JWT_SECRET"] = secrets.token_hex(32)
        values["ANON_KEY"] = make_key("anon", values["JWT_SECRET"])
        values["SERVICE_ROLE_KEY"] = make_key("service_role", values["JWT_SECRET"])
        return values, "generated"
    secret = values["JWT_SECRET"]
    if (jwt_role(values.get("ANON_KEY", ""), secret) != "anon"
            or jwt_role(values.get("SERVICE_ROLE_KEY", ""), secret) != "service_role"):
        values["ANON_KEY"] = make_key("anon", secret)
        values["SERVICE_ROLE_KEY"] = make_key("service_role", secret)
        return values, "resigned"
    return values, "ok"


def write_atomic(path: str, text: str) -> None:
    """Scrive con permessi 0600 fin dalla creazione, poi rinomina."""
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".env.", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def main(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            current = parse_env(fh.read())
    except FileNotFoundError:
        current = {}
    values, status = ensure(current)
    if status != "ok":
        write_atomic(path, render_env(values))
    elif os.stat(path).st_mode & 0o077:
        os.chmod(path, 0o600)
    return status


if __name__ == "__main__":
    print(main(sys.argv[1] if len(sys.argv) > 1 else ".env"))

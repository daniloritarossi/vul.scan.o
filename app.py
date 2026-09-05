"""
app.py
------
Server FastAPI del Vulnerability Feed Aggregator.

Endpoint:
  GET  /                -> pagina web (form + tabella risultati).
  POST /api/identify    -> dato il testo della vulnerabilita', ritorna il
                           "Software Target" identificato (OSINT/locale).
  GET  /api/scan        -> esegue la scansione dell'inventario e trasmette i
                           risultati in tempo reale via SSE (Server-Sent Events),
                           un asset alla volta.
  GET  /api/assets      -> elenco asset dell'inventario (senza password).

Avvio:
    uvicorn app:app --reload --port 8000
"""

import json
import logging
import os
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Request
from fastapi.responses import (HTMLResponse, JSONResponse, RedirectResponse,
                               Response, StreamingResponse)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import asset_import
from assets import (load_assets, get_asset, add_asset, update_asset,
                    set_asset_enabled, update_asset_fields, delete_asset,
                    Asset, AssetStoreError)
from crypto import encrypt_password, is_encrypted, decrypt_password
from config import load_config, save_config
from osint import identify_product, extract_local
from scanner import scan_asset, _get_simulate_auth as _simulate_auth, version_affected
from cve import (query_osv, summarize_cves, query_osv_ids, extract_affected_version,
                 query_osv_ecosystem, os_ecosystem, generate_remediation,
                 generate_triage_report, compute_fix_plan)
from db import (persist_scan, persist_result, update_scan_summary, fetch_audit,
                verify_audit_chain,
                create_posture_run, persist_posture_asset, finalize_posture_run,
                fetch_posture, fetch_posture_runs, fetch_posture_sbom,
                fetch_findings, fetch_findings_by_fps, upsert_findings,
                set_finding_status, close_stale_posture_findings,
                log_finding_events, fetch_finding_events, verify_findings_chain,
                verify_posture_chain)
from posture import scan_asset_posture
from sbom_export import (sbom_rows, build_cyclonedx, build_spdx,
                         filter_rows, group_by_component, sort_rows, summarize_sbom)
from risk import assess_run_risk, compute_trend
from ingest import ingest_report, IngestError, SUPPORTED_TOOLS
from findings import (fingerprint, merge_findings, posture_findings,
                      summarize, is_breached, STATUSES,
                      lifecycle_events, parse_as_of, reconstruct_as_of,
                      compare_states)
from ticketing import (create_ticket, check_connection, fetch_ticket_status,
                       ref_provider, TicketError)
from localscan import run_gitleaks, run_trivy_image, LocalScanError
from compliance import derive_compliance, compliance_summary
from db import fetch_finding, set_finding_ticket, set_finding_ticket_status
import db
from auth import (AuthRequired, Forbidden, PasswordChangeRequired, CurrentUser,
                  get_current_user, require_roles, visible_asset_ids,
                  visible_asset_ips, make_session_token, verify_password,
                  hash_password, ensure_default_admin, create_onetime_token,
                  consume_onetime_token, set_user_password,
                  password_policy_error, SESSION_COOKIE, SESSION_TTL, ROLES)
from auth import _secret as _hmac_secret
import evidence
import msrc
import nvd
import ratelimit
from mailer import (send_activation, send_reset, activation_link,
                    smtp_enabled, MailError)

logger = logging.getLogger("vfa.app")

BASE_DIR = Path(__file__).parent
ASSETS_FILE = BASE_DIR / "assets.txt"

# Flag 'Secure' del cookie di sessione: attivo di default, disattivabile solo
# per lo sviluppo locale su http (VFA_COOKIE_SECURE=0). In produzione (dietro
# TLS) il cookie NON deve mai viaggiare in chiaro.
COOKIE_SECURE = os.environ.get("VFA_COOKIE_SECURE", "1") != "0"

# Fiducia in X-Forwarded-For: attiva SOLO dietro un reverse proxy che riscrive
# l'header (VFA_TRUST_PROXY=1). Esposta direttamente, l'applicazione riceve
# quell'header dal client e crederebbe a qualunque indirizzo dichiari.
TRUST_PROXY = os.environ.get("VFA_TRUST_PROXY", "0") == "1"


def _set_session_cookie(resp, user_id: int) -> None:
    """Imposta il cookie di sessione firmato con i flag di sicurezza uniformi."""
    resp.set_cookie(SESSION_COOKIE, make_session_token(user_id),
                    max_age=SESSION_TTL, httponly=True,
                    samesite="lax", secure=COOKIE_SECURE)

# Versione scritta da start.sh quando aggiorna da tarball (installazioni senza
# .git: lo zip di una release non porta con se' la storia).
VERSION_FILE = BASE_DIR / ".vfa_version"


def _git_version() -> str:
    """
    Versione dell'installazione corrente.

    Ordine: tag git ('v1.0.1-alfa', o 'v1.0.1-alfa-3-gabc1234' se HEAD e' oltre
    il tag), poi .vfa_version (scritto da start.sh sugli aggiornamenti da
    tarball), infine 'dev'. Senza il secondo passaggio un'installazione da zip
    non saprebbe MAI quale versione sta eseguendo.
    """
    try:
        out = subprocess.run(
            ["git", "describe", "--tags", "--always"],
            cwd=BASE_DIR, capture_output=True, text=True, timeout=3,
        )
        v = out.stdout.strip()
        if v:
            return v
    except Exception:
        pass
    try:
        v = VERSION_FILE.read_text(encoding="utf-8").strip()
        if v:
            return v
    except Exception:
        pass
    return "dev"


APP_VERSION = _git_version()

# Repo GitHub per il check aggiornamenti (override con VFA_GITHUB_REPO).
GITHUB_REPO = os.environ.get("VFA_GITHUB_REPO", "daniloritarossi/vul.scan.o")


def _base_tag(version: str) -> str:
    """'v1.0.11-alfa-3-gabc1234' -> 'v1.0.11-alfa' (output di git describe)."""
    import re
    return re.sub(r"-\d+-g[0-9a-f]+$", "", (version or "").strip())


def _version_tuple(tag: str):
    """'v1.0.11-alfa' -> (1, 0, 11) per il confronto numerico. None se non parsabile."""
    import re
    m = re.match(r"v?(\d+)\.(\d+)(?:\.(\d+))?", tag or "")
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


# Cache del check remoto: 1 chiamata GitHub ogni 6 ore, non a ogni pagina.
_version_cache = {"at": 0.0, "release": None, "tags": None}


def _release_build() -> Optional[dict]:
    """
    Versione dell'installazione espressa in RELEASE: {base, ahead}.

    'git describe' da solo risponde col tag piu' recente, rilasciato o no, e il
    sito finiva per esibire una versione che come release non esiste. Qui si
    chiede a git la distanza dall'ultima release PUBBLICATA raggiungibile da
    HEAD (--match ripetuto sui soli tag rilasciati):

        base='v1.0.60-beta', ahead=0  -> l'installazione E' quella release
        base='v1.0.60-beta', ahead=1  -> una build oltre quella release

    None se GitHub non e' raggiungibile (non si conoscono le release), se non
    c'e' git, o se nessuna release e' raggiungibile da HEAD: in quei casi resta
    la versione locale, senza inventare corrispondenze.
    """
    tags = _released_tags()
    if not tags:
        return None
    cmd = ["git", "describe", "--tags", "--long", "--always"]
    for t in sorted(tags):
        cmd += ["--match", t]
    try:
        out = subprocess.run(cmd, cwd=BASE_DIR, capture_output=True,
                             text=True, timeout=3)
        desc = out.stdout.strip()
    except Exception:
        return None
    # Formato: '<tag>-<n>-g<sha>'. Senza tag raggiungibile git risponde col solo
    # sha abbreviato, che non e' una versione.
    import re
    m = re.match(r"^(.*)-(\d+)-g[0-9a-f]+$", desc)
    if not m or m.group(1) not in tags:
        return None
    return {"base": m.group(1), "ahead": int(m.group(2))}


def _released_tags() -> Optional[set]:
    """
    Tag che corrispondono a una release PUBBLICATA. None se GitHub non risponde.

    Serve a dire se la versione in esecuzione e' una release o un tag interno:
    la versione mostrata nel sito viene da 'git describe', che prende il tag
    piu' recente indipendentemente dal fatto che sia mai stato rilasciato.
    """
    _fetch_latest_release()          # popola la cache (una sola chiamata)
    return _version_cache.get("tags")


def _fetch_latest_release() -> Optional[dict]:
    """
    Release pubblicata piu' recente su GitHub.
    {tag, name, url, prerelease, published_at}, None se irraggiungibile.

    Si guarda alle RELEASE, non ai tag: un tag puo' esistere senza release
    (lavoro taggato ma non ancora pubblicato) e proporlo come aggiornamento
    manderebbe l'utente su una versione che nessuno ha rilasciato.

    Non si usa /releases/latest: quell'endpoint ESCLUDE le prerelease, e questo
    progetto pubblica solo '-beta' — risponderebbe 404 nascondendo ogni
    aggiornamento. Si prende quindi l'elenco e si sceglie la versione massima
    fra le release pubblicate (draft esclusi: non sono pubbliche). A parita' di
    versione una release stabile batte una prerelease.
    """
    import time as _time
    import requests as _req
    now = _time.time()
    if _version_cache["release"] and now - _version_cache["at"] < 6 * 3600:
        return _version_cache["release"]
    try:
        r = _req.get(f"https://api.github.com/repos/{GITHUB_REPO}/releases",
                     params={"per_page": 30},
                     headers={"Accept": "application/vnd.github+json"},
                     timeout=6)
        r.raise_for_status()
        best, best_key, tags = None, None, set()
        for rel in r.json():
            if rel.get("draft"):
                continue
            tag = rel.get("tag_name") or ""
            tags.add(tag)
            ver = _version_tuple(tag)
            if not ver:
                continue
            key = (ver, 0 if rel.get("prerelease") else 1)
            if best_key is None or key > best_key:
                best_key, best = key, {
                    "tag": tag,
                    "name": rel.get("name") or tag,
                    "url": rel.get("html_url"),
                    "prerelease": bool(rel.get("prerelease")),
                    "published_at": rel.get("published_at"),
                }
        _version_cache.update({"at": now, "release": best, "tags": tags})
        return best
    except Exception as exc:
        logger.info("check versione GitHub fallito: %s", exc)
        return None

app = FastAPI(title="Vulnerability Feed Aggregator", version=APP_VERSION)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.globals["app_version"] = APP_VERSION
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# ---------------------------------------------------------------------------
# AUTENTICAZIONE / RBAC (cono di visibilita')
# ---------------------------------------------------------------------------

@app.on_event("startup")
def _seed_default_admin():
    """Crea admin/admin al primo avvio (best-effort, vedi auth.py)."""
    ensure_default_admin()


@app.exception_handler(AuthRequired)
async def _auth_required_handler(request: Request, exc: AuthRequired):
    """API -> 401 JSON; pagine -> redirect alla login."""
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": "Autenticazione richiesta"}, status_code=401)
    return RedirectResponse("/login", status_code=303)


@app.exception_handler(Forbidden)
async def _forbidden_handler(request: Request, exc: Forbidden):
    """Ruolo/scope insufficiente: 403 per le API, home per le pagine.

    Ogni rifiuto finisce nel registro attivita': i tentativi di accesso NEGATI
    sono meta' del valore di un audit di autorizzazione — dicono chi ha provato
    a uscire dal proprio ruolo o dal proprio cono di visibilita'.
    """
    try:
        denied_user = get_current_user(request)
    except Exception:
        denied_user = None
    _audit("authz.denied", request, denied_user, outcome="denied",
           target={"type": "endpoint", "id": request.url.path,
                   "label": f"{request.method} {request.url.path}"},
           detail={"reason": exc.detail})
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": exc.detail}, status_code=403)
    return RedirectResponse("/", status_code=303)


@app.exception_handler(PasswordChangeRequired)
async def _pwchange_handler(request: Request, exc: PasswordChangeRequired):
    """Cambio password obbligatorio: blocca tutto tranne /change-password."""
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": "Cambio password obbligatorio",
                             "code": "password_change_required"},
                            status_code=403)
    return RedirectResponse("/change-password", status_code=303)


# Dependency riutilizzabili per la matrice dei ruoli.
_admin_only = require_roles("admin")
_admin_manager = require_roles("admin", "manager")
_writer = require_roles("admin", "manager", "editor")   # scritture reali
# Lettura del registro di audit e dell'evidenza point-in-time. NON e' un
# permesso di scrittura: prima queste rotte usavano _writer, cioe' una lettura
# protetta da un alias di scrittura ("chiunque non sia viewer"), il che
# lasciava fuori proprio la persona che l'audit lo deve leggere.
# 'stakeholder' resta fuori come 'viewer': il registro espone 'actor_name',
# cioe' attivita' attribuibile a persone identificate, e un asset owner di
# reparto non deve leggere chi ha fatto cosa.
_audit_reader = require_roles("admin", "manager", "editor", "auditor")
# Export di dati read-only che sono un deliverable d'audit (SBOM standard).
_exporter = require_roles("admin", "manager", "editor", "auditor")


def _require_asset_in_scope(user: CurrentUser, asset_id: int) -> None:
    """403 se l'editor tenta di operare su un asset fuori dal suo cono."""
    ids = visible_asset_ids(user)
    if ids is not None and asset_id not in ids:
        raise Forbidden("Asset fuori dal tuo cono di visibilita'")


def _require_ip_in_scope(user: CurrentUser, ip: str) -> None:
    """403 se l'editor tenta di operare su un finding di un host fuori scope."""
    ips = visible_asset_ips(user)
    if ips is not None and (ip or "") not in ips:
        raise Forbidden("Asset fuori dal tuo cono di visibilita'")


def _req_meta(request: Request | None) -> dict:
    """
    Provenienza della richiesta per il registro attivita' (ip + user agent).

    X-Forwarded-For viene letto SOLO se VFA_TRUST_PROXY=1, cioe' se davanti
    all'applicazione c'e' davvero un reverse proxy che lo riscrive. Senza
    quella garanzia l'header e' scrivibile dal client: bastava cambiarlo a ogni
    richiesta per falsificare il 'da dove' del registro d'audit e per farla
    franca col contatore per indirizzo del rate limit sul login.
    """
    if request is None:
        return {}
    ip = ""
    if TRUST_PROXY:
        ip = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    ip = ip or (request.client.host if request.client else "")
    return {"ip": ip or None, "user_agent": request.headers.get("user-agent") or ""}


def _audit(action: str, request: Request | None = None,
           user: CurrentUser | None = None, outcome: str = "success",
           target: dict | None = None, detail: dict | None = None,
           actor: dict | None = None) -> None:
    """
    Registra un'azione nel registro attivita' (chi/cosa/su cosa/da dove).

    Scrittura best-effort: il registro non deve mai far fallire l'operazione
    dell'utente. 'actor' esplicito serve alle azioni senza sessione (login
    fallito, attivazione via token), dove l'attore non e' l'utente corrente.
    """
    if actor is None and user is not None:
        actor = {"id": user.id, "name": user.username, "role": user.role}
    try:
        db.log_audit_event(action, outcome=outcome, actor=actor, target=target,
                           detail=detail, request_meta=_req_meta(request))
    except Exception as exc:                      # difesa in profondita'
        logger.warning("audit '%s' non registrato: %s", action, exc)


def _filter_posture_run(run: dict, ips) -> dict:
    """Copia della run di postura limitata agli asset con ip nel set indicato."""
    if not run or ips is None:
        return run
    filtered = dict(run)
    filtered["posture_assets"] = [
        pa for pa in (run.get("posture_assets") or []) if pa.get("ip") in ips
    ]
    return filtered


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    """Pagina di login (unica pagina accessibile senza sessione)."""
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/api/login")
async def api_login(request: Request):
    """Verifica credenziali e apre la sessione (cookie HttpOnly firmato)."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    src_ip = _req_meta(request).get("ip") or ""
    # Freno al password guessing PRIMA di toccare il DB e l'hash: superata la
    # soglia il tentativo non viene nemmeno valutato. Il conteggio comprende
    # gli username inesistenti, altrimenti "va in blocco" varrebbe come
    # conferma che l'account esiste.
    wait = ratelimit.retry_after(username, src_ip, load_config().get("auth"))
    if wait:
        if ratelimit.should_announce(username, src_ip):
            _audit("auth.throttled", request, outcome="denied",
                   actor={"name": username or None},
                   detail={"username": username, "retry_after": wait,
                           "reason": "too_many_failed_logins"})
        # Ritardo fisso: un rifiuto istantaneo distinguerebbe "bloccato" da
        # "password sbagliata" col solo cronometro.
        time.sleep(0.5)
        return JSONResponse(
            {"error": "Troppi tentativi di accesso. Riprova più tardi.",
             "code": "too_many_attempts", "retry_after": wait},
            status_code=429, headers={"Retry-After": str(wait)})
    row = db.fetch_user_by_username(username) if username else None
    # Account invitato ma mai attivato: password_hash assente o is_active falso.
    # Risposta identica alle credenziali errate (no enumeration).
    if (not row or not row.get("password_hash")
            or not row.get("is_active", True)
            or not verify_password(password, row["password_hash"])):
        ratelimit.record_failure(username, src_ip, load_config().get("auth"))
        # Il registro invece DISTINGUE il motivo: la risposta HTTP non deve
        # rivelare se l'utente esiste, ma un audit di sicurezza deve poter
        # separare "password sbagliata su account reale" (possibile attacco a
        # credenziali) da "username inesistente" (enumerazione).
        reason = ("unknown_user" if not row
                  else "inactive" if not row.get("is_active", True)
                  or not row.get("password_hash") else "bad_password")
        _audit("auth.login", request, outcome="failure",
               actor={"id": (row or {}).get("id"), "name": username or None,
                      "role": (row or {}).get("role")},
               detail={"username": username, "reason": reason})
        return JSONResponse({"error": "Credenziali non valide"}, status_code=401)
    # Credenziali corrette: l'account riparte pulito. Il contatore per
    # INDIRIZZO resta, un successo su un account non assolve l'origine che sta
    # provando gli altri.
    ratelimit.clear_user(username)
    _audit("auth.login", request,
           actor={"id": row["id"], "name": row["username"], "role": row["role"]},
           detail={"must_change_password": bool(row.get("must_change_password"))})
    resp = JSONResponse({"ok": True, "username": row["username"], "role": row["role"],
                         "must_change_password": bool(row.get("must_change_password"))})
    _set_session_cookie(resp, row["id"])
    return resp


@app.get("/logout")
def logout(request: Request):
    """Chiude la sessione e torna alla login."""
    # L'utente e' risolto dal cookie senza dependency: /logout deve funzionare
    # anche con una sessione ormai invalida (in quel caso non c'e' nulla da
    # registrare, la sessione era gia' chiusa).
    try:
        user = get_current_user(request)
    except Exception:
        user = None
    if user is not None:
        _audit("auth.logout", request, user)
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.get("/api/me")
def api_me(user: CurrentUser = Depends(get_current_user)):
    """Utente corrente (per la UI: chip utente, visibilita' voci di menu)."""
    return user.to_dict()


@app.get("/api/version/check")
def api_version_check(user: CurrentUser = Depends(get_current_user)):
    """
    Confronta la versione installata con l'ultima RELEASE pubblicata su GitHub.
    Risposta cache-ata lato server (6h) per non consumare rate limit.

    {current, current_known, latest, latest_url, prerelease, published_at,
     update_available, repo_url}

    Il confronto e' sempre numerico: se la versione locale non e' riconoscibile
    (installazione da sorgenti senza tag ne' .vfa_version) 'update_available'
    resta false e 'current_known' lo dichiara. Prima bastava che le due stringhe
    fossero diverse per annunciare un aggiornamento, e un'installazione 'dev'
    vedeva il banner per sempre, anche sull'ultima versione.
    """
    # Riletta a ogni chiamata: APP_VERSION e' congelata all'avvio del processo
    # e diventa stantia se nel frattempo viene creato/checkout-ato un tag.
    current = _base_tag(_git_version())
    release = _fetch_latest_release() or {}
    latest = release.get("tag")
    cur_v, lat_v = _version_tuple(current), _version_tuple(latest)
    update = bool(cur_v and lat_v and lat_v > cur_v)
    # La versione mostrata nel sito viene da 'git describe', che prende il tag
    # piu' recente anche se non e' mai stato rilasciato. Qui si dice se quella
    # versione corrisponde a una release pubblicata: None = non verificabile
    # (GitHub irraggiungibile), e in quel caso l'interfaccia non afferma nulla.
    tags = _released_tags()
    released = None if tags is None else (current in tags)
    # Versione da MOSTRARE: la release da cui deriva la build, non il tag piu'
    # recente. 'ahead' > 0 significa che si sta eseguendo qualcosa oltre quella
    # release, e va detto invece di spacciare la build per la release stessa.
    build = _release_build() or {}
    display = build.get("base") or current
    ahead = build.get("ahead")
    if released:                       # la build E' esattamente quella release
        display, ahead = current, 0
    return {"current": current, "current_known": cur_v is not None,
            "current_released": released,
            "display_version": display, "commits_ahead": ahead,
            "latest": latest, "latest_url": release.get("url"),
            "prerelease": release.get("prerelease"),
            "published_at": release.get("published_at"),
            "update_available": update,
            "repo_url": f"https://github.com/{GITHUB_REPO}"}


# ---------------------------------------------------------------------------
# Onboarding via email: attivazione account, reset e cambio password.
# ---------------------------------------------------------------------------

@app.get("/activate", response_class=HTMLResponse)
def activate_page(request: Request, token: str = ""):
    """Pagina di attivazione/reset: l'utente sceglie la propria password.
    Raggiungibile senza sessione (il token one-time E' la credenziale)."""
    return templates.TemplateResponse("activate.html",
                                      {"request": request, "token": token})


@app.post("/api/activate")
async def api_activate(request: Request):
    """
    Consuma un token one-time (attivazione o reset) e imposta la password
    scelta dall'utente. L'attivazione verifica implicitamente l'email.
    Body: {token, password}.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    token = (body.get("token") or "").strip()
    password = body.get("password") or ""
    err = password_policy_error(password)
    if err:
        return JSONResponse({"error": err}, status_code=400)
    # Prova entrambi i purpose: il token e' one-time e legato all'utente.
    user_row = consume_onetime_token(token, "activation")
    verified = user_row is not None
    if user_row is None:
        user_row = consume_onetime_token(token, "reset")
    if user_row is None:
        _audit("auth.token_redeem", request, outcome="failure",
               detail={"reason": "invalid_or_expired"})
        return JSONResponse({"error": "Token non valido o scaduto"}, status_code=400)
    if not set_user_password(user_row["id"], password):
        return JSONResponse({"error": "Supabase non raggiungibile"}, status_code=503)
    if verified and user_row.get("email") and not user_row.get("email_verified_at"):
        db.update_user(user_row["id"], {"email_verified_at": "now()"})
    # Attivazione e reset scrivono entrambi la password ma sono due fatti
    # diversi per un audit: il primo apre un account, il secondo ne
    # ricredenzializza uno esistente.
    _audit("auth.account_activate" if verified else "auth.password_reset_complete",
           request,
           actor={"id": user_row["id"], "name": user_row["username"],
                  "role": user_row.get("role")},
           target={"type": "user", "id": user_row["id"],
                   "label": user_row["username"]},
           detail={"email_verified": bool(verified and user_row.get("email"))})
    return {"ok": True, "username": user_row["username"]}


@app.get("/change-password", response_class=HTMLResponse)
def change_password_page(request: Request,
                         user: CurrentUser = Depends(get_current_user)):
    """Pagina di cambio password (anche in modalita' forzata)."""
    return templates.TemplateResponse(
        "change_password.html",
        {"request": request, "forced": user.must_change_password})


@app.post("/api/change-password")
async def api_change_password(request: Request,
                              user: CurrentUser = Depends(get_current_user)):
    """
    Cambio password dell'utente corrente. Body: {old_password, new_password}.
    Richiede la password attuale; invalida tutte le sessioni emesse prima
    (il nuovo cookie viene reimpostato in risposta).
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    old_pw = body.get("old_password") or ""
    new_pw = body.get("new_password") or ""
    err = password_policy_error(new_pw)
    if err:
        return JSONResponse({"error": err}, status_code=400)
    row = db.fetch_user(user.id)
    if not row or not verify_password(old_pw, row.get("password_hash") or ""):
        _audit("auth.password_change", request, user, outcome="failure",
               detail={"reason": "wrong_current_password"})
        return JSONResponse({"error": "Password attuale errata"}, status_code=400)
    if old_pw == new_pw:
        return JSONResponse({"error": "La nuova password deve essere diversa"},
                            status_code=400)
    if not set_user_password(user.id, new_pw):
        return JSONResponse({"error": "Supabase non raggiungibile"}, status_code=503)
    _audit("auth.password_change", request, user,
           target={"type": "user", "id": user.id, "label": user.username},
           detail={"forced": bool(user.must_change_password)})
    # La password vecchia non esiste piu': i fallimenti accumulati su di essa
    # non devono chiudere fuori chi ha appena scelto quella nuova.
    ratelimit.clear_user(user.username)
    # Nuovo cookie: quello corrente e' invalidato da password_changed_at.
    resp = JSONResponse({"ok": True})
    _set_session_cookie(resp, user.id)
    return resp


@app.post("/api/forgot")
async def api_forgot(request: Request):
    """
    "Password dimenticata": invia un link di reset se l'email corrisponde a
    un utente attivo. Risposta SEMPRE identica (no enumeration).
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    email = (body.get("email") or "").strip().lower()
    generic = {"ok": True,
               "message": "Se l'email corrisponde a un account, riceverai un link di reset."}
    if not email or not smtp_enabled():
        # Registrato comunque: un flusso di reset non partito perche' SMTP e'
        # spento e' un'informazione utile quando l'utente dice "non mi arriva
        # niente" — e resta la traccia del tentativo.
        _audit("auth.password_reset_request", request, outcome="failure",
               detail={"email": email or None,
                       "reason": "smtp_disabled" if email else "missing_email"})
        return generic
    row = db.fetch_user_by_email(email)
    if row and row.get("is_active"):
        token = create_onetime_token(row["id"], "reset")
        if token:
            try:
                send_reset(email, row["username"], token)
            except MailError as exc:
                logger.warning("send_reset fallita: %s", exc)
    # La RISPOSTA e' identica in ogni caso (no enumeration), il registro no:
    # 'matched' distingue un reset legittimo da un sondaggio di indirizzi.
    _audit("auth.password_reset_request", request,
           actor={"id": (row or {}).get("id"), "name": (row or {}).get("username"),
                  "role": (row or {}).get("role")},
           detail={"email": email, "matched": bool(row and row.get("is_active"))})
    return generic


@app.get("/", response_class=HTMLResponse)
def index(request: Request, user: CurrentUser = Depends(get_current_user)):
    """Serve la singola pagina dell'applicazione."""
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "simulate_auth": _simulate_auth()},
    )


@app.get("/assets", response_class=HTMLResponse)
def assets_page(request: Request, user: CurrentUser = Depends(get_current_user)):
    """Pagina di gestione (CRUD) dell'inventario asset."""
    return templates.TemplateResponse("assets.html", {"request": request})


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, user: CurrentUser = Depends(_audit_reader)):
    """Pagina AUDIT: storico dei risultati di scansione salvati su Supabase."""
    return templates.TemplateResponse("audit.html", {"request": request})


@app.get("/sbom", response_class=HTMLResponse)
def sbom_page(request: Request, user: CurrentUser = Depends(get_current_user)):
    """Pagina SBOM: Software Bill of Materials per asset dell'inventario."""
    return templates.TemplateResponse("sbom.html", {"request": request})


@app.get("/api/sbom")
def api_sbom(run_id: int | None = None,
             page: int = 0, page_size: int = 25,
             asset: str = "", pkg: str = "", q: str = "",
             vuln: str = "", license: str = "", group: str = "",
             sort: str = "", dir: str = "asc",
             user: CurrentUser = Depends(get_current_user)):
    """
    Inventario software della run di postura (tutti i componenti, non solo i
    vulnerabili). Ogni riga porta gli identificatori SBOM (purl, cpe, licenza,
    fornitore, sha256, relazioni) + classe di licenza.

    Server-side: filtri (asset/pkg/q/vuln/license), grouping per componente,
    ordinamento, paginazione, KPI di sintesi + elenco run. page_size=0 = tutto
    (usato dall'export). Editor: solo gli asset del proprio cono di visibilita'.
    """
    run = fetch_posture_sbom(run_id)
    runs_meta = fetch_posture_runs() or []
    runs = [{"id": r.get("id"), "created_at": r.get("created_at"),
             "assets_scanned": r.get("assets_scanned")} for r in runs_meta]
    if not run:
        return {"rows": [], "total": 0, "summary": summarize_sbom([]),
                "runs": runs, "page": page, "page_size": page_size, "group": group}
    run = _filter_posture_run(run, visible_asset_ips(user))
    rows = sbom_rows(run)
    rows = filter_rows(rows, asset=asset, pkg=pkg, q=q, vuln=vuln, license=license)
    summary = summarize_sbom(rows)          # KPI sul set filtrato (componenti reali)
    display = group_by_component(rows) if group == "component" else rows
    display = sort_rows(display, sort, dir)
    total = len(display)
    if page_size and page_size > 0:
        start = max(page, 0) * page_size
        display = display[start:start + page_size]
    return {"rows": display, "total": total, "summary": summary, "runs": runs,
            "page": page, "page_size": page_size, "group": group,
            "run_id": run.get("id")}


@app.get("/api/sbom/export")
def api_sbom_export(request: Request, format: str = "cyclonedx",
                    run_id: int | None = None,
                    user: CurrentUser = Depends(_exporter)):
    """
    Esporta la SBOM in formato standard.
    format: 'cyclonedx' (CycloneDX 1.5) | 'spdx' (SPDX 2.3).
    Download come file JSON.
    """
    run = fetch_posture_sbom(run_id)
    run = _filter_posture_run(run or {}, visible_asset_ips(user))
    fmt = (format or "cyclonedx").lower()
    if fmt == "spdx":
        doc = build_spdx(run or {})
        fname = "sbom.spdx.json"
    elif fmt == "cyclonedx":
        doc = build_cyclonedx(run or {})
        fname = "sbom.cdx.json"
    else:
        return JSONResponse({"error": f"formato non supportato: {format}"}, status_code=400)
    # L'export porta fuori l'inventario software completo: e' un'uscita di dati
    # e come tale va registrata (formato, run e ampiezza dello scope).
    _audit("export.sbom", request, user,
           target={"type": "posture_run", "id": (run or {}).get("id")},
           detail={"format": fmt,
                   "assets": len((run or {}).get("posture_assets") or []),
                   "scoped": visible_asset_ips(user) is not None})
    return JSONResponse(doc, headers={
        "Content-Disposition": f'attachment; filename="{fname}"',
    })


def _actor(user: CurrentUser) -> dict:
    """Snapshot dell'attore per i registri tamper-evident (scans, eventi)."""
    return {"id": user.id, "name": user.username}


@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request, user: CurrentUser = Depends(get_current_user)):
    """Pagina FINDINGS: ciclo di vita unificato (dedup + workflow + SLA)."""
    return templates.TemplateResponse("findings.html", {"request": request})


@app.get("/api/findings")
def api_findings(status: str | None = None, severity: str | None = None,
                 source: str | None = None, q: str | None = None,
                 user: CurrentUser = Depends(get_current_user)):
    """
    Elenco finding unificati + aggregati per la UI.
    Filtri opzionali: status, severity, source (substring), q (testo libero).
    Ruoli scoped (editor, stakeholder): solo i finding degli asset nel proprio
    cono di visibilita' (anche gli aggregati sono ricalcolati sul
    sottoinsieme, niente leak).
    503 se il DB non e' raggiungibile.
    """
    rows = fetch_findings()
    if rows is None:
        return JSONResponse({"error": "Supabase unreachable", "findings": []},
                            status_code=503)
    scope_ips = visible_asset_ips(user)
    if scope_ips is not None:
        rows = [r for r in rows if (r.get("asset_ip") or "") in scope_ips]
    summary = summarize(rows)   # aggregati sull'intero dataset, non sul filtro
    if status:
        rows = [r for r in rows if (r.get("status") or "open") == status]
    if severity:
        rows = [r for r in rows if (r.get("severity") or "").upper() == severity.upper()]
    if source:
        rows = [r for r in rows if source.lower() in (r.get("source") or "").lower()]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in json.dumps(r, default=str).lower()]
    for r in rows:
        r["sla_breached"] = is_breached(r)
        r["compliance"] = derive_compliance(r)
    summary["compliance"] = compliance_summary(rows)
    # Il provider configurato serve alla tabella per riconoscere i ticket
    # aperti con un tracker diverso da quello attivo: il loro stato agli atti
    # non e' piu' aggiornabile, e la riga deve poterlo dire da sola, senza
    # aspettare che qualcuno prema AGGIORNA. Non e' un segreto: e' il nome del
    # provider, non le sue credenziali.
    return {"findings": rows, "summary": summary,
            "ticketing_provider": ((load_config().get("ticketing") or {})
                                   .get("provider") or "")}


def _point_in_time(user: CurrentUser, date: str | None, since: str | None):
    """
    Ricostruisce lo stato dei finding a una data (e opzionalmente a una data
    precedente, col relativo delta), applicando il cono di visibilita'.

    Ritorna (payload, None) in caso di successo, (None, JSONResponse) se i
    parametri sono invalidi o il DB non risponde. Condiviso da
    /api/findings/as-of e dall'export di evidenza: i due DEVONO produrre gli
    stessi numeri, altrimenti il report firmato non dimostra cio' che l'API
    mostra a schermo.
    """
    try:
        as_of = parse_as_of(date)
        since_dt = parse_as_of(since) if since else None
    except ValueError as exc:
        return None, JSONResponse({"error": str(exc)}, status_code=400)
    if since_dt and since_dt > as_of:
        return None, JSONResponse({"error": "'since' deve precedere 'date'"},
                                  status_code=400)

    current = fetch_findings()
    events = fetch_finding_events(until=as_of.strftime("%Y-%m-%dT%H:%M:%S+00:00"))
    if current is None or events is None:
        return None, JSONResponse({"error": "Supabase unreachable"}, status_code=503)

    scope_ips = visible_asset_ips(user)
    if scope_ips is not None:
        by_fp = {r.get("fingerprint"): r for r in current}
        current = [r for r in current if (r.get("asset_ip") or "") in scope_ips]
        events = [
            e for e in events
            if (e.get("asset_ip")
                or by_fp.get(e.get("fingerprint"), {}).get("asset_ip")
                or "") in scope_ips
        ]

    state = reconstruct_as_of(events, current, as_of)
    before = reconstruct_as_of(events, current, since_dt) if since_dt else None
    delta = compare_states(before, state) if before else None
    scope = "all assets" if scope_ips is None else f"visibility cone ({len(scope_ips)} assets)"
    return {"state": state, "before": before, "delta": delta, "scope": scope}, None


@app.get("/api/findings/as-of")
def api_findings_as_of(date: str | None = None, since: str | None = None,
                       details: bool = False,
                       user: CurrentUser = Depends(_audit_reader)):
    """
    Stato dei finding a una data (evidenza point-in-time per audit esterno).

    'date'    ISO ('2026-03-31' = fine giornata UTC). Assente = adesso.
    'since'   seconda data, precedente: aggiunge il delta fra i due istanti
              (risolti / accettati / nuovi / ancora aperti).
    'details' true = include l'elenco dei finding, non solo i conteggi.

    Lo stato e' ricostruito per replay del registro append-only
    'finding_events'; i finding nati prima del registro sono stimati da
    first_seen/status_changed_at e contati a parte ('estimated'), cosi' e'
    esplicito cosa e' provato e cosa e' dedotto. La risposta include l'esito
    della verifica della catena hash del registro.
    Admin, manager e auditor: tutta la flotta. Editor: solo gli asset del
    proprio cono di visibilita'. Viewer: 403.
    """
    res, err = _point_in_time(user, date, since)
    if err is not None:
        return err
    state, before, delta = res["state"], res["before"], res["delta"]
    out = {"as_of": state["as_of"], "state": state,
           "chain": verify_findings_chain()}
    if before is not None:
        out["since"] = before["as_of"]
        out["state_since"] = before
        out["delta"] = delta
        if not details:
            before.pop("findings", None)
            delta.pop("fingerprints", None)
    if not details:
        state.pop("findings", None)
    return out


@app.post("/api/findings/import")
async def api_findings_import(request: Request, tool: str = "auto",
                              asset_ip: str = "",
                              user: CurrentUser = Depends(_writer)):
    """
    Ingestione di un report di scanner ESTERNO (capability ASPM: aggregazione).
    Body: JSON grezzo del report (Trivy/Grype/Semgrep JSON, Nuclei JSON/JSONL).
    'tool' forza il parser ('auto' = riconoscimento dal contenuto).
    'asset_ip' (opzionale) attribuisce i finding a un asset dell'inventario.
    I finding confluiscono nel ciclo di vita unificato: dedup per fingerprint,
    riapertura automatica dei 'fixed' riapparsi, SLA per severita'.
    """
    raw = await request.body()
    try:
        detected, normalized = ingest_report(raw, tool=tool, asset_ip=asset_ip)
    except IngestError as exc:
        return JSONResponse({"error": str(exc),
                             "supported": list(SUPPORTED_TOOLS)}, status_code=400)
    # Editor: scarta (con conteggio) i finding riferiti ad asset fuori dal cono
    # di visibilita', invece di rifiutare l'intero batch (le pipeline CI non
    # si rompono su report a host misti).
    skipped_out_of_scope = 0
    scope_ips = visible_asset_ips(user)
    if scope_ips is not None:
        in_scope = [f for f in normalized if (f.get("asset_ip") or "") in scope_ips]
        skipped_out_of_scope = len(normalized) - len(in_scope)
        normalized = in_scope
    if not normalized:
        return {"ok": True, "tool": detected, "parsed": 0,
                "new": 0, "updated": 0, "reopened": 0,
                "skipped_out_of_scope": skipped_out_of_scope}
    fps = [fingerprint(f) for f in normalized]
    existing = fetch_findings_by_fps(list(set(fps)))
    if existing is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    existing_by_fp = {r["fingerprint"]: r for r in existing}
    rows, stats = merge_findings(normalized, existing_by_fp,
                                 cfg_sla=load_config().get("sla"))
    if not upsert_findings(rows):
        return JSONResponse({"error": "Persistenza fallita"}, status_code=503)
    log_finding_events(lifecycle_events(rows, existing_by_fp, _actor(user)))
    # Un'ingestione INTRODUCE finding nel sistema: senza traccia, un batch
    # caricato da una pipeline e uno caricato a mano sono indistinguibili.
    _audit("ingest.import", request, user,
           target={"type": "report", "label": detected},
           detail={"tool": detected, "parsed": len(normalized),
                   "asset_ip": asset_ip or None,
                   "skipped_out_of_scope": skipped_out_of_scope, **stats})
    return {"ok": True, "tool": detected, "parsed": len(normalized),
            "skipped_out_of_scope": skipped_out_of_scope, **stats}


@app.patch("/api/findings/{finding_id}/status")
async def api_findings_status(finding_id: int, request: Request,
                              user: CurrentUser = Depends(_writer)):
    """
    Transizione di stato del workflow. Body: {status, note?}.
    Stati validi: open | triaged | accepted | fixed.
    Editor: solo su finding di asset nel proprio cono di visibilita'.
    """
    # Letto per tutti i ruoli (non solo scoped): serve lo stato di partenza per
    # il registro attivita', che l'UPDATE sta per sovrascrivere.
    f = fetch_finding(finding_id)
    if user.scoped:
        if f is None:
            return JSONResponse({"error": "Invalid id or DB unreachable"},
                                status_code=404)
        _require_ip_in_scope(user, f.get("asset_ip") or "")
    body = await request.json()
    status = (body.get("status") or "").strip().lower()
    note = (body.get("note") or "").strip()
    if status not in STATUSES:
        return JSONResponse(
            {"error": f"Stato non valido: {status}", "valid": list(STATUSES)},
            status_code=400)
    if not set_finding_status(finding_id, status, note, actor=_actor(user)):
        return JSONResponse({"error": "Invalid id or DB unreachable"}, status_code=404)
    # Doppia registrazione voluta: 'finding_events' regge la ricostruzione
    # point-in-time dei conteggi, questo registro risponde a "chi ha accettato
    # quel rischio, da che postazione e quando" senza incrociare due tabelle.
    _audit("finding.status_change", request, user,
           target={"type": "finding", "id": finding_id,
                   "label": (f or {}).get("title")},
           detail={"from": (f or {}).get("status"), "to": status,
                   "severity": (f or {}).get("severity"),
                   "asset_ip": (f or {}).get("asset_ip"), "note": note})
    return {"ok": True, "status": status}


@app.post("/api/findings/{finding_id}/ticket")
def api_findings_ticket(finding_id: int, request: Request,
                        user: CurrentUser = Depends(_writer)):
    """
    Crea un ticket di remediation (GitHub Issue / Jira) per il finding e ne
    salva il riferimento. Provider e credenziali in config.json ('ticketing').
    Editor: solo su finding di asset nel proprio cono di visibilita'.
    """
    f = fetch_finding(finding_id)
    if f is None:
        return JSONResponse({"error": "Finding non trovato o DB non raggiungibile"},
                            status_code=404)
    _require_ip_in_scope(user, f.get("asset_ip") or "")
    if f.get("ticket_url"):
        return {"ok": True, "already": True,
                "ref": f.get("ticket_ref"), "url": f.get("ticket_url")}
    try:
        ticket = create_ticket(load_config().get("ticketing") or {}, f)
    except TicketError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    set_finding_ticket(finding_id, ticket["ref"], ticket["url"])
    # L'apertura del ticket manda titolo e dettagli del finding a un sistema
    # ESTERNO (GitHub/Jira): e' un'uscita di dati verso terzi.
    _audit("finding.ticket_create", request, user,
           target={"type": "finding", "id": finding_id, "label": f.get("title")},
           detail={"ref": ticket.get("ref"), "url": ticket.get("url"),
                   "provider": (load_config().get("ticketing") or {}).get("provider")})
    return {"ok": True, "already": False, **ticket}


@app.post("/api/findings/export")
async def api_findings_export(request: Request,
                              user: CurrentUser = Depends(get_current_user)):
    """
    Contesto di audit per l'export della tabella findings.

    Il foglio dei dati lo costruisce il browser, che le righe le ha gia'; qui
    si aggiunge cio' che il browser NON puo' sapere e senza cui il file non
    prova nulla: chi lo ha estratto, quando, con quale cono di visibilita' e
    con quali filtri — cioe' che cosa NON c'e' dentro — e lo stato delle
    catene hash nello stesso istante. Un elenco di vulnerabilita' senza la
    verifica dei registri e' un foglio di calcolo, non un'evidenza.

    L'export e' esso stesso un'azione registrata: chi ha portato fuori quali
    dati, e quanti, e' esattamente cio' che un audit chiede a valle.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    filters = body.get("filters") or {}
    rows_exported = int(body.get("rows") or 0)

    all_rows = fetch_findings()
    if all_rows is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    scope_ips = visible_asset_ips(user)
    if scope_ips is not None:
        all_rows = [r for r in all_rows if (r.get("asset_ip") or "") in scope_ips]

    # La verifica delle catene e' best-effort: se il DB non risponde si dice
    # "non verificabile", non si tace e non si finge un esito.
    def _verdict(fn):
        try:
            v = fn()
        except Exception:
            v = None
        if not v:
            return {"ok": None, "note": "not verifiable"}
        return {"ok": bool(v.get("ok")), "total": v.get("total"),
                "verified": v.get("verified"), "broken": len(v.get("broken") or [])}

    context = {
        "exported_at": db._utc_iso(),
        "exported_by": user.username,
        "exported_by_role": user.role,
        "app_version": APP_VERSION,
        # Forma leggibile dalla macchina: la frase la compone il client, che
        # sa in che lingua sta scrivendo il foglio.
        "scope": {"kind": "all" if scope_ips is None else "cone",
                  "assets": None if scope_ips is None else len(scope_ips)},
        "rows_exported": rows_exported,
        "rows_in_scope": len(all_rows),
        "filters": filters,
        "integrity": {
            "scan_ledger": _verdict(db.verify_audit_chain),
            "finding_events": _verdict(db.verify_findings_chain),
            "posture_runs": _verdict(db.verify_posture_chain),
            "activity_ledger": _verdict(db.verify_events_chain),
        },
    }
    _audit("finding.export", request, user,
           target={"type": "finding", "label": f"{rows_exported} row(s)"},
           detail={"rows_exported": rows_exported, "rows_in_scope": len(all_rows),
                   "filters": {k: v for k, v in filters.items() if v},
                   "format": (body.get("format") or "xlsx")})
    return {"ok": True, "context": context}


@app.post("/api/findings/tickets/refresh")
def api_findings_tickets_refresh(request: Request,
                                 user: CurrentUser = Depends(_writer)):
    """
    Rilegge dal provider lo stato dei ticket gia' aperti e lo salva sui finding.

    Lo stato lo muovono le persone nel loro tracker: qualunque valore tenuto
    solo qui sarebbe una copia che invecchia in silenzio, quindi si rilegge
    su richiesta invece di fingere di saperlo. Editor e stakeholder vedono
    aggiornarsi solo i ticket dei finding nel proprio cono di visibilita'.
    """
    rows = fetch_findings()
    if rows is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    scope_ips = visible_asset_ips(user)
    if scope_ips is not None:
        rows = [r for r in rows if (r.get("asset_ip") or "") in scope_ips]
    ticketed = [r for r in rows if (r.get("ticket_ref") or "").strip()]
    if not ticketed:
        return {"ok": True, "checked": 0, "updated": 0, "changed": [], "statuses": {}}

    # Lo stesso ticket puo' essere referenziato da piu' finding: si interroga
    # una volta sola e si scrive su tutte le righe che lo puntano.
    refs = sorted({(r.get("ticket_ref") or "").strip() for r in ticketed})
    cfg = load_config().get("ticketing") or {}
    provider = (cfg.get("provider") or "").strip().lower()
    # Cambiare provider in Settings non cancella i ticket aperti con quello di
    # prima: quei riferimenti non sono interrogabili qui, e vanno dichiarati
    # tali invece di essere contati fra i "controllati" e lasciati con uno
    # stato che nessuno aggiornera' piu'.
    foreign = [r for r in refs if ref_provider(r) not in (None, provider)]
    askable = [r for r in refs if r not in foreign]
    try:
        found = fetch_ticket_status(cfg, askable) if askable else {}
    except TicketError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    # Forma giusta ma il provider non li ha restituiti: cancellati, spostati,
    # o fuori dai permessi di questo token. Anche questo va detto.
    unresolved = [r for r in askable if r not in found]

    updated, changed = 0, []
    for r in ticketed:
        ref = (r.get("ticket_ref") or "").strip()
        info = found.get(ref)
        if not info:
            continue
        if r.get("ticket_status") == info["status"] \
                and r.get("ticket_state") == info["state"]:
            continue          # nessun cambiamento: nessuna scrittura
        if set_finding_ticket_status(r["id"], info["status"], info["state"]):
            updated += 1
            changed.append({"id": r["id"], "ref": ref,
                            "from": r.get("ticket_status") or None,
                            "to": info["status"]})
    # Interrogare il tracker altrui e' un'uscita verso un sistema esterno; il
    # registro annota quanti ticket e quanti sono cambiati, non il loro
    # contenuto.
    _audit("finding.ticket_refresh", request, user,
           target={"type": "finding", "label": f"{len(refs)} ticket"},
           detail={"provider": provider, "checked": len(refs),
                   "resolved": len(found), "updated": updated,
                   "foreign": len(foreign), "unresolved": len(unresolved)})
    return {"ok": True, "checked": len(refs), "resolved": len(found),
            "updated": updated, "changed": changed,
            "provider": provider,
            "foreign": foreign, "unresolved": unresolved,
            "statuses": {k: {"status": v["status"], "state": v["state"]}
                         for k, v in found.items()}}


@app.post("/api/findings/scan-local")
async def api_findings_scan_local(request: Request,
                                  user: CurrentUser = Depends(_admin_manager)):
    """
    Esegue uno scanner LOCALE (binario opzionale sul server) e ne ingerisce
    il report nel ciclo di vita unificato.
    Body: {"type": "secrets" | "image", "target": "<path|image-ref>",
           "asset_ip": "<opzionale>"}.
      - secrets -> gitleaks sulla directory 'target'
      - image   -> trivy (vuln + secret) sull'immagine container 'target'
    Solo admin/manager: 'target' e' un path filesystem o un riferimento
    immagine arbitrario scelto dal chiamante, non verificabile contro il
    cono di visibilita' di un asset (l'asset_ip serve solo per l'etichetta
    dei finding) — non e' un'operazione da lasciare a 'editor'.
    """
    body = await request.json()
    scan_type = (body.get("type") or "").strip().lower()
    target = (body.get("target") or "").strip()
    asset_ip = (body.get("asset_ip") or "").strip()
    if not target:
        return JSONResponse({"error": "Missing target"}, status_code=400)
    try:
        if scan_type == "secrets":
            raw, tool = run_gitleaks(target), "gitleaks"
        elif scan_type == "image":
            raw, tool = run_trivy_image(target), "trivy"
        else:
            return JSONResponse(
                {"error": f"Tipo non valido: {scan_type} (secrets|image)"},
                status_code=400)
    except LocalScanError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    try:
        _, normalized = ingest_report(raw, tool=tool, asset_ip=asset_ip or target)
    except IngestError as exc:
        return JSONResponse({"error": f"Parsing report {tool}: {exc}"}, status_code=502)
    if not normalized:
        return {"ok": True, "tool": tool, "parsed": 0,
                "new": 0, "updated": 0, "reopened": 0}
    fps = [fingerprint(f) for f in normalized]
    existing = fetch_findings_by_fps(list(set(fps)))
    if existing is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    existing_by_fp = {r["fingerprint"]: r for r in existing}
    rows, stats = merge_findings(normalized, existing_by_fp,
                                 cfg_sla=load_config().get("sla"))
    if not upsert_findings(rows):
        return JSONResponse({"error": "Persistenza fallita"}, status_code=503)
    log_finding_events(lifecycle_events(rows, existing_by_fp, _actor(user)))
    # 'target' e' un path o un riferimento immagine scelto dal chiamante: far
    # eseguire uno scanner locale al server e' un'operazione privilegiata e il
    # bersaglio e' il dato che conta.
    _audit("scan.local", request, user,
           target={"type": "local_target", "label": target},
           detail={"type": scan_type, "tool": tool, "target": target,
                   "asset_ip": asset_ip or None, "parsed": len(normalized), **stats})
    return {"ok": True, "tool": tool, "parsed": len(normalized), **stats}


def _sync_posture_findings(report: dict, actor: dict | None = None) -> None:
    """
    Best-effort: versa i finding della postura di UN asset nel ciclo di vita
    unificato (dedup/riapertura) e auto-chiude quelli non piu' osservati.
    Ogni nascita, riapertura e auto-chiusura finisce nel registro eventi.
    Non solleva mai: la scansione di postura non dipende da questo passo.
    """
    try:
        normalized = posture_findings(report)
        fps = [fingerprint(f) for f in normalized]
        existing = fetch_findings_by_fps(list(set(fps)))
        if existing is None:
            return
        existing_by_fp = {r["fingerprint"]: r for r in existing}
        rows, _ = merge_findings(normalized, existing_by_fp,
                                 cfg_sla=load_config().get("sla"))
        if rows:
            upsert_findings(rows)
            log_finding_events(lifecycle_events(rows, existing_by_fp, actor))
        close_stale_posture_findings(report.get("ip") or "", fps, actor=actor)
    except Exception:
        pass


@app.get("/intel", response_class=HTMLResponse)
def intel_page(request: Request, user: CurrentUser = Depends(get_current_user)):
    """Pagina INTEL: dashboard Full Posture (ASPM-style)."""
    return templates.TemplateResponse("intel.html", {"request": request})


@app.get("/risk", response_class=HTMLResponse)
def risk_page(request: Request, user: CurrentUser = Depends(get_current_user)):
    """Pagina RISK: prioritizzazione contestuale (EPSS/KEV + contesto + trend)."""
    return templates.TemplateResponse("risk.html", {"request": request})


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: CurrentUser = Depends(_admin_manager)):
    """Pagina di configurazione dell'applicativo (admin: scrittura; manager: lettura)."""
    return templates.TemplateResponse("settings.html", {"request": request})


@app.get("/api/settings")
def api_settings_get(user: CurrentUser = Depends(_admin_manager)):
    """Legge la configurazione corrente (admin e manager)."""
    cfg = load_config()
    # Non esporre mai la chiave API in chiaro: maschera se presente.
    masked = json.loads(json.dumps(cfg))
    if masked.get("ai", {}).get("claude_api_key"):
        masked["ai"]["claude_api_key"] = "••••••••"
    if masked.get("search_engine", {}).get("serper_api_key"):
        masked["search_engine"]["serper_api_key"] = "••••••••"
    if masked.get("ticketing", {}).get("github_token"):
        masked["ticketing"]["github_token"] = "••••••••"
    if masked.get("ticketing", {}).get("jira_api_token"):
        masked["ticketing"]["jira_api_token"] = "••••••••"
    if masked.get("smtp", {}).get("password"):
        masked["smtp"]["password"] = "••••••••"
    if masked.get("nvd", {}).get("api_key"):
        masked["nvd"]["api_key"] = "••••••••"
    return masked


@app.post("/api/settings")
async def api_settings_post(request: Request,
                            user: CurrentUser = Depends(_admin_only)):
    """Aggiorna la configurazione. Merge parziale per sezione. SOLO admin."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    cfg = load_config()

    # Aggiorna solo le sezioni/chiavi ricevute; non sovrascrivere le chiavi
    # API se il client invia il placeholder "••••••••".
    changed: dict = {}
    for section, values in body.items():
        if section not in cfg:
            continue
        if not isinstance(values, dict):
            continue
        for key, val in values.items():
            if key not in cfg[section]:
                continue
            # Preserva il valore originale se il frontend invia placeholder.
            if isinstance(val, str) and "••••" in val:
                continue
            if cfg[section][key] != val:
                changed.setdefault(section, {})[key] = {
                    "from": cfg[section][key], "to": val}
            cfg[section][key] = val

    save_config(cfg)
    # Solo le chiavi realmente cambiate, col prima/dopo. I valori sensibili
    # (chiavi API, password SMTP) sono redatti da db.log_audit_event: il
    # registro dice CHE la chiave e' stata riscritta, mai con quale valore.
    _audit("config.update", request, user,
           target={"type": "config", "id": ",".join(sorted(changed)) or None,
                   "label": ", ".join(sorted(changed)) or "no change"},
           detail={"sections": sorted(changed), "changed": changed})
    # Le fonti tengono in cache risposte e indici: dopo un cambio di chiave,
    # timeout o finestra le voci vecchie sarebbero calcolate su impostazioni
    # che non valgono piu'.
    if "nvd" in body:
        nvd.clear_cache()
    if "msrc" in body:
        msrc.clear_cache()
    return {"ok": True}


@app.post("/api/settings/ticketing/check")
async def api_ticketing_check(request: Request,
                              user: CurrentUser = Depends(_admin_only)):
    """
    Verifica la configurazione ticketing SENZA creare alcun ticket.

    Il body puo' contenere i valori attualmente nella form, cosi' che la
    verifica si possa fare PRIMA di salvare: chi sta correggendo un dominio
    sbagliato non deve essere costretto a scriverlo nel file per scoprire che
    era sbagliato. I campi mascherati ("••••••••") vengono risolti dal file,
    con la stessa regola di POST /api/settings.

    Solo admin: la verifica usa le credenziali salvate e le spende verso un
    servizio esterno.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    stored = (load_config().get("ticketing") or {})
    cfg = dict(stored)
    for key, val in (body or {}).items():
        if key not in stored:
            continue
        if isinstance(val, str) and "••••" in val:
            continue          # placeholder: tieni il valore salvato
        cfg[key] = val

    result = check_connection(cfg)

    # Un amministratore che spende le credenziali del prodotto verso un
    # servizio esterno e' un'azione da registrare; il registro annota l'esito
    # e la diagnosi, mai il token ne' l'esito di una risposta remota completa.
    _audit("settings.ticketing_check", request, user,
           outcome="success" if result.get("ok") else "failure",
           target={"type": "config", "id": "ticketing",
                   "label": cfg.get("provider") or "off"},
           detail={"provider": cfg.get("provider") or "",
                   "ok": bool(result.get("ok")),
                   "code": result.get("code") or None,
                   "field": result.get("field") or None})
    return result


@app.get("/api/ollama/models")
def api_ollama_models(user: CurrentUser = Depends(_admin_manager)):
    """Lista modelli disponibili su Ollama (GET /api/tags). [] se offline."""
    import requests as _req
    from urllib.parse import urlparse
    cfg = load_config()["ai"]
    base = urlparse(cfg.get("ollama_url", "http://localhost:11434/api/generate"))
    tags_url = f"{base.scheme}://{base.netloc}/api/tags"
    try:
        r = _req.get(tags_url, timeout=4)
        r.raise_for_status()
        models = [m["name"] for m in r.json().get("models", [])]
        return {"models": sorted(models)}
    except Exception:
        return {"models": []}


@app.get("/api/posture/scan")
def api_posture_scan(request: Request, ips: str | None = None,
                     user: CurrentUser = Depends(_writer)):
    """
    Avvio MANUALE della Full Posture: per ogni asset raccoglie l'inventario
    pacchetti e lo valuta con OSV. Streaming SSE: 'run', 'asset'*, 'done'.
    Persistenza best-effort su Supabase (run -> asset -> findings).

    'ips' (opzionale): lista IP/host separati da virgola -> scansiona solo quelli.
    Assente/vuoto => tutti gli asset dell'inventario.
    Editor: scansiona solo gli asset del proprio cono di visibilita'.
    """
    selected = {s.strip() for s in (ips or "").split(",") if s.strip()}
    scope_ids = visible_asset_ids(user)

    def stream():
        try:
            assets = load_assets(ASSETS_FILE)
        except AssetStoreError as exc:
            yield _sse("error", {"message": str(exc)})
            return
        # Esclude gli asset disabilitati in inventario dalla scansione di postura.
        assets = [a for a in assets if a.enabled]
        if scope_ids is not None:
            assets = [a for a in assets if a.id in scope_ids]
        if selected:
            assets = [a for a in assets if a.ip in selected]
        if not assets:
            yield _sse("error", {"message": "No asset selected."})
            return
        run_id = create_posture_run(_actor(user))
        _audit("posture.scan_start", request, user,
               target={"type": "posture_run", "id": run_id},
               detail={"assets": len(assets), "selected_ips": sorted(selected) or None})
        yield _sse("run", {"run_id": run_id, "total_assets": len(assets)})

        n = pkgs = vuln = vulns = score_sum = 0
        for asset in assets:
            report = scan_asset_posture(asset)
            report["os_type"] = asset.os_type or None
            report["os_major_version"] = asset.os_major_version or None
            persist_posture_asset(run_id, report)
            # Ciclo di vita unificato: dedup + riaperture + auto-fix (best-effort).
            _sync_posture_findings(report, _actor(user))
            n += 1
            pkgs += report["total_packages"]
            vuln += report["vulnerable_packages"]
            vulns += report["total_vulns"]
            score_sum += report["score"]
            yield _sse("asset", report)

        avg = round(score_sum / n) if n else 100
        totals = {"assets_scanned": n, "total_packages": pkgs,
                  "total_vulnerable": vuln, "total_vulns": vulns, "avg_score": avg}
        finalize_posture_run(run_id, totals)
        _audit("posture.scan_complete", request, user,
               target={"type": "posture_run", "id": run_id}, detail=totals)
        yield _sse("done", {"run_id": run_id, **totals})

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/api/posture/cve")
def api_posture_cve(package: str, ecosystem: str | None = None,
                    version: str | None = None,
                    user: CurrentUser = Depends(get_current_user)):
    """Lista COMPLETA di id CVE per (pacchetto, ecosistema, versione) — 'show more' posture."""
    return query_osv_ecosystem(package, ecosystem, version)


@app.get("/api/posture/fixplan")
def api_posture_fixplan(package: str, ecosystem: str | None = None,
                        version: str | None = None,
                        user: CurrentUser = Depends(get_current_user)):
    """Fix plan OSV: per-CVE versione 'fixed' + versione minima che risolve tutto (resolver UI)."""
    return compute_fix_plan(package, ecosystem, version)


@app.get("/api/posture")
def api_posture(run_id: int | None = None,
                user: CurrentUser = Depends(get_current_user)):
    """
    Ritorna una run di postura (ultima se run_id assente) con asset+findings.
    Editor: solo gli asset del proprio cono di visibilita'.
    """
    data = fetch_posture(run_id)
    if data is None:
        return JSONResponse({"error": "Supabase unreachable", "run": {}}, status_code=503)
    data = _filter_posture_run(data, visible_asset_ips(user))
    return {"run": data}


@app.get("/api/posture/runs")
def api_posture_runs(user: CurrentUser = Depends(get_current_user)):
    """Elenco storico delle run di postura."""
    data = fetch_posture_runs()
    if data is None:
        return JSONResponse({"error": "Supabase unreachable", "runs": []}, status_code=503)
    return {"runs": data}


@app.get("/api/risk")
def api_risk(run_id: int | None = None, probe: bool = True,
             user: CurrentUser = Depends(get_current_user)):
    """
    Rischio CONTESTUALE di una run di postura (ultima se run_id assente).

    Combina: severita' della postura + exploitability (EPSS + CISA KEV) +
    reachability (porte di servizio aperte) + contesto business dell'asset
    (ambiente, internet-facing, criticita' dall'inventario).

    'probe=false' salta la sonda TCP delle porte (piu' veloce, no reachability).
    Editor: il rischio e' RICALCOLATO sul solo cono di visibilita' (gli
    aggregati non rivelano nulla degli asset non assegnati).
    """
    run = fetch_posture(run_id)
    if run is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    if not run:
        return {"risk": {"assets": [], "summary": {}, "meta": {}}}
    scope_ips = visible_asset_ips(user)
    run = _filter_posture_run(run, scope_ips)
    try:
        assets = load_assets(ASSETS_FILE)
        ctx = {a.ip: {"id": a.id, "environment": a.environment,
                      "internet_facing": a.internet_facing,
                      "criticality": a.criticality} for a in assets
               if scope_ips is None or a.ip in scope_ips}
    except AssetStoreError:
        ctx = {}
    return {"risk": assess_run_risk(run, ctx, probe=probe)}


@app.get("/api/risk/trend")
def api_risk_trend(user: CurrentUser = Depends(get_current_user)):
    """
    Serie storica del rischio (score/CVE per run) + delta finding-level fra le
    due run piu' recenti (nuove vs risolte). 503 se il DB non risponde.
    Ruoli scoped (editor, stakeholder): il delta e' calcolato sul solo cono di
    visibilita'; nella serie storica i contatori globali per-run vengono omessi
    (nessun leak indiretto).
    """
    runs = fetch_posture_runs()
    if runs is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    scope_ips = visible_asset_ips(user)
    if scope_ips is not None:
        # Gli aggregati per-run (avg_score, total_vulns) sono globali: per i
        # ruoli scoped si mantengono solo id/data delle run nella serie.
        runs = [{"id": r.get("id"), "created_at": r.get("created_at")}
                for r in runs]
    current = previous = None
    if len(runs) >= 1:
        current = _filter_posture_run(fetch_posture(runs[0].get("id")), scope_ips)
    if len(runs) >= 2:
        previous = _filter_posture_run(fetch_posture(runs[1].get("id")), scope_ips)
    return {"trend": compute_trend(runs, current, previous)}


@app.patch("/api/assets/{index}/context")
async def api_assets_context(index: int, request: Request,
                             user: CurrentUser = Depends(_writer)):
    """
    Aggiorna il contesto business di un asset (per la prioritizzazione del rischio).
    Body (tutti opzionali): {environment, internet_facing, criticality}.
    Editor: solo su asset del proprio cono di visibilita'.
    """
    _require_asset_in_scope(user, index)
    body = await request.json()
    row = {}
    if "environment" in body:
        env = (body.get("environment") or "unknown").strip().lower()
        if env not in ("production", "staging", "dev", "unknown"):
            env = "unknown"
        row["environment"] = env
    if "internet_facing" in body:
        row["internet_facing"] = bool(body.get("internet_facing"))
    if "criticality" in body:
        try:
            c = int(body.get("criticality"))
        except (TypeError, ValueError):
            c = 3
        row["criticality"] = max(1, min(5, c))
    if not row:
        return JSONResponse({"error": "No context fields"}, status_code=400)
    if not update_asset_fields(index, row):
        return JSONResponse({"error": "Invalid index or DB unreachable"}, status_code=404)
    # Il contesto business pesa sulla prioritizzazione del rischio: abbassare
    # la criticita' di un asset ne abbassa il rischio calcolato senza toccare
    # una sola vulnerabilita'.
    _audit("asset.context_change", request, user,
           target={"type": "asset", "id": index}, detail=row)
    return {"ok": True, **row}


def _audit_scope_filter(data: list, user: CurrentUser) -> list:
    """Applica il cono di visibilita' RBAC: i ruoli scoped vedono solo i propri
    asset."""
    scope_ips = visible_asset_ips(user)
    if scope_ips is None:
        return data
    out = []
    for scan in data:
        results = [r for r in (scan.get("scan_results") or [])
                   if (r.get("ip") or "") in scope_ips]
        if results:
            out.append({**scan, "scan_results": results})
    return out


def _audit_facets(data: list, outcome: str | None, source: str | None,
                  os_type: str | None, actor: str | None) -> list:
    """Filtri sfaccettati server-side. outcome/os filtrano le righe; una scan
    resta solo se conserva almeno una riga. source/actor filtrano la scan."""
    out = []
    for scan in data:
        if source and (scan.get("source") or "").lower() != source.lower():
            continue
        if actor and (scan.get("actor_name") or "").lower() != actor.lower():
            continue
        rows = scan.get("scan_results") or []
        if outcome:
            rows = [r for r in rows if (r.get("vuln_match") or "") == outcome]
        if os_type:
            rows = [r for r in rows if (r.get("os_type") or "").lower() == os_type.lower()]
        if (outcome or os_type) and not rows:
            continue
        out.append({**scan, "scan_results": rows} if (outcome or os_type) else scan)
    return out


def _audit_search(data: list, q: str) -> list:
    """Ricerca full-text su header scan + righe risultato. Una scan resta con le
    sole righe che matchano; se l'header matcha, tutte le righe restano."""
    q = q.strip().lower()
    if not q:
        return data
    out = []
    for s in data:
        head = " ".join(str(x) for x in [
            s.get("product"), s.get("version"), s.get("source"), s.get("description"),
            s.get("actor_name"), " ".join(s.get("cve_ids") or []), s.get("cve_summary"),
        ] if x).lower()
        head_match = q in head
        rows = []
        for r in (s.get("scan_results") or []):
            if head_match:
                rows.append(r); continue
            hay = " ".join(str(x) for x in [
                r.get("ip"), r.get("method"), r.get("vuln_match"), r.get("detected_version"),
                r.get("raw_evidence"), " ".join(r.get("cve_ids") or []), r.get("affected_version"),
                r.get("match_basis"), r.get("os_type"), r.get("os_major_version"),
                "found" if r.get("product_found") else "not found",
                "auth" if r.get("auth_required") else "no-auth",
            ] if x).lower()
            if q in hay:
                rows.append(r)
        if rows:
            out.append({**s, "scan_results": rows})
    return out


def _audit_kpis(data: list) -> dict:
    """Aggregati calcolati sul set filtrato (non paginato)."""
    results = [r for s in data for r in (s.get("scan_results") or [])]
    vuln = sum(1 for r in results if r.get("vuln_match") == "VULNERABILE")
    assets = len({r.get("ip") for r in results if r.get("ip")})
    last = max((s.get("created_at") or "" for s in data), default="") or None
    return {"scans": len(data), "results": len(results),
            "vuln": vuln, "assets": assets, "last_scan": last}


@app.get("/api/audit")
def api_audit(
    user: CurrentUser = Depends(_audit_reader),
    page: int = 0, page_size: int = 20,
    date_from: str | None = None, date_to: str | None = None,
    outcome: str | None = None, source: str | None = None,
    os_type: str | None = None, actor: str | None = None,
    q: str | None = None,
):
    """
    Storico scansioni (scans + scan_results annidati) letto da Supabase.
    Admin, manager e auditor: tutto. Editor: solo i risultati relativi agli
    asset del proprio cono di visibilita'. Viewer: 403.

    Filtri (tutti opzionali): date_from/date_to (ISO, lato DB), outcome, source,
    os_type, actor (lato server). Paginazione: page/page_size (page_size=0 = tutto).
    KPI e 'total' sono calcolati sul set filtrato COMPLETO, poi si ritorna solo
    la pagina richiesta. 503 se il DB non e' raggiungibile.
    """
    data = fetch_audit(date_from=date_from, date_to=date_to)
    if data is None:
        return JSONResponse(
            {"error": "Supabase unreachable", "scans": []},
            status_code=503,
        )
    data = _audit_scope_filter(data, user)
    # Opzioni facet dal set in-scope COMPLETO (prima dei filtri) cosi' i menu non
    # si svuotano quando un filtro e' attivo.
    sources = sorted({(s.get("source") or "").strip() for s in data if s.get("source")})
    actors = sorted({(s.get("actor_name") or "").strip() for s in data if s.get("actor_name")})
    data = _audit_facets(data, outcome, source, os_type, actor)
    if q:
        data = _audit_search(data, q)
    kpis = _audit_kpis(data)
    total = len(data)
    if page_size and page_size > 0:
        start = max(page, 0) * page_size
        page_slice = data[start:start + page_size]
    else:
        page_slice = data
    return {"scans": page_slice, "total": total, "page": page,
            "page_size": page_size, "kpis": kpis,
            "sources": sources, "actors": actors}


def _event_search(rows: list, q: str) -> list:
    """Ricerca full-text su azione, attore, bersaglio e dettaglio dell'evento."""
    ql = (q or "").strip().lower()
    if not ql:
        return rows
    out = []
    for e in rows:
        hay = " ".join(str(x) for x in [
            e.get("action"), e.get("category"), e.get("outcome"),
            e.get("actor_name"), e.get("actor_role"), e.get("target_type"),
            e.get("target_id"), e.get("target_label"), e.get("src_ip"),
            json.dumps(e.get("detail") or {}, default=str),
        ] if x).lower()
        if ql in hay:
            out.append(e)
    return out


def _event_kpis(rows: list) -> dict:
    """Aggregati sul set filtrato: volume, esiti e attori distinti."""
    failures = sum(1 for e in rows if (e.get("outcome") or "") == "failure")
    denied = sum(1 for e in rows if (e.get("outcome") or "") == "denied")
    actors = len({e.get("actor_name") for e in rows if e.get("actor_name")})
    last = max((e.get("event_ts") or "" for e in rows), default="") or None
    return {"events": len(rows), "failures": failures, "denied": denied,
            "actors": actors, "last_event": last}


@app.get("/api/audit/events")
def api_audit_events(
    user: CurrentUser = Depends(_audit_reader),
    page: int = 0, page_size: int = 25,
    date_from: str | None = None, date_to: str | None = None,
    category: str | None = None, action: str | None = None,
    outcome: str | None = None, actor: str | None = None,
    q: str | None = None,
):
    """
    Registro delle ATTIVITA': accessi, autorizzazioni negate, amministrazione
    utenti e gruppi, assegnazioni, configurazione, export, scansioni.
    E' il registro che risponde a "chi ha fatto cosa", complementare allo
    storico scansioni di /api/audit.

    Admin, manager e auditor: tutti gli eventi. Editor: SOLO i propri — il
    registro attribuisce attivita' a persone identificate, e un ruolo scoped
    non deve leggere l'attivita' amministrativa altrui (stessa ragione per cui
    'stakeholder' e 'viewer' restano fuori del tutto).

    Filtri: date_from/date_to (lato DB), category, action, outcome, actor, q.
    Paginazione: page/page_size (page_size=0 = tutto).
    """
    rows = db.fetch_audit_events(
        date_from=date_from, date_to=date_to,
        actor_id=user.id if user.scoped else None)
    if rows is None:
        return JSONResponse({"error": "Supabase unreachable", "events": []},
                            status_code=503)
    # Opzioni dei menu dal set in-scope COMPLETO (prima dei filtri), cosi' non
    # si svuotano quando un filtro e' attivo.
    categories = sorted({(e.get("category") or "").strip() for e in rows if e.get("category")})
    actions = sorted({(e.get("action") or "").strip() for e in rows if e.get("action")})
    actors = sorted({(e.get("actor_name") or "").strip() for e in rows if e.get("actor_name")})
    if category:
        rows = [e for e in rows if (e.get("category") or "") == category]
    if action:
        rows = [e for e in rows if (e.get("action") or "") == action]
    if outcome:
        rows = [e for e in rows if (e.get("outcome") or "") == outcome]
    if actor:
        rows = [e for e in rows if (e.get("actor_name") or "").lower() == actor.lower()]
    if q:
        rows = _event_search(rows, q)
    kpis = _event_kpis(rows)
    total = len(rows)
    if page_size and page_size > 0:
        start = max(page, 0) * page_size
        rows = rows[start:start + page_size]
    return {"events": rows, "total": total, "page": page, "page_size": page_size,
            "kpis": kpis, "categories": categories, "actions": actions,
            "actors": actors, "scoped": user.scoped}


def _posture_run_state(run: dict, verdict: dict) -> str:
    """
    Stato di integrita' della singola run: verified | sealed | anchored |
    unsigned | tampered.

    'sealed' e' piu' forte di 'verified': significa che anche i TOTALI (asset,
    pacchetti, vulnerabilita', score) sono coperti dal sigillo di fine run, ed
    e' esattamente cio' che un audit contesta.
    """
    rid = run.get("id")
    broken = set(verdict.get("broken") or []) | set(verdict.get("finals_broken") or [])
    if rid in broken:
        return "tampered"
    if not run.get("row_hash"):
        anchor = verdict.get("anchor") or {}
        anchored = (anchor.get("present") and anchor.get("digest_ok")
                    and anchor.get("self_hash_ok")
                    and rid is not None and rid <= (anchor.get("through_id") or 0))
        return "anchored" if anchored else "unsigned"
    return "sealed" if run.get("final_hash") else "verified"


@app.get("/api/audit/posture")
def api_audit_posture(
    user: CurrentUser = Depends(_audit_reader),
    page: int = 0, page_size: int = 20,
    date_from: str | None = None, date_to: str | None = None,
    actor: str | None = None, state: str | None = None,
    q: str | None = None,
):
    """
    Storico delle run di postura per il registro di audit: una riga per run,
    con attore, totali sigillati e stato di integrita'.

    Esisteva gia' la PROVA (GET /api/audit/posture-verify) ma non la VISTA: un
    auditor poteva farsi dire che i conteggi point-in-time non erano stati
    alterati, senza poterli sfogliare dalla pagina di audit. Sono i numeri piu'
    probanti del prodotto — "a questa data N vulnerabilita' aperte" — e la
    pagina mostrava solo le query di threat intelligence.

    Ruoli scoped (editor): la run resta, ma vengono mostrati solo gli asset del
    proprio cono di visibilita' e i totali NON vengono ricalcolati — sono
    valori sigillati, e riscriverli qui significherebbe presentare come
    'sigillata' una cifra diversa da quella firmata. Il campo 'scoped' lo
    dichiara.
    """
    runs = db.fetch_posture_history(date_from=date_from, date_to=date_to)
    if runs is None:
        return JSONResponse({"error": "Supabase unreachable", "runs": []},
                            status_code=503)
    verdict = verify_posture_chain() or {}
    scope_ips = visible_asset_ips(user)

    out = []
    for r in runs:
        assets = r.get("posture_assets") or []
        if scope_ips is not None:
            assets = [a for a in assets if (a.get("ip") or "") in scope_ips]
            if not assets:
                continue          # run che non tocca nessun asset del cono
        out.append({**r, "posture_assets": assets,
                    "state": _posture_run_state(r, verdict)})

    actors = sorted({(r.get("actor_name") or "").strip() for r in out if r.get("actor_name")})
    if actor:
        out = [r for r in out if (r.get("actor_name") or "").lower() == actor.lower()]
    if state:
        out = [r for r in out if r["state"] == state]
    if q:
        ql = q.strip().lower()
        out = [r for r in out
               if ql in json.dumps({k: v for k, v in r.items()
                                    if k != "posture_assets"}, default=str).lower()
               or any(ql in (a.get("ip") or "").lower() for a in (r.get("posture_assets") or []))]

    kpis = {
        "runs": len(out),
        "assets": sum(r.get("assets_scanned") or 0 for r in out),
        "vulns": sum(r.get("total_vulns") or 0 for r in out),
        # Quante run reggono davvero una verifica: e' la cifra che conta quando
        # si consegna lo storico, non il numero di run.
        "sealed": sum(1 for r in out if r["state"] == "sealed"),
        "last_run": max((r.get("created_at") or "" for r in out), default="") or None,
    }
    total = len(out)
    if page_size and page_size > 0:
        start = max(page, 0) * page_size
        out = out[start:start + page_size]
    return {"runs": out, "total": total, "page": page, "page_size": page_size,
            "kpis": kpis, "actors": actors, "scoped": scope_ips is not None,
            "integrity": {k: verdict.get(k) for k in
                          ("verdict", "ok", "verified", "total", "unsigned",
                           "anchored", "unprotected", "coverage",
                           "protected_coverage", "finals_verified",
                           "finals_pending", "tamper_reasons")}}


ANCHORABLE_CHAINS = ("scans", "posture_runs", "finding_events", "audit_events")


@app.post("/api/audit/anchor")
async def api_audit_anchor(request: Request,
                           user: CurrentUser = Depends(_admin_only)):
    """
    Ancora le righe non firmate dei registri: ne registra il digest in una riga
    firmata, cosi' da quel momento ogni loro modifica e' rilevabile.

    Body opzionale {"chains": ["scans", ...], "note": "..."}; senza corpo
    vengono ancorate tutte le catene che ne hanno bisogno.

    Solo admin, e volutamente NON automatico: l'ancora dichiara "questo era lo
    stato al momento T" e trasforma righe indimostrabili in righe protette da
    qui in avanti. E' un'affermazione che deve fare una persona, non un job di
    avvio — e resta scritta nel registro attivita' con chi l'ha fatta.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    chains = body.get("chains") or list(ANCHORABLE_CHAINS)
    bad = [c for c in chains if c not in ANCHORABLE_CHAINS]
    if bad:
        return JSONResponse({"error": f"Catene non valide: {bad}",
                             "valid": list(ANCHORABLE_CHAINS)}, status_code=400)
    note = (body.get("note") or "").strip()
    created, skipped = [], []
    for chain in chains:
        # Il testimone locale della testa (ledger_head) viene mantenuto a ogni
        # append, ma su un'installazione preesistente non ha ancora una
        # baseline: senza, un troncamento della coda resterebbe invisibile.
        # Questa e' l'azione deliberata in cui l'admin dichiara di accettare lo
        # stato corrente, quindi e' anche il punto giusto per registrarla.
        db._head_touch(chain)
        row = db.create_ledger_anchor(chain, actor=_actor(user), note=note)
        if row is None:
            # Nessuna riga da ancorare (tutto gia' firmato) o DB muto.
            skipped.append(chain)
            continue
        created.append({"chain": chain, "through_id": row.get("through_id"),
                        "row_count": row.get("row_count"),
                        "digest": row.get("digest")})
        _audit("audit.anchor", request, user,
               target={"type": "ledger", "id": chain, "label": chain},
               detail={"through_id": row.get("through_id"),
                       "row_count": row.get("row_count"),
                       "digest": row.get("digest"), "note": note})
    if not created and not skipped:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    return {"ok": True, "anchored": created, "nothing_to_anchor": skipped}


@app.get("/api/audit/events/verify")
def api_audit_events_verify(user: CurrentUser = Depends(_audit_reader)):
    """
    Verifica la catena hash del registro attivita': dice se una riga di
    "chi ha fatto cosa" e' stata alterata o rimossa dopo la scrittura.
    503 se il DB non e' raggiungibile.
    """
    res = db.verify_events_chain()
    if res is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    return res


@app.get("/api/audit/verify")
def api_audit_verify(user: CurrentUser = Depends(_audit_reader)):
    """
    Verifica la catena hash del ledger scansioni (tamper-evidence) su due
    livelli: row_hash (campi immutabili + linkatura) e final_hash (version e
    conteggio CVE sigillati a fine scansione). 503 se DB assente.
    """
    res = verify_audit_chain()
    if res is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    return res


@app.get("/api/audit/findings-verify")
def api_findings_verify(user: CurrentUser = Depends(_audit_reader)):
    """
    Verifica la catena hash del registro eventi dei finding: e' la prova di
    integrita' che accompagna i conteggi point-in-time di /api/findings/as-of.
    503 se il DB non e' raggiungibile.
    """
    res = verify_findings_chain()
    if res is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    return res


@app.get("/api/audit/posture-verify")
def api_posture_verify(user: CurrentUser = Depends(_audit_reader)):
    """
    Verifica la catena hash delle run di postura, sui due livelli: creazione
    (attore + linkatura) e totali sigillati a fine run. Sono i numeri che un
    audit legge come "vulnerabilita' rilevate a questa data".
    503 se il DB non e' raggiungibile.
    """
    res = verify_posture_chain()
    if res is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    return res


EVIDENCE_FORMATS = ("json", "csv", "html")


@app.get("/api/audit/evidence")
def api_audit_evidence(request: Request, date: str | None = None,
                       since: str | None = None, format: str = "json",
                       user: CurrentUser = Depends(_audit_reader)):
    """
    Report di evidenza FIRMATO da consegnare a un audit esterno.

    Mette insieme in un solo documento i conteggi point-in-time alle due date,
    il delta di remediation e l'esito della verifica di TUTTE le catene hash
    (ledger scansioni, registro eventi, run di postura), poi firma il tutto in
    HMAC-SHA256 col segreto dell'istanza. Numeri e prova di integrita' viaggiano
    insieme: separarli renderebbe il report inverificabile.

    'format': json (macchina) | csv (foglio di calcolo) | html (stampabile ->
    PDF dal browser). Nessuna libreria PDF: la stampa del browser produce lo
    stesso documento senza aggiungere dipendenze.
    Editor: il report copre solo il proprio cono di visibilita', ed e' scritto
    nel campo 'scope' del report — un'evidenza parziale dichiarata tale.
    """
    fmt = (format or "json").strip().lower()
    if fmt not in EVIDENCE_FORMATS:
        return JSONResponse(
            {"error": f"Formato non valido: {fmt}", "valid": list(EVIDENCE_FORMATS)},
            status_code=400)
    res, err = _point_in_time(user, date, since)
    if err is not None:
        return err
    # I dettagli per-finding non entrano nel report: e' un documento di
    # conteggi, e includerli esporrebbe l'inventario a chi lo riceve.
    res["state"].pop("findings", None)
    if res["before"]:
        res["before"].pop("findings", None)
    if res["delta"]:
        res["delta"].pop("fingerprints", None)

    report = evidence.build_report(
        state=res["state"], before=res["before"], delta=res["delta"],
        chains={"scans": verify_audit_chain(),
                "finding_events": verify_findings_chain(),
                "posture_runs": verify_posture_chain(),
                # Il registro attivita' e' parte della prova: un report che
                # certifica i conteggi ma tace sull'integrita' del "chi ha
                # fatto cosa" copre solo meta' della domanda d'audit.
                "audit_events": db.verify_events_chain()},
        actor=user.username, scope=res["scope"],
    )
    evidence.sign(report, _hmac_secret())
    # L'evidenza firmata e' il deliverable d'audit per eccellenza: chi l'ha
    # generata, per quali date e in che formato entra nel registro.
    _audit("export.evidence", request, user,
           target={"type": "report", "id": report.get("generated_at")},
           detail={"format": fmt, "date": date, "since": since,
                   "scope": res["scope"]})

    stamp = (report["generated_at"] or "")[:10]
    if fmt == "json":
        return report
    if fmt == "csv":
        body, media = evidence.to_csv(report), "text/csv; charset=utf-8"
    else:
        body, media = evidence.to_html(report), "text/html; charset=utf-8"
    return Response(
        content=body, media_type=media,
        headers={"Content-Disposition":
                 f'attachment; filename="audit-evidence-{stamp}.{fmt}"'})


@app.post("/api/audit/evidence/verify")
async def api_audit_evidence_verify(request: Request,
                                    user: CurrentUser = Depends(_audit_reader)):
    """
    Riverifica un report di evidenza esportato in precedenza (body: il JSON
    del report). Dice se una singola cifra e' stata ritoccata dopo l'export.
    Non richiede che i dati originali esistano ancora: la firma copre il
    contenuto del documento, non lo stato corrente del database.
    """
    try:
        report = await request.json()
    except Exception:
        return JSONResponse({"error": "Body non e' JSON valido"}, status_code=400)
    if not isinstance(report, dict):
        return JSONResponse({"error": "Il body deve essere il report JSON"},
                            status_code=400)
    return evidence.verify(report, _hmac_secret())


def _scan_outcome(scan: dict) -> str:
    """Esito peggiore fra le righe di una scan (per la timeline attivita')."""
    vals = {(r.get("vuln_match") or "") for r in (scan.get("scan_results") or [])}
    if "VULNERABILE" in vals:
        return "VULNERABILE"
    if "INCERTO" in vals:
        return "INCERTO"
    if "NON VULNERABILE" in vals:
        return "NON VULNERABILE"
    return ""


@app.get("/api/dashboard")
def api_dashboard(recent: int = 6, user: CurrentUser = Depends(get_current_user)):
    """
    Aggregato leggero per la home: attivita' recente (dal ledger) + sintesi
    finding con SLA. Una sola chiamata, filtrata sul cono di visibilita' RBAC.
    Best-effort: le sezioni con DB irraggiungibile tornano vuote/null, non 503,
    cosi' la dashboard resta utilizzabile a pezzi.
    """
    out: dict = {"recent": [], "findings": None, "actor": user.username, "role": user.role}

    # 1) Attivita' recente dal ledger (scoped).
    audit = fetch_audit(limit=200)
    if audit is not None:
        audit = _audit_scope_filter(audit, user)
        for s in audit[:max(0, recent)]:
            out["recent"].append({
                "id": s.get("id"), "product": s.get("product"), "version": s.get("version"),
                "source": s.get("source"), "actor_name": s.get("actor_name"),
                "created_at": s.get("created_at"), "signed": bool(s.get("row_hash")),
                "outcome": _scan_outcome(s), "assets": len(s.get("scan_results") or []),
            })

    # 2) Finding: sintesi (stati/severita'/SLA) + top scaduti.
    rows = fetch_findings()
    if rows is not None:
        scope_ips = visible_asset_ips(user)
        if scope_ips is not None:
            rows = [r for r in rows if (r.get("asset_ip") or "") in scope_ips]
        summary = summarize(rows)
        open_rows = [r for r in rows if (r.get("status") or "open") in ("open", "triaged")]
        for r in open_rows:
            r["_breached"] = is_breached(r)
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        open_rows.sort(key=lambda r: (
            0 if r["_breached"] else 1,
            sev_rank.get((r.get("severity") or "UNKNOWN").upper(), 4),
            r.get("sla_due") or "",
        ))
        top = [{
            "package": r.get("package"), "version": r.get("version"),
            "asset_ip": r.get("asset_ip"), "severity": (r.get("severity") or "UNKNOWN").upper(),
            "status": r.get("status") or "open", "sla_due": r.get("sla_due"),
            "first_seen": r.get("first_seen"), "breached": r["_breached"],
        } for r in open_rows[:max(0, recent)]]
        out["findings"] = {"summary": summary, "top": top}

    return out


def _normalize_host(raw: str) -> str:
    """Estrae l'hostname/IP puro da una stringa asset (toglie schema, path, porta)."""
    raw = (raw or "").strip()
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.netloc or parsed.path
    raw = raw.split("/")[0]              # via eventuale path
    # via porta (solo host:port, non IPv6 con piu' ':').
    if raw.count(":") == 1:
        raw = raw.split(":")[0]
    return raw.strip()


def _reachable(host: str, ports=(80, 443, 22, 8080), timeout: float = 1.5) -> bool:
    """True se una connessione TCP riesce su almeno una delle porte note.

    Le porte sono sondate in parallelo: il tempo totale resta ~`timeout`
    anche per host che filtrano/droppano i pacchetti, invece di sommare il
    timeout di ogni porta in sequenza.
    """
    def _probe(port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        futures = [pool.submit(_probe, p) for p in ports]
        for fut in as_completed(futures):
            if fut.result():
                for f in futures:
                    f.cancel()
                return True
    return False


def _ssh_probe(host: str, username: str, password: str,
               timeout: float = 3.0) -> tuple[bool, str]:
    """
    Tenta un login SSH reale. Ritorna (ok, motivo).

    Il motivo non e' decorativo: "credenziali rifiutate" e "host key non nei
    known_hosts" sono due fallimenti che si somigliano sullo schermo e non
    hanno niente in comune nella soluzione. Chi importa un perimetro deve
    sapere se correggere il foglio o il proprio known_hosts.
    """
    import paramiko

    client = paramiko.SSHClient()
    # Coerente con lo scan autenticato reale (scanner.py): carica i known_hosts
    # e RIFIUTA host key sconosciute. AutoAddPolicy accetterebbe qualunque
    # chiave, esponendo le credenziali dell'asset a un MITM.
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            host,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        return True, "ok"
    except paramiko.AuthenticationException:
        return False, "auth_failed"
    except paramiko.SSHException as exc:
        # RejectPolicy solleva SSHException: e' un rifiuto NOSTRO, non
        # dell'host, e va detto per quello che e'.
        low = str(exc).lower()
        if "known_hosts" in low or "not found in" in low:
            return False, "host_key_unknown"
        return False, "protocol_error"
    except socket.timeout:
        return False, "timeout"
    except Exception:
        return False, "unreachable"
    finally:
        client.close()


def _check_ssh(asset: Asset, timeout: float = 3.0) -> bool:
    """Tenta login SSH reale con le credenziali dell'asset. True se ha successo."""
    try:
        password = decrypt_password(asset.password)
    except RuntimeError:
        return False
    return _ssh_probe(asset.ip, asset.username, password, timeout)[0]


@app.get("/api/asset/health")
def api_asset_health(host: str, index: int,
                     user: CurrentUser = Depends(get_current_user)):
    """
    Raggiungibilita' TCP + (se asset ha credenziali) login SSH.
    Risposta: {reachable, ssh_ok}  — ssh_ok=null se nessuna credenziale.
    'host' deve combaciare con l'IP dell'asset indicato da 'index' (nel cono
    di visibilita' dell'utente): impedisce di usare l'endpoint come sonda di
    rete verso host arbitrari (era sfruttabile anche da 'viewer').
    """
    _require_asset_in_scope(user, index)
    try:
        asset = get_asset(index, ASSETS_FILE)  # 'index' = id riga Supabase
    except AssetStoreError:
        asset = None
    h = _normalize_host(host)
    if not asset or not h or h != _normalize_host(asset.ip):
        raise Forbidden("Host non corrisponde all'asset indicato")

    reachable = _reachable(h)
    ssh_ok = None

    if reachable and asset.auth_required:
        if is_encrypted(asset.password):
            ssh_ok = _check_ssh(asset)
        else:
            ssh_ok = False  # password in chiaro: login rifiutato

    return {"host": host, "reachable": reachable, "ssh_ok": ssh_ok}


@app.get("/api/cve")
def api_cve(product: str, version: str | None = None,
            os_type: str | None = None, os_major_version: str | None = None,
            user: CurrentUser = Depends(get_current_user)):
    """
    Lista COMPLETA di id CVE (OSV) per (prodotto, versione).
    Usato dal 'show more' della pagina Audit per espandere oltre i 10 salvati.

    L'ecosistema OSV (richiesto dall'API) e' dedotto dal SO se fornito,
    altrimenti default Debian.
    """
    eco = os_ecosystem(os_type, os_major_version) or "Debian"
    return query_osv_ids(product, version, ecosystem=eco)


def _scope_filter_assets(assets: list, user: CurrentUser) -> list:
    """Applica il cono di visibilita' all'inventario (editor: solo assegnati)."""
    ids = visible_asset_ids(user)
    if ids is None:
        return assets
    return [a for a in assets if a.id in ids]


def _assignments_by_asset() -> dict:
    """{asset_id: [{'type','id','name'}]} per la colonna ASSEGNATO A della UI."""
    rows = db.fetch_all_assignments() or []
    out: dict = {}
    for r in rows:
        if r.get("user_id") is not None:
            entry = {"type": "user", "id": r["user_id"],
                     "name": (r.get("users") or {}).get("username", "?")}
        else:
            entry = {"type": "group", "id": r["group_id"],
                     "name": (r.get("groups") or {}).get("name", "?")}
        out.setdefault(r["asset_id"], []).append(entry)
    return out


@app.get("/api/assets")
def api_assets(user: CurrentUser = Depends(get_current_user)):
    """
    Ritorna l'inventario interpretato (senza password).
    Editor/stakeholder: solo asset assegnati.
    Auditor/viewer/stakeholder: username redatto.
    """
    try:
        assets = _scope_filter_assets(load_assets(ASSETS_FILE), user)
    except AssetStoreError as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)
    out = [a.to_dict() for a in assets]
    if user.readonly:
        for d in out:
            d["username"] = None
    return {"assets": out}


def _asset_full(a: Asset) -> dict:
    """Serializzazione per la pagina CRUD. La password non viene mai esposta.

    'index' = id riga Supabase (nome mantenuto per compatibilita' frontend).
    """
    return {
        "index": a.id,
        "ip": a.ip,
        "username": a.username,
        "has_password": bool(a.password),
        "password_encrypted": is_encrypted(a.password) if a.password else True,
        "auth_required": a.auth_required,
        "os_type": a.os_type,
        "os_major_version": a.os_major_version,
        "enabled": a.enabled,
    }


@app.get("/api/assets/all")
def api_assets_all(user: CurrentUser = Depends(get_current_user)):
    """
    Inventario completo per la gestione CRUD, con le assegnazioni
    utente/gruppo di ogni asset (cono di visibilita').
    Editor/stakeholder: solo asset assegnati.
    Auditor/viewer/stakeholder: username redatto.
    """
    try:
        assets = _scope_filter_assets(load_assets(ASSETS_FILE), user)
    except AssetStoreError as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)
    assign = _assignments_by_asset()
    out = []
    for a in assets:
        d = _asset_full(a)
        d["assignments"] = assign.get(a.id, [])
        if user.readonly:
            d["username"] = ""
            d["has_password"] = False
        out.append(d)
    return {"assets": out}


@app.post("/api/assets")
async def api_assets_create(request: Request,
                            user: CurrentUser = Depends(_writer)):
    """
    Aggiunge un asset all'inventario. Body: {ip, username, password}.
    Editor: l'asset creato viene AUTO-ASSEGNATO a lui (o a un suo gruppo se il
    body indica 'assign_group_id'), cosi' non puo' creare asset orfani ne'
    fuori dal proprio cono di visibilita'.
    """
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    if not ip:
        return JSONResponse({"error": "Missing IP"}, status_code=400)
    os_type = (body.get("os_type") or "").strip().lower()
    if os_type not in ("linux", "windows"):
        return JSONResponse({"error": "OS type required (linux or windows)"}, status_code=400)
    assign_group = body.get("assign_group_id")
    if user.scoped and assign_group is not None \
            and int(assign_group) not in user.group_ids:
        raise Forbidden("Non appartieni al gruppo indicato")
    plain_pw = (body.get("password") or "").strip()
    try:
        stored_pw = encrypt_password(plain_pw) if plain_pw else ""
    except RuntimeError as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)
    new_id = add_asset(Asset(
        ip=ip,
        username=(body.get("username") or "").strip(),
        password=stored_pw,
        os_type=os_type,
        os_major_version=(body.get("os_major_version") or "").strip(),
        enabled=bool(body.get("enabled", True)),
    ))
    if new_id is None:
        return JSONResponse({"error": "Supabase non raggiungibile"}, status_code=503)
    _audit("asset.create", request, user,
           target={"type": "asset", "id": new_id, "label": ip},
           detail={"os_type": os_type,
                   "os_major_version": (body.get("os_major_version") or "").strip() or None,
                   "enabled": bool(body.get("enabled", True)),
                   "credentials_set": bool(plain_pw)})
    if user.scoped:
        # L'auto-assegnazione e' una concessione di visibilita' fatta
        # dall'applicativo, non dall'utente: senza traccia sembrerebbe che
        # l'editor abbia sempre avuto quell'asset nel proprio cono.
        if assign_group is not None:
            db.add_asset_assignment(new_id, group_id=int(assign_group))
            _audit("assignment.auto", request, user,
                   target={"type": "asset", "id": new_id, "label": ip},
                   detail={"group_id": int(assign_group), "reason": "creator_scope"})
        else:
            db.add_asset_assignment(new_id, user_id=user.id)
            _audit("assignment.auto", request, user,
                   target={"type": "asset", "id": new_id, "label": ip},
                   detail={"user_id": user.id, "reason": "creator_scope"})
    return {"ok": True, "index": new_id}


@app.get("/api/assets/import/template")
def api_assets_import_template(user: CurrentUser = Depends(_writer)):
    """
    Contratto del modello di import: colonne prefissate + due righe di esempio.

    Il file lo genera il browser (stesso SheetJS degli export), ma le colonne
    le detta il server: se il modello scaricato e il validatore divergessero,
    l'operatore compilerebbe diligentemente un file che viene rifiutato.
    """
    return asset_import.template()


def _probe_row(fields: dict) -> dict:
    """Sonda di rete per una riga: raggiungibilita' TCP + login se ha credenziali."""
    host = _normalize_host(fields["ip"])
    reachable = _reachable(host)
    ssh = None
    if fields["username"] and fields["password"]:
        if not reachable:
            # Non si tenta un login verso un host che non risponde: il
            # fallimento sarebbe garantito e direbbe dell'host, non della
            # credenziale.
            ssh = {"ok": False, "reason": "unreachable"}
        else:
            ok, reason = _ssh_probe(host, fields["username"], fields["password"])
            ssh = {"ok": ok, "reason": reason}
    return {"reachable": reachable, "ssh": ssh}


def _import_preflight(rows: list, existing_ips: set[str], probe: bool = True) -> list[dict]:
    """
    Verdetto riga per riga, nell'ordine del file.

    'status' vale 'ok' | 'error' | 'duplicate' | 'warning'. La password non
    compare MAI nel verdetto: e' arrivata in chiaro dal foglio e non deve
    tornare indietro verso il browser ne' finire in un log.
    """
    seen: set[str] = set()
    report: list[dict] = []
    for i, raw in enumerate(rows):
        fields, errors = asset_import.normalize(raw if isinstance(raw, dict) else {})
        key = _normalize_host(fields["ip"]).lower()
        status, reasons = "ok", list(errors)
        if errors:
            status = "error"
        elif key and key in seen:
            status, reasons = "duplicate", ["duplicate_in_file"]
        elif key and key in existing_ips:
            status, reasons = "duplicate", ["duplicate_in_inventory"]
        if key:
            seen.add(key)
        report.append({
            "line": i + 1,
            "ip": fields["ip"],
            "username": fields["username"],
            "os_type": fields["os_type"],
            "has_credentials": bool(fields["username"] and fields["password"]),
            "status": status,
            "reasons": reasons,
            "reachable": None,
            "ssh": None,
            "_fields": fields,
        })

    # Le sonde partono solo per le righe che sarebbero davvero importabili:
    # non ha senso bussare all'host di una riga gia' scartata, e ogni sonda
    # evitata e' traffico che non generiamo verso reti altrui.
    todo = [r for r in report if r["status"] == "ok"]
    if probe and todo:
        with ThreadPoolExecutor(max_workers=min(16, len(todo))) as pool:
            futures = {pool.submit(_probe_row, r["_fields"]): r for r in todo}
            for fut in as_completed(futures):
                row = futures[fut]
                try:
                    res = fut.result()
                except Exception:
                    res = {"reachable": False, "ssh": None}
                row["reachable"] = res["reachable"]
                row["ssh"] = res["ssh"]
                if not res["reachable"]:
                    row["status"], row["reasons"] = "warning", ["unreachable"]
                elif res["ssh"] and not res["ssh"]["ok"]:
                    row["status"] = "warning"
                    row["reasons"] = ["ssh_" + res["ssh"]["reason"]]
    return report


def _import_summary(report: list[dict]) -> dict:
    """Conteggi per stato, piu' il totale importabile senza conferma."""
    counts = {"total": len(report), "ok": 0, "warning": 0, "error": 0, "duplicate": 0}
    for r in report:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return counts


def _public_report(report: list[dict]) -> list[dict]:
    """Verdetto ripulito dai campi interni (contiene la password in chiaro)."""
    return [{k: v for k, v in r.items() if not k.startswith("_")} for r in report]


def _existing_asset_ips() -> set[str]:
    """IP gia' in inventario, normalizzati. Cono ignorato di proposito: un
    editor non deve poter creare un duplicato di un asset che non vede."""
    try:
        return {_normalize_host(a.ip).lower() for a in load_assets(ASSETS_FILE) if a.ip}
    except AssetStoreError:
        return set()


@app.post("/api/assets/import/preflight")
async def api_assets_import_preflight(request: Request,
                                      user: CurrentUser = Depends(_writer)):
    """
    Verifica un file di import SENZA scrivere nulla. Body: {rows: [...]}.

    Ogni riga importabile riceve una sonda TCP e, se porta credenziali, un
    tentativo di login reale: l'esito e' quello che l'operatore vede prima di
    decidere se continuare o rivedere il file.
    """
    body = await request.json()
    rows = body.get("rows")
    if not isinstance(rows, list) or not rows:
        return JSONResponse({"error": "No rows"}, status_code=400)
    if len(rows) > asset_import.MAX_ROWS:
        return JSONResponse(
            {"error": f"Too many rows (max {asset_import.MAX_ROWS})",
             "max_rows": asset_import.MAX_ROWS}, status_code=413)

    report = _import_preflight(rows, _existing_asset_ips())
    summary = _import_summary(report)
    # La verifica e' un'attivita' di rete verso host di terzi fatta con
    # credenziali fornite da chi carica il file: lasciarla senza traccia
    # renderebbe l'import un canale di sondaggio anonimo.
    _audit("asset.import_preflight", request, user,
           detail={"rows": summary["total"], "ok": summary["ok"],
                   "warning": summary["warning"], "error": summary["error"],
                   "duplicate": summary["duplicate"]})
    return {"summary": summary, "rows": _public_report(report),
            "max_rows": asset_import.MAX_ROWS}


@app.post("/api/assets/import")
async def api_assets_import(request: Request,
                            user: CurrentUser = Depends(_writer)):
    """
    Import vero. Body: {rows: [...], acknowledge_warnings: bool}.

    Righe con errori o duplicate non entrano MAI. Le righe segnalate dalla
    sonda entrano solo con acknowledge_warnings=true: e' la scelta esplicita
    dell'operatore, e viene registrata come tale.

    Senza conferma le sonde vengono rieseguite qui: e' la garanzia che nessun
    asset entri in inventario senza una verifica di raggiungibilita' fresca,
    invece che sulla parola del browser.
    """
    body = await request.json()
    rows = body.get("rows")
    ack = bool(body.get("acknowledge_warnings"))
    if not isinstance(rows, list) or not rows:
        return JSONResponse({"error": "No rows"}, status_code=400)
    if len(rows) > asset_import.MAX_ROWS:
        return JSONResponse(
            {"error": f"Too many rows (max {asset_import.MAX_ROWS})",
             "max_rows": asset_import.MAX_ROWS}, status_code=413)

    assign_group = body.get("assign_group_id")
    if user.scoped and assign_group is not None \
            and int(assign_group) not in user.group_ids:
        raise Forbidden("Non appartieni al gruppo indicato")

    report = _import_preflight(rows, _existing_asset_ips(), probe=not ack)
    summary = _import_summary(report)
    if not ack and summary["warning"]:
        # 409: il file e' leggibile, e' la realta' di rete a non tornare.
        # Sta all'operatore decidere, non al server.
        _audit("asset.import", request, user, outcome="blocked",
               detail={"reason": "unconfirmed_warnings", **summary})
        return JSONResponse({"error": "warnings", "summary": summary,
                             "rows": _public_report(report)}, status_code=409)

    imported, failed = [], []
    for row in report:
        if row["status"] in ("error", "duplicate"):
            continue
        f = row["_fields"]
        try:
            stored_pw = encrypt_password(f["password"]) if f["password"] else ""
        except RuntimeError as exc:
            row["status"], row["reasons"] = "error", ["encrypt_failed"]
            failed.append({"line": row["line"], "ip": f["ip"], "error": str(exc)})
            continue
        new_id = add_asset(Asset(
            ip=f["ip"], username=f["username"], password=stored_pw,
            os_type=f["os_type"], os_major_version=f["os_major_version"],
            enabled=f["enabled"], environment=f["environment"],
            internet_facing=f["internet_facing"], criticality=f["criticality"],
        ))
        if new_id is None:
            row["status"], row["reasons"] = "error", ["store_unreachable"]
            failed.append({"line": row["line"], "ip": f["ip"],
                           "error": "Supabase non raggiungibile"})
            continue
        row["id"] = new_id
        imported.append({"id": new_id, "ip": f["ip"]})
        if user.scoped:
            # Stessa concessione di visibilita' della creazione singola: un
            # editor non deve creare asset che poi non vede.
            if assign_group is not None:
                db.add_asset_assignment(new_id, group_id=int(assign_group))
            else:
                db.add_asset_assignment(new_id, user_id=user.id)

    _audit("asset.import", request, user,
           outcome="success" if not failed else "partial",
           detail={"imported": len(imported), "failed": len(failed),
                   # 'probed' dice da dove vengono i conteggi qui sotto: con
                   # la conferma le sonde si saltano, quindi 'warning: 0' non
                   # significa "nessun avviso", significa "non richiesto".
                   "acknowledged_warnings": ack, "probed": not ack, **summary,
                   "ips": [x["ip"] for x in imported][:50]})
    if user.scoped and imported:
        _audit("assignment.auto", request, user,
               detail={"assets": [x["id"] for x in imported],
                       "group_id": int(assign_group) if assign_group is not None else None,
                       "user_id": None if assign_group is not None else user.id,
                       "reason": "creator_scope"})
    return {"ok": True, "imported": len(imported), "failed": failed,
            "summary": summary, "rows": _public_report(report)}


@app.put("/api/assets/{index}/assignments")
async def api_assets_assignments(index: int, request: Request,
                                 user: CurrentUser = Depends(_admin_manager)):
    """
    Sostituisce le assegnazioni utente/gruppo dell'asset (cono di visibilita').
    Body: {"user_ids": [..], "group_ids": [..]}. Solo admin e manager:
    l'editor non puo' riassegnare (rischio self-escalation su asset altrui).
    """
    body = await request.json()
    user_ids = body.get("user_ids") or []
    group_ids = body.get("group_ids") or []
    try:
        current = get_asset(index, ASSETS_FILE)
    except AssetStoreError as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)
    if current is None:
        return JSONResponse({"error": "Invalid index"}, status_code=404)
    prev = [a for a in (db.fetch_all_assignments() or []) if a["asset_id"] == index]
    if not db.set_asset_assignments(index, user_ids, group_ids):
        return JSONResponse({"error": "Supabase non raggiungibile"}, status_code=503)
    # Assegnare un asset ALLARGA il cono di visibilita' di qualcuno: e' una
    # concessione di accesso a dati, e come tale va registrata col prima/dopo.
    _audit("assignment.set", request, user,
           target={"type": "asset", "id": index, "label": current.ip},
           detail={"from": {"user_ids": sorted(a["user_id"] for a in prev if a.get("user_id")),
                            "group_ids": sorted(a["group_id"] for a in prev if a.get("group_id"))},
                   "to": {"user_ids": sorted(int(u) for u in user_ids),
                          "group_ids": sorted(int(g) for g in group_ids)}})
    return {"ok": True, "user_ids": user_ids, "group_ids": group_ids}


@app.put("/api/assets/{index}")
async def api_assets_update(index: int, request: Request,
                            user: CurrentUser = Depends(_writer)):
    """Aggiorna l'asset indicato (index = id Supabase). Body: {ip, username, password}.
    Editor: solo asset del proprio cono di visibilita'."""
    _require_asset_in_scope(user, index)
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    if not ip:
        return JSONResponse({"error": "Missing IP"}, status_code=400)
    os_type = (body.get("os_type") or "").strip().lower()
    if os_type not in ("linux", "windows"):
        return JSONResponse({"error": "OS type required (linux or windows)"}, status_code=400)
    try:
        current = get_asset(index, ASSETS_FILE)
    except AssetStoreError as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)
    if current is None:
        return JSONResponse({"error": "Invalid index"}, status_code=404)
    plain_pw = (body.get("password") or "").strip()
    if plain_pw:
        try:
            stored_pw = encrypt_password(plain_pw)
        except RuntimeError as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)
    else:
        stored_pw = current.password  # mantiene password cifrata esistente
    # 'enabled' opzionale: se assente, preserva lo stato corrente.
    enabled = body.get("enabled")
    enabled = current.enabled if enabled is None else bool(enabled)
    ok = update_asset(index, Asset(
        ip=ip,
        username=(body.get("username") or "").strip(),
        password=stored_pw,
        os_type=os_type,
        os_major_version=(body.get("os_major_version") or "").strip(),
        enabled=enabled,
        # Preserva il contesto business: non fa parte del form CRUD e verrebbe
        # altrimenti resettato ai default a ogni salvataggio dell'asset.
        environment=current.environment,
        internet_facing=current.internet_facing,
        criticality=current.criticality,
    ))
    if not ok:
        return JSONResponse({"error": "Supabase non raggiungibile"}, status_code=503)
    # Campi cambiati, non il record intero: il registro deve dire cosa e'
    # cambiato. La password non compare mai — solo il fatto che e' stata
    # riscritta (la credenziale di accesso a un host e' un fatto d'audit).
    changed = {}
    if ip != current.ip:
        changed["ip"] = {"from": current.ip, "to": ip}
    new_user = (body.get("username") or "").strip()
    if new_user != (current.username or ""):
        changed["username"] = {"from": current.username, "to": new_user}
    if os_type != (current.os_type or ""):
        changed["os_type"] = {"from": current.os_type, "to": os_type}
    new_osv = (body.get("os_major_version") or "").strip()
    if new_osv != (current.os_major_version or ""):
        changed["os_major_version"] = {"from": current.os_major_version, "to": new_osv}
    if enabled != current.enabled:
        changed["enabled"] = {"from": current.enabled, "to": enabled}
    if plain_pw:
        changed["credentials_rotated"] = True
    _audit("asset.update", request, user,
           target={"type": "asset", "id": index, "label": ip},
           detail={"changed": changed})
    return {"ok": True}


@app.patch("/api/assets/{index}/enabled")
async def api_assets_toggle(index: int, request: Request,
                            user: CurrentUser = Depends(_writer)):
    """Abilita/disabilita un asset per le scansioni. Body: {enabled: bool}.
    Editor: solo asset del proprio cono di visibilita'."""
    _require_asset_in_scope(user, index)
    body = await request.json()
    enabled = bool(body.get("enabled", True))
    if not set_asset_enabled(index, enabled):
        return JSONResponse({"error": "Invalid index"}, status_code=404)
    # Disabilitare un asset lo toglie da TUTTE le scansioni successive: e' il
    # modo piu' silenzioso di far sparire un host dai conteggi di sicurezza.
    _audit("asset.enabled_change", request, user,
           target={"type": "asset", "id": index},
           detail={"enabled": enabled})
    return {"ok": True, "enabled": enabled}


@app.delete("/api/assets/{index}")
def api_assets_delete(index: int, request: Request,
                      user: CurrentUser = Depends(_writer)):
    """Elimina l'asset indicato (index = id Supabase).
    Editor: solo asset del proprio cono di visibilita'."""
    _require_asset_in_scope(user, index)
    try:
        before = get_asset(index, ASSETS_FILE)
    except AssetStoreError:
        before = None
    if not delete_asset(index):
        return JSONResponse({"error": "Invalid index"}, status_code=404)
    _audit("asset.delete", request, user,
           target={"type": "asset", "id": index,
                   "label": getattr(before, "ip", None)},
           detail={"os_type": getattr(before, "os_type", None)})
    return {"ok": True}


# ---------------------------------------------------------------------------
# AMMINISTRAZIONE UTENTI E GRUPPI (cono di visibilita')
# ---------------------------------------------------------------------------

@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, user: CurrentUser = Depends(_admin_only)):
    """Pagina ADMIN: gestione utenti, gruppi e membership. Solo admin."""
    return templates.TemplateResponse("admin.html", {"request": request})


@app.get("/api/users")
def api_users_list(user: CurrentUser = Depends(_admin_manager)):
    """Elenco utenti (senza hash password). Admin e manager (il manager ne ha
    bisogno per assegnare gli asset); le scritture restano solo admin.

    Ogni riga porta lo stato del freno anti-guessing ('lock'): un account
    bloccato da troppi login falliti non e' distinguibile da uno con la
    password dimenticata se non lo si dice, e l'admin finirebbe per resettare
    credenziali che funzionano.
    """
    users = db.fetch_users()
    if users is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    auth_cfg = load_config().get("auth")
    for u in users:
        u["lock"] = ratelimit.user_status(u.get("username") or "", auth_cfg)
    return {"users": users}


@app.post("/api/users/{user_id}/unlock")
def api_users_unlock(user_id: int, request: Request,
                     user: CurrentUser = Depends(_admin_only)):
    """
    Sblocca subito un account frenato dai troppi login falliti, senza
    aspettare la scadenza della finestra e senza toccare la password.

    Solo admin: rimuovere il freno riapre la porta a chi stava provando le
    password, quindi e' una decisione da registrare con un nome sopra.
    """
    target = db.fetch_user(user_id)
    if not target:
        return JSONResponse({"error": "Utente non trovato"}, status_code=404)
    cleared = ratelimit.clear_user(target.get("username") or "")
    _audit("auth.unlock", request, user,
           target={"type": "user", "id": user_id,
                   "label": target.get("username")},
           detail={"cleared_failures": cleared})
    return {"ok": True, "cleared_failures": cleared,
            "lock": ratelimit.user_status(target.get("username") or "",
                                          load_config().get("auth"))}


def _send_invite(user_row: dict) -> dict:
    """
    Genera il token di attivazione e invia (o espone) il link.
    SMTP configurato -> email; SMTP assente -> il link torna all'admin nella
    risposta per la consegna manuale. La password non viaggia MAI via email.
    """
    token = create_onetime_token(user_row["id"], "activation")
    if token is None:
        return {"error": "Supabase non raggiungibile"}
    link = activation_link(token)
    if smtp_enabled() and user_row.get("email"):
        try:
            send_activation(user_row["email"], user_row["username"], token)
            return {"sent": True, "email": user_row["email"]}
        except MailError as exc:
            logger.warning("send_activation fallita: %s", exc)
            return {"sent": False, "activation_link": link,
                    "warning": f"Email non inviata ({exc}); consegna il link manualmente."}
    return {"sent": False, "activation_link": link,
            "warning": "SMTP non configurato: consegna il link manualmente."}


@app.post("/api/users")
async def api_users_create(request: Request,
                           user: CurrentUser = Depends(_admin_only)):
    """
    Crea un utente INVITATO. Body: {username, email, role}.
    Nessuna password: l'utente la sceglie via link di attivazione one-time
    (l'apertura del link valida anche l'email). Solo admin.
    Retro-compatibilita': se il body contiene 'password' l'utente e' creato
    attivo, ma con cambio password forzato al primo accesso.
    """
    body = await request.json()
    username = (body.get("username") or "").strip()
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    role = (body.get("role") or "viewer").strip().lower()
    if not username:
        return JSONResponse({"error": "username obbligatorio"}, status_code=400)
    if role not in ROLES:
        return JSONResponse({"error": f"Ruolo non valido: {role}",
                             "valid": list(ROLES)}, status_code=400)
    if not password and (not email or "@" not in email):
        return JSONResponse({"error": "email valida obbligatoria per l'invito "
                             "(oppure fornisci una password provvisoria)"},
                            status_code=400)
    row = {"username": username, "role": role, "email": email or None}
    if password:
        row.update({"password_hash": hash_password(password),
                    "is_active": True, "must_change_password": True})
    else:
        row.update({"password_hash": None, "is_active": False})
    new_id = db.insert_user(row)
    if new_id is None:
        _audit("user.create", request, user, outcome="failure",
               target={"type": "user", "label": username},
               detail={"role": role, "reason": "duplicate_or_db_unreachable"})
        return JSONResponse({"error": "Creazione fallita (username/email duplicati o DB non raggiungibile)"},
                            status_code=409)
    _audit("user.create", request, user,
           target={"type": "user", "id": new_id, "label": username},
           detail={"role": role, "email": email or None,
                   "activation": "password" if password else "invite"})
    out = {"ok": True, "id": new_id}
    if not password:
        invite = _send_invite({"id": new_id, "username": username, "email": email})
        if "error" in invite:
            return JSONResponse(invite, status_code=503)
        out.update(invite)
    return out


@app.post("/api/users/{user_id}/invite")
def api_users_reinvite(user_id: int, request: Request,
                       user: CurrentUser = Depends(_admin_only)):
    """Reinvia l'invito di attivazione (brucia i token precedenti). Solo admin."""
    target = db.fetch_user(user_id)
    if not target:
        return JSONResponse({"error": "Utente non trovato"}, status_code=404)
    if target.get("is_active") and target.get("password_hash"):
        return JSONResponse({"error": "Utente gia' attivo"}, status_code=400)
    invite = _send_invite(target)
    if "error" in invite:
        return JSONResponse(invite, status_code=503)
    _audit("user.invite", request, user,
           target={"type": "user", "id": user_id, "label": target.get("username")},
           detail={"sent": bool(invite.get("sent")), "email": target.get("email")})
    return {"ok": True, **invite}


@app.post("/api/users/{user_id}/reset")
def api_users_reset(user_id: int, request: Request,
                    user: CurrentUser = Depends(_admin_only)):
    """
    Invia un link di reset password all'utente (l'admin non conosce mai la
    password altrui). Solo admin.
    """
    target = db.fetch_user(user_id)
    if not target:
        return JSONResponse({"error": "Utente non trovato"}, status_code=404)
    if not target.get("is_active"):
        return JSONResponse({"error": "Utente non attivo: usa il reinvio invito"},
                            status_code=400)
    token = create_onetime_token(user_id, "reset")
    if token is None:
        return JSONResponse({"error": "Supabase non raggiungibile"}, status_code=503)
    link = activation_link(token)
    # Un admin che forza il reset della password di un altro account e' una
    # delle azioni piu' sensibili dell'applicativo: registrata sempre, prima
    # dell'esito della consegna (il token e' gia' stato emesso).
    _audit("user.password_reset", request, user,
           target={"type": "user", "id": user_id, "label": target.get("username")},
           detail={"email": target.get("email")})
    # Chi riceve un reset deve poter rientrare: tenerlo bloccato dai tentativi
    # falliti che hanno portato al reset non protegge nulla.
    ratelimit.clear_user(target.get("username") or "")
    if smtp_enabled() and target.get("email"):
        try:
            send_reset(target["email"], target["username"], token)
            return {"ok": True, "sent": True, "email": target["email"]}
        except MailError as exc:
            logger.warning("send_reset fallita: %s", exc)
            return {"ok": True, "sent": False, "reset_link": link,
                    "warning": f"Email non inviata ({exc}); consegna il link manualmente."}
    return {"ok": True, "sent": False, "reset_link": link,
            "warning": "SMTP non configurato o email assente: consegna il link manualmente."}


@app.put("/api/users/{user_id}")
async def api_users_update(user_id: int, request: Request,
                           user: CurrentUser = Depends(_admin_only)):
    """Aggiorna ruolo e/o password di un utente. Body: {role?, password?}."""
    body = await request.json()
    row = {}
    role = (body.get("role") or "").strip().lower()
    if role:
        if role not in ROLES:
            return JSONResponse({"error": f"Ruolo non valido: {role}",
                                 "valid": list(ROLES)}, status_code=400)
        row["role"] = role
    if body.get("password"):
        # Password impostata dall'admin = provvisoria: cambio forzato al
        # prossimo accesso (l'admin non deve conoscere la password d'uso).
        row["password_hash"] = hash_password(body["password"])
        row["must_change_password"] = True
        row["is_active"] = True
    if not row:
        return JSONResponse({"error": "Niente da aggiornare"}, status_code=400)
    # Stato PRECEDENTE letto prima dell'UPDATE: senza il ruolo di partenza il
    # registro direbbe solo "ora e' admin", non "e' stato promosso da viewer".
    before = db.fetch_user(user_id)
    # L'ultimo admin non puo' auto-degradarsi: lockout garantito.
    if row.get("role") and row["role"] != "admin":
        if before and before["role"] == "admin":
            admins = [u for u in (db.fetch_users() or []) if u["role"] == "admin"]
            if len(admins) <= 1:
                _audit("user.role_change", request, user, outcome="failure",
                       target={"type": "user", "id": user_id,
                               "label": (before or {}).get("username")},
                       detail={"from": before["role"], "to": row["role"],
                               "reason": "last_admin"})
                return JSONResponse({"error": "Impossibile rimuovere l'ultimo admin"},
                                    status_code=400)
    if not db.update_user(user_id, row):
        return JSONResponse({"error": "Invalid id or DB unreachable"}, status_code=404)
    tgt = {"type": "user", "id": user_id, "label": (before or {}).get("username")}
    # Due azioni distinte in una sola rotta: il cambio di ruolo e' un evento di
    # autorizzazione, la password impostata dall'admin e' un evento di
    # credenziali. Registrarle insieme renderebbe incercabile la prima.
    if row.get("role"):
        _audit("user.role_change", request, user, target=tgt,
               detail={"from": (before or {}).get("role"), "to": row["role"],
                       "self": user_id == user.id})
    if row.get("password_hash"):
        _audit("user.password_set", request, user, target=tgt,
               detail={"must_change_password": True})
    return {"ok": True}


@app.delete("/api/users/{user_id}")
def api_users_delete(user_id: int, request: Request,
                     user: CurrentUser = Depends(_admin_only)):
    """Elimina un utente (assegnazioni e membership cascano). Solo admin."""
    if user_id == user.id:
        return JSONResponse({"error": "Non puoi eliminare il tuo stesso utente"},
                            status_code=400)
    target = db.fetch_user(user_id)
    if target and target["role"] == "admin":
        admins = [u for u in (db.fetch_users() or []) if u["role"] == "admin"]
        if len(admins) <= 1:
            return JSONResponse({"error": "Impossibile eliminare l'ultimo admin"},
                                status_code=400)
    if not db.delete_user(user_id):
        return JSONResponse({"error": "Invalid id or DB unreachable"}, status_code=404)
    # La riga utente sparisce: senza queste due informazioni nel registro,
    # ruolo ed email dell'account cancellato non sono piu' ricostruibili.
    _audit("user.delete", request, user,
           target={"type": "user", "id": user_id,
                   "label": (target or {}).get("username")},
           detail={"role": (target or {}).get("role"),
                   "email": (target or {}).get("email")})
    return {"ok": True}


@app.get("/api/groups")
def api_groups_list(user: CurrentUser = Depends(_writer)):
    """
    Elenco gruppi con membri. Admin e manager: tutti i gruppi.
    Editor: solo i gruppi a cui appartiene.
    """
    groups = db.fetch_groups()
    if groups is None:
        return JSONResponse({"error": "Supabase unreachable"}, status_code=503)
    out = [{"id": g["id"], "name": g["name"],
            "member_ids": [m["user_id"] for m in (g.get("user_groups") or [])]}
           for g in groups]
    if user.scoped:
        out = [g for g in out if g["id"] in user.group_ids]
    return {"groups": out}


@app.post("/api/groups")
async def api_groups_create(request: Request,
                            user: CurrentUser = Depends(_admin_only)):
    """Crea un gruppo. Body: {name}. Solo admin."""
    body = await request.json()
    name = (body.get("name") or "").strip()
    if not name:
        return JSONResponse({"error": "Nome gruppo obbligatorio"}, status_code=400)
    new_id = db.insert_group(name)
    if new_id is None:
        return JSONResponse({"error": "Creazione fallita (nome duplicato o DB non raggiungibile)"},
                            status_code=409)
    _audit("group.create", request, user,
           target={"type": "group", "id": new_id, "label": name},
           detail={"name": name})
    return {"ok": True, "id": new_id}


@app.delete("/api/groups/{group_id}")
def api_groups_delete(group_id: int, request: Request,
                      user: CurrentUser = Depends(_admin_only)):
    """Elimina un gruppo (membership e assegnazioni cascano). Solo admin."""
    # Il gruppo porta con se' membership e assegnazioni: il registro conserva
    # cosa e' stato revocato insieme al gruppo (cascata invisibile altrimenti).
    before = next((g for g in (db.fetch_groups() or []) if g["id"] == group_id), None)
    if not db.delete_group(group_id):
        return JSONResponse({"error": "Invalid id or DB unreachable"}, status_code=404)
    _audit("group.delete", request, user,
           target={"type": "group", "id": group_id,
                   "label": (before or {}).get("name")},
           detail={"members": [m["user_id"]
                               for m in ((before or {}).get("user_groups") or [])]})
    return {"ok": True}


@app.put("/api/groups/{group_id}/members")
async def api_groups_members(group_id: int, request: Request,
                             user: CurrentUser = Depends(_admin_only)):
    """Sostituisce la membership del gruppo. Body: {user_ids: [..]}. Solo admin."""
    body = await request.json()
    user_ids = body.get("user_ids") or []
    groups = db.fetch_groups() or []
    before = next((g for g in groups if g["id"] == group_id), None)
    prev_ids = sorted(m["user_id"] for m in ((before or {}).get("user_groups") or []))
    if not db.set_group_members(group_id, user_ids):
        return JSONResponse({"error": "Invalid id or DB unreachable"}, status_code=503)
    # La membership determina il cono di visibilita': va registrata come delta
    # (chi e' entrato, chi e' uscito), non come stato finale — e' l'ingresso in
    # un gruppo il fatto che un audit contesta.
    now_ids = sorted(int(u) for u in user_ids)
    _audit("group.members_set", request, user,
           target={"type": "group", "id": group_id,
                   "label": (before or {}).get("name")},
           detail={"from": prev_ids, "to": now_ids,
                   "added": sorted(set(now_ids) - set(prev_ids)),
                   "removed": sorted(set(prev_ids) - set(now_ids))})
    return {"ok": True}


@app.post("/api/identify")
async def api_identify(request: Request,
                       user: CurrentUser = Depends(_writer)):
    """
    Identifica il software impattato dalla descrizione testuale.
    Body JSON: {"description": "...", "use_osint": true|false}
    """
    body = await request.json()
    description = (body.get("description") or "").strip()
    use_osint = bool(body.get("use_osint", True))
    if not description:
        return JSONResponse({"error": "Missing description"}, status_code=400)

    info = identify_product(description, use_osint=use_osint)
    return {"description": description, "target": info.to_dict()}


@app.get("/api/scan")
def api_scan(request: Request, description: str, use_osint: bool = True,
             lang: str = "en", deep: bool = False,
             user: CurrentUser = Depends(_writer)):
    """
    Esegue la scansione e trasmette i risultati in streaming (SSE).
    Ogni messaggio 'data:' e' un JSON con l'esito di un singolo asset.
    Eventi finali: 'target' (prodotto identificato) e 'done'.

    'lang' (default 'en') seleziona la lingua della sintesi CVE generata dall'LLM.
    Editor: scansiona solo gli asset del proprio cono di visibilita'.
    """
    scope_ids = visible_asset_ids(user)

    def event_stream():
        try:
            yield from _event_stream_inner()
        except Exception as exc:
            yield _sse("error", {"message": f"Internal error: {exc}"})

    def _event_stream_inner():
        # 1. Identificazione prodotto.
        # Punto 1: se il dizionario locale non trova nulla, l'LLM sarà invocato.
        _local_peek = extract_local(description)
        if not _local_peek.product and use_osint:
            yield _sse("ai_call", {**_ai_tag(), "purpose": "extract"})
        target = identify_product(description, use_osint=use_osint)
        yield _sse("target", target.to_dict())

        if not target.product:
            yield _sse("done", {"scanned": 0, "note": "No product identified."})
            return

        # 2. Caricamento inventario.
        try:
            assets = load_assets(ASSETS_FILE)
        except AssetStoreError as exc:
            yield _sse("error", {"message": str(exc)})
            return
        # Esclude gli asset disabilitati in inventario dalla scansione.
        assets = [a for a in assets if a.enabled]
        # Cono di visibilita': l'editor scansiona solo gli asset assegnati.
        if scope_ids is not None:
            assets = [a for a in assets if a.id in scope_ids]

        # 2b. ADVISORY AI: se il prodotto e' noto ma l'input NON contiene una
        #     versione (vulnerabilita' generica senza CVE), chiedo all'LLM di
        #     dedurre il RANGE di versione affetto, da confrontare con quella
        #     installata su ciascun asset. Best-effort ('' se Ollama offline).
        if not target.version:
            yield _sse("ai_call", {**_ai_tag(), "purpose": "advisory"})
            yield ": keepalive\n\n"
            advisory_expr = extract_affected_version(target.product, description)
            affected_source = "ai" if advisory_expr else None
        else:
            advisory_expr = ""              # versione gia' nota dall'input
            affected_source = "input"
        if advisory_expr:
            yield _sse("advisory", {
                "product": target.product,
                "affected_version": advisory_expr,
                "source": "ai",
            })

        # 2c. Apertura della scansione su Supabase (best-effort: None se DB assente).
        scan_id = persist_scan(
            description, target.to_dict(), {},
            advisory={"affected_version": advisory_expr or None,
                      "affected_source": affected_source},
            actor={"id": user.id, "name": user.username},
        )
        # Il ledger 'scans' resta la fonte del DETTAGLIO di scansione; qui
        # entra la sola riga di attivita', cosi' la timeline "chi ha fatto
        # cosa" e' completa senza dover leggere due registri.
        _audit("scan.run", request, user,
               target={"type": "scan", "id": scan_id, "label": target.product},
               detail={"description": (description or "")[:200],
                       "product": target.product, "version": target.version or None,
                       "assets": len(assets), "use_osint": bool(use_osint)})

        # 3. Scansione asset per asset (risultati in tempo reale), con
        #    arricchimento CVE (OSV) sulla versione realmente rilevata.
        ai_remediation = bool(load_config()["ai"].get("ai_remediation", False))
        all_results: list[dict] = []
        summary_version = None
        summary_eco = None
        for asset in assets:
            result = scan_asset(asset, target, deep=deep)
            rd = result.to_dict()
            rd["affected_version"] = None
            rd["match_basis"] = "none"
            # Ecosistema OSV dedotto dal SO dell'asset (OSV richiede sempre
            # package.ecosystem; senza, la query e' rifiutata con 400).
            eco = os_ecosystem(asset.os_type, asset.os_major_version)
            # La query OSV e' a livello prodotto+ecosistema (la versione upstream
            # non e' usata: gli ecosistemi distro usano stringhe native). Percio'
            # basta che il prodotto sia PRESENTE: cosi' la colonna CVE si popola
            # anche per asset senza versione rilevata (es. auth simulato).
            if rd["product_found"]:
                # Fallback Debian se l'ecosistema non e' deducibile: mantiene la
                # colonna CVE per-asset coerente col conteggio di sintesi (che usa
                # lo stesso fallback), evitando header 304 e righe vuote.
                asset_eco = eco or "Debian"
                info = query_osv(target.product, rd["detected_version"], ecosystem=asset_eco)
                rd["cve_count"] = info["count"]
                rd["cve_ids"] = info["ids"]
                rd["cve_error"] = info["error"]
                if summary_version is None and rd["detected_version"]:
                    summary_version = rd["detected_version"]
                if summary_eco is None:
                    summary_eco = asset_eco
                # Verdetto advisory AI (vulnerabilita' senza CVE): sovrascrive
                # vuln_match confrontando la versione installata col range affetto.
                if advisory_expr:
                    imp = version_affected(rd["detected_version"], advisory_expr)
                    rd["vuln_match"] = ("VULNERABILE" if imp is True
                                        else "NON VULNERABILE" if imp is False
                                        else "INCERTO")
                    rd["match_basis"] = "ai-advisory"
                    rd["affected_version"] = advisory_expr
                elif target.version:
                    rd["match_basis"] = "input-version"
            else:
                rd["cve_count"] = None
                rd["cve_ids"] = []
                rd["cve_error"] = None
            # Arricchimento con OS info dall'inventario asset.
            rd["os_type"] = asset.os_type or None
            rd["os_major_version"] = asset.os_major_version or None
            # Punto 4: remediation AI (solo se abilitato in config e asset vulnerabile).
            rd["remediation"] = ""
            if ai_remediation and rd["vuln_match"] == "VULNERABILE" and rd.get("cve_count"):
                rd["remediation"] = generate_remediation(
                    target.product, rd.get("detected_version"),
                    rd.get("cve_ids", []), rd.get("cve_count", 0), lang=lang,
                )
            all_results.append(rd)
            # Persistenza del singolo esito (best-effort).
            persist_result(scan_id, rd)
            yield _sse("result", rd)

        # 3b. Grafo dipendenze REALI: unione delle dipendenze runtime rilevate
        #     (ldd -> pacchetto) su tutti gli asset dove il prodotto e' presente.
        #     Nessuna tabella di assunzioni: solo cio' che e' linkato sui target.
        runtime_deps = sorted({
            d for r in all_results for d in (r.get("dependencies") or [])
        })
        contributing = sum(1 for r in all_results if r.get("dependencies"))
        # Archi inter-dipendenza reali: unione deduplicata (non orientata), con
        # entrambi gli estremi fra le dipendenze risolte.
        _dep_set = set(runtime_deps)
        _seen_edges: set = set()
        runtime_edges: list[list[str]] = []
        for r in all_results:
            for a, b in (r.get("dep_edges") or []):
                if a not in _dep_set or b not in _dep_set or a == b:
                    continue
                key = tuple(sorted((a, b)))
                if key not in _seen_edges:
                    _seen_edges.add(key)
                    runtime_edges.append([a, b])
        yield _sse("deps", {
            "product": target.product,
            "dependencies": runtime_deps,
            "edges": runtime_edges,
            "source": "runtime-ldd",
            "asset_count": contributing,
        })

        # 4. Sintesi CVE (OSV per il conteggio ufficiale + LLM locale per il testo).
        ver = summary_version or target.version
        # Ecosistema: quello dell'asset che ha fornito la versione di sintesi;
        # fallback Debian (copertura OS-package piu' ampia in OSV) se ignoto.
        osv = query_osv(target.product, ver, ecosystem=summary_eco or "Debian")
        if osv["ids"]:
            yield _sse("ai_call", {**_ai_tag(), "purpose": "summary"})
            yield ": keepalive\n\n"
        summary = summarize_cves(target.product, ver, osv["ids"], count=osv["count"], lang=lang)
        cve_payload = {
            "product": target.product,
            "version": ver,
            "count": osv["count"],
            "ids": osv["ids"],
            "summary": summary,
            "error": osv["error"],
        }
        # Aggiorna la riga 'scans' con la sintesi CVE finale (best-effort).
        update_scan_summary(scan_id, cve_payload)
        yield _sse("cve", cve_payload)

        # Punto 2: triage AI post-scan — top-3 asset critici con motivazione e azione.
        if all_results:
            yield _sse("ai_call", {**_ai_tag(), "purpose": "triage"})
            yield ": keepalive\n\n"
            triage_text = generate_triage_report(all_results, target.product, lang=lang)
            if triage_text:
                yield _sse("triage", {"report": triage_text, "product": target.product})

        yield _sse("done", {"scanned": len(assets)})

    return StreamingResponse(event_stream(), media_type="text/event-stream")


def _sse(event: str, payload: dict) -> str:
    """Formatta un messaggio Server-Sent Event."""
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n"


def _ai_tag() -> dict:
    """Provider e modello LLM correnti per i log SSE."""
    ai = load_config()["ai"]
    provider = ai.get("provider", "ollama")
    model = (ai.get("claude_model") if provider == "claude"
             else ai.get("ollama_model", "qwen2.5:7b"))
    return {"provider": provider, "model": model}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)

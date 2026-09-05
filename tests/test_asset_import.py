"""
test_asset_import.py
--------------------
Import del perimetro asset da file (CSV / XLSX).

Il file lo legge il browser; qui si prova cio' che il browser non puo'
garantire. Le proprieta' da proteggere sono quattro:

  1. il modello e il validatore sono la STESSA cosa: le colonne del template
     scaricato sono quelle che l'import accetta, altrimenti si compila con
     diligenza un file destinato a essere rifiutato;
  2. nessun asset entra senza una verifica di raggiungibilita' fresca, a meno
     che l'operatore non abbia esplicitamente scavalcato l'avviso;
  3. "dato sbagliato" e "host spento" non sono la stessa cosa: il primo non
     entra mai, il secondo entra solo su conferma. Confonderli significa o
     perdere asset legittimi o importare spazzatura su conferma;
  4. la password arriva IN CHIARO dal foglio: non deve tornare indietro nella
     risposta, e in inventario deve arrivare cifrata.

Le sonde di rete sono sostituite (monkeypatch): la suite non deve bussare a
host reali, e i test devono dire la stessa cosa su una macchina scollegata.
"""
import asset_import
import app as app_module
import db
import pytest
from crypto import is_encrypted

# Rete di documentazione (RFC 5737): non instradabile, non puo' collidere con
# un host vero di chi esegue la suite.
IP_A, IP_B, IP_C = "192.0.2.101", "192.0.2.102", "192.0.2.103"


def _row(ip, **kw):
    base = {"ip": ip, "username": "", "password": "", "os_type": "linux",
            "os_major_version": "Ubuntu 22.04", "enabled": "yes",
            "environment": "production", "internet_facing": "no",
            "criticality": "3"}
    base.update(kw)
    return base


@pytest.fixture
def net(monkeypatch):
    """Rete finta e osservabile: si puo' decidere chi risponde e si conta chi
    e' stato interrogato."""
    state = {"reached": [], "ssh": [], "up": True, "ssh_ok": True}

    def _reachable(host, *a, **kw):
        state["reached"].append(host)
        return state["up"]

    def _ssh(host, username, password, timeout=3.0):
        state["ssh"].append((host, username, password))
        return (True, "ok") if state["ssh_ok"] else (False, "auth_failed")

    monkeypatch.setattr(app_module, "_reachable", _reachable)
    monkeypatch.setattr(app_module, "_ssh_probe", _ssh)
    return state


@pytest.fixture
def cleanup():
    """Cancella gli asset creati dal test, qualunque cosa sia successo."""
    created = []
    yield created
    for aid in created:
        db.delete_asset(aid)


def _import(client, rows, ack=False):
    return client.post("/api/assets/import",
                       json={"rows": rows, "acknowledge_warnings": ack})


def _ids_of(client, ips):
    """Id degli asset con quegli IP (per la pulizia)."""
    r = client.get("/api/assets/all")
    return [a["index"] for a in r.json().get("assets", []) if a["ip"] in ips]


# --------------------------------------------------------------- il modello

def test_template_columns_are_fixed_and_match_the_validator(role_clients):
    """Il template non e' un suggerimento: e' il contratto che il server
    applica."""
    r = role_clients["admin"].get("/api/assets/import/template")
    assert r.status_code == 200, r.text
    spec = r.json()
    names = [c["name"] for c in spec["columns"]]
    assert names == asset_import.COLUMN_NAMES
    assert "ip" in names and "os_type" in names
    # Ogni riga di esempio compila TUTTE le colonne dichiarate: un esempio
    # incompleto insegna un formato che poi viene rifiutato.
    for row in spec["rows"]:
        assert set(row) == set(names)


def test_template_ships_exactly_two_example_rows(role_clients):
    spec = role_clients["admin"].get("/api/assets/import/template").json()
    assert len(spec["rows"]) == 2


def test_example_rows_cannot_be_real_hosts(role_clients):
    """Gli esempi stanno in TEST-NET-1: importati per distrazione non mettono
    in scansione l'host di qualcun altro."""
    spec = role_clients["admin"].get("/api/assets/import/template").json()
    for row in spec["rows"]:
        assert row["ip"].startswith("192.0.2.")


def test_the_two_examples_cover_both_shapes(role_clients):
    """Un esempio con credenziali e uno senza: sono i due modi di censire un
    asset, e chi compila deve vederli entrambi."""
    spec = role_clients["admin"].get("/api/assets/import/template").json()
    creds = [bool(r["username"] and r["password"]) for r in spec["rows"]]
    assert sorted(creds) == [False, True]


# ------------------------------------------------------- la verifica di rete

def test_every_importable_row_is_probed(role_clients, net):
    r = role_clients["admin"].post("/api/assets/import/preflight",
                                   json={"rows": [_row(IP_A), _row(IP_B)]})
    assert r.status_code == 200, r.text
    assert sorted(net["reached"]) == [IP_A, IP_B]


def test_credentials_are_tested_only_when_complete(role_clients, net):
    """Un login di prova si fa solo se c'e' davvero una credenziale da
    provare."""
    role_clients["admin"].post("/api/assets/import/preflight", json={"rows": [
        _row(IP_A),                                        # nessuna credenziale
        _row(IP_B, username="u", password="p"),            # credenziale intera
    ]})
    assert [h for h, _, _ in net["ssh"]] == [IP_B]


def test_no_login_attempt_towards_a_silent_host(role_clients, net):
    """Verso un host che non risponde il login fallirebbe per forza: l'esito
    parlerebbe dell'host, non della credenziale."""
    net["up"] = False
    role_clients["admin"].post("/api/assets/import/preflight",
                               json={"rows": [_row(IP_A, username="u", password="p")]})
    assert net["ssh"] == []


def test_unreachable_host_is_a_warning_not_an_error(role_clients, net):
    """Un host spento oggi non e' un dato sbagliato: la decisione resta
    dell'operatore."""
    net["up"] = False
    d = role_clients["admin"].post("/api/assets/import/preflight",
                                   json={"rows": [_row(IP_A)]}).json()
    assert d["rows"][0]["status"] == "warning"
    assert d["rows"][0]["reasons"] == ["unreachable"]


def test_refused_credentials_are_reported_as_such(role_clients, net):
    net["ssh_ok"] = False
    d = role_clients["admin"].post("/api/assets/import/preflight", json={
        "rows": [_row(IP_A, username="u", password="p")]}).json()
    assert d["rows"][0]["status"] == "warning"
    assert d["rows"][0]["reasons"] == ["ssh_auth_failed"]


def test_preflight_writes_nothing(role_clients, net):
    before = len(role_clients["admin"].get("/api/assets/all").json()["assets"])
    role_clients["admin"].post("/api/assets/import/preflight",
                               json={"rows": [_row(IP_A)]})
    after = len(role_clients["admin"].get("/api/assets/all").json()["assets"])
    assert before == after


# ------------------------------------------------------------ i dati storti

@pytest.mark.parametrize("row,reason", [
    (_row(""), "ip_missing"),
    (_row("not an ip!"), "ip_invalid"),
    (_row("192.168.0.1:22"), "ip_invalid"),
    (_row("https://example.com/app"), "ip_invalid"),
    (_row(IP_A, os_type=""), "os_type_missing"),
    (_row(IP_A, os_type="solaris"), "os_type_invalid"),
    (_row(IP_A, username="u"), "credentials_incomplete"),
    (_row(IP_A, password="p"), "credentials_incomplete"),
    (_row(IP_A, environment="prod-ish"), "environment_invalid"),
    (_row(IP_A, criticality="9"), "criticality_invalid"),
])
def test_malformed_rows_are_errors_with_a_named_reason(role_clients, net, row, reason):
    d = role_clients["admin"].post("/api/assets/import/preflight",
                                   json={"rows": [row]}).json()
    assert d["rows"][0]["status"] == "error"
    assert reason in d["rows"][0]["reasons"]


def test_a_bad_row_is_never_imported_not_even_with_confirmation(role_clients, net, cleanup):
    """La conferma vale sugli avvisi di rete, non sui dati: nessun 'importa
    comunque' rende valido un IP che non esiste."""
    r = _import(role_clients["admin"], [_row("still not an ip")], ack=True)
    assert r.status_code == 200, r.text
    assert r.json()["imported"] == 0


def test_a_bad_row_does_not_stop_the_good_ones(role_clients, net, cleanup):
    """Un foglio compilato a mano ha quasi sempre una riga storta: farebbe
    perdere l'intero import per una virgola."""
    r = _import(role_clients["admin"], [_row("nope!"), _row(IP_A)])
    assert r.status_code == 200, r.text
    cleanup.extend(_ids_of(role_clients["admin"], {IP_A}))
    assert r.json()["imported"] == 1


# ------------------------------------------------ l'IP scritto male

@pytest.mark.parametrize("ip", [
    "999.999.999.999",   # ottetti fuori scala
    "192.0.2.300",       # un solo ottetto fuori scala
    "192.0.2",           # troppo corto
    "192.0.2.1.5",       # troppo lungo
    "008.8.8.8",         # zero iniziale: 008 e' 8 o ottale?
    "1234",              # un'etichetta sola, tutta numerica
    "abc.123",           # etichetta di destra numerica
])
def test_an_ip_written_wrong_is_an_error_not_a_hostname(role_clients, net, ip):
    """
    Il buco che questa regola chiude: le etichette DNS possono essere numeriche,
    quindi senza un controllo esplicito '999.999.999.999' passa come "nome
    valido", viene messo in sonda, non risponde (ovviamente) e arriva
    all'operatore come un banale AVVISO di host spento. L'operatore conferma,
    e in inventario entra un asset che non potra' mai essere scansionato.
    La RFC 1123 §2.1 vieta proprio l'etichetta finale tutta numerica, per non
    confondere un nome con un indirizzo.
    """
    d = role_clients["admin"].post("/api/assets/import/preflight",
                                   json={"rows": [_row(ip)]}).json()
    row = d["rows"][0]
    assert row["status"] == "error", f"{ip} deve essere un errore, non {row['status']}"
    assert row["reasons"] == ["ip_malformed_address"]


@pytest.mark.parametrize("ip", ["999.999.999.999", "192.0.2", "abc.123"])
def test_an_ip_written_wrong_is_never_probed(role_clients, net, ip):
    """Non si bussa a un indirizzo che non esiste: la sonda direbbe 'non
    risponde', cioe' la cosa sbagliata."""
    role_clients["admin"].post("/api/assets/import/preflight",
                               json={"rows": [_row(ip)]})
    assert net["reached"] == []


@pytest.mark.parametrize("ip", ["999.999.999.999", "192.0.2.300", "1234"])
def test_an_ip_written_wrong_never_enters_not_even_confirmed(role_clients, net, ip, cleanup):
    r = _import(role_clients["admin"], [_row(ip)], ack=True)
    assert r.status_code == 200, r.text
    assert r.json()["imported"] == 0


@pytest.mark.parametrize("host", [
    "8.8.8.8", "0.0.0.0", "::1", "fe80::1",
    "srv01", "host-01.reparto.local", "esempio.local",
])
def test_legitimate_hosts_still_pass(role_clients, net, host):
    """La regola non deve trasformarsi in un rifiuto di host validi: un nome a
    etichetta singola e un IPv6 sono perimetro perfettamente legittimo."""
    d = role_clients["admin"].post("/api/assets/import/preflight",
                                   json={"rows": [_row(host)]}).json()
    assert d["rows"][0]["status"] != "error", f"{host} e' valido: {d['rows'][0]['reasons']}"

# ------------------------------------------------------------- i duplicati

def test_the_same_ip_twice_in_one_file_enters_once(role_clients, net, cleanup):
    r = _import(role_clients["admin"], [_row(IP_A), _row(IP_A, os_major_version="altro")])
    assert r.status_code == 200, r.text
    cleanup.extend(_ids_of(role_clients["admin"], {IP_A}))
    assert r.json()["imported"] == 1
    assert r.json()["summary"]["duplicate"] == 1


def test_an_ip_already_in_inventory_is_not_imported_again(role_clients, net, cleanup):
    first = _import(role_clients["admin"], [_row(IP_A)])
    assert first.json()["imported"] == 1
    cleanup.extend(_ids_of(role_clients["admin"], {IP_A}))
    again = role_clients["admin"].post("/api/assets/import/preflight",
                                       json={"rows": [_row(IP_A)]}).json()
    assert again["rows"][0]["status"] == "duplicate"
    assert again["rows"][0]["reasons"] == ["duplicate_in_inventory"]


# --------------------------------------------------- avvisi e consenso

def test_warnings_block_the_import_until_someone_decides(role_clients, net):
    """Il server non decide al posto dell'operatore, ma non decide nemmeno
    per lui in silenzio: si ferma e mostra il motivo."""
    net["up"] = False
    r = _import(role_clients["admin"], [_row(IP_A)])
    assert r.status_code == 409
    body = r.json()
    assert body["error"] == "warnings"
    assert body["summary"]["warning"] == 1
    assert body["rows"][0]["reasons"] == ["unreachable"]


def test_confirmation_imports_the_warned_rows(role_clients, net, cleanup):
    net["up"] = False
    r = _import(role_clients["admin"], [_row(IP_A)], ack=True)
    assert r.status_code == 200, r.text
    cleanup.extend(_ids_of(role_clients["admin"], {IP_A}))
    assert r.json()["imported"] == 1


def test_a_clean_import_is_verified_again_before_writing(role_clients, net, cleanup):
    """Senza conferma le sonde si rifanno al momento della scrittura: il
    verdetto mostrato all'operatore e' un'informazione, non un lasciapassare
    che il browser puo' rigiocare."""
    net["reached"].clear()
    r = _import(role_clients["admin"], [_row(IP_A)])
    assert r.status_code == 200, r.text
    cleanup.extend(_ids_of(role_clients["admin"], {IP_A}))
    assert net["reached"] == [IP_A]


# ------------------------------------------------------------- le password

def test_the_password_never_comes_back(role_clients, net):
    """Arriva in chiaro dal foglio: se tornasse indietro finirebbe nella
    cronologia del browser e in qualunque log intermedio."""
    secret = "S3cret-not-to-echo"
    r = role_clients["admin"].post("/api/assets/import/preflight", json={
        "rows": [_row(IP_A, username="u", password=secret)]})
    assert secret not in r.text


def test_the_password_reaches_the_inventory_encrypted(role_clients, net, cleanup):
    r = _import(role_clients["admin"], [_row(IP_A, username="u", password="S3cret-2026")])
    assert r.status_code == 200, r.text
    ids = _ids_of(role_clients["admin"], {IP_A})
    cleanup.extend(ids)
    row = [a for a in (db.fetch_assets() or []) if a.get("ip") == IP_A]
    assert row and is_encrypted(row[0]["password"])


# ----------------------------------------------------------- chi puo' farlo

@pytest.mark.parametrize("role", ["admin", "manager", "editor"])
def test_writers_can_import(role_clients, role, net):
    assert role_clients[role].post("/api/assets/import/preflight",
                                   json={"rows": [_row(IP_A)]}).status_code == 200


@pytest.mark.parametrize("role", ["auditor", "viewer", "stakeholder"])
def test_readers_cannot_import(role_clients, role, net):
    """Il preflight e' una sonda di rete verso host di terzi fatta con
    credenziali fornite da chi carica: non e' una lettura."""
    assert role_clients[role].post("/api/assets/import/preflight",
                                   json={"rows": [_row(IP_A)]}).status_code == 403
    assert _import(role_clients[role], [_row(IP_A)]).status_code == 403


def test_anonymous_cannot_import(anon_client, net):
    assert anon_client.post("/api/assets/import/preflight",
                            json={"rows": [_row(IP_A)]}).status_code in (401, 403)


def test_an_editor_keeps_what_it_imports_in_its_own_cone(role_clients, net, cleanup):
    """Un editor che importasse asset fuori dal proprio cono creerebbe righe
    che poi non vede: invisibili a lui e sconosciute a tutti gli altri."""
    r = _import(role_clients["editor"], [_row(IP_C)])
    assert r.status_code == 200, r.text
    ids = _ids_of(role_clients["admin"], {IP_C})
    cleanup.extend(ids)
    assert r.json()["imported"] == 1
    visible = {a["ip"] for a in role_clients["editor"].get("/api/assets/all").json()["assets"]}
    assert IP_C in visible


# ------------------------------------------------------------- i limiti

def test_a_file_too_big_is_refused_before_any_probe(role_clients, net):
    """Ogni riga costa una sonda: un file enorme non sarebbe un import, sarebbe
    una scansione di rete lanciata da un form."""
    rows = [_row(f"10.90.{i // 256}.{i % 256}") for i in range(asset_import.MAX_ROWS + 1)]
    r = role_clients["admin"].post("/api/assets/import/preflight", json={"rows": rows})
    assert r.status_code == 413
    assert net["reached"] == []


def test_an_empty_body_is_refused(role_clients, net):
    assert role_clients["admin"].post("/api/assets/import/preflight",
                                      json={"rows": []}).status_code == 400


# --------------------------------------------------------------- la traccia

def test_the_check_leaves_a_trace(role_clients, net, monkeypatch):
    """Sondare host di terzi con credenziali altrui e' esattamente l'attivita'
    che un registro deve poter ricostruire."""
    seen = []
    real = app_module._audit
    monkeypatch.setattr(app_module, "_audit",
                        lambda a, *ar, **kw: (seen.append((a, kw.get("detail") or {})),
                                              real(a, *ar, **kw))[1])
    net["up"] = False
    role_clients["admin"].post("/api/assets/import/preflight",
                               json={"rows": [_row(IP_A), _row("bad!")]})
    ev = [d for a, d in seen if a == "asset.import_preflight"]
    assert ev, "il controllo deve lasciare traccia"
    assert ev[0]["rows"] == 2 and ev[0]["warning"] == 1 and ev[0]["error"] == 1


def test_the_override_is_recorded_as_an_override(role_clients, net, monkeypatch, cleanup):
    """Chi ha importato asset che la rete non confermava, e sapendolo, e' la
    domanda che un audit fa a valle."""
    seen = []
    real = app_module._audit
    monkeypatch.setattr(app_module, "_audit",
                        lambda a, *ar, **kw: (seen.append((a, kw.get("detail") or {})),
                                              real(a, *ar, **kw))[1])
    net["up"] = False
    _import(role_clients["admin"], [_row(IP_A)], ack=True)
    cleanup.extend(_ids_of(role_clients["admin"], {IP_A}))
    ev = [d for a, d in seen if a == "asset.import"]
    assert ev and ev[0]["acknowledged_warnings"] is True
    assert ev[0]["imported"] == 1


def test_a_refusal_is_recorded_too(role_clients, net, monkeypatch):
    seen = []
    real = app_module._audit
    monkeypatch.setattr(app_module, "_audit",
                        lambda a, *ar, **kw: (seen.append((a, kw.get("outcome"))),
                                              real(a, *ar, **kw))[1])
    net["up"] = False
    _import(role_clients["admin"], [_row(IP_A)])
    assert ("asset.import", "blocked") in seen


# --------------------------------------------- il contenuto che entra

def test_business_context_survives_the_import(role_clients, net, cleanup):
    """Environment, esposizione e criticita' pesano sulla prioritizzazione del
    rischio: se l'import le perdesse, ogni asset importato arriverebbe come
    'unknown' e il /risk mentirebbe per omissione."""
    r = _import(role_clients["admin"], [_row(
        IP_A, environment="staging", internet_facing="yes", criticality="5")])
    assert r.status_code == 200, r.text
    cleanup.extend(_ids_of(role_clients["admin"], {IP_A}))
    row = [a for a in (db.fetch_assets() or []) if a.get("ip") == IP_A][0]
    assert row["environment"] == "staging"
    assert row["internet_facing"] is True
    assert row["criticality"] == 5


def test_enabled_column_is_honoured(role_clients, net, cleanup):
    r = _import(role_clients["admin"], [_row(IP_A, enabled="no")])
    assert r.status_code == 200, r.text
    ids = _ids_of(role_clients["admin"], {IP_A})
    cleanup.extend(ids)
    row = [a for a in (db.fetch_assets() or []) if a.get("ip") == IP_A][0]
    assert row["enabled"] is False

"""
Resolver FIX VERSION (/api/posture/fixplan -> cve.compute_fix_plan).

Regressione originale: le app dell'inventario Windows hanno ecosystem
'Windows', che OSV non conosce. La query rispondeva 400 e l'interfaccia
mostrava "error — retry later", invitando a ritentare qualcosa che non poteva
riuscire.

Oggi il resolver e' a cascata (OSV -> MSRC -> NVD) e ogni risultato dichiara la
fonte. I test coprono i due livelli separatamente: '_osv_fix_plan' per la
logica OSV, 'compute_fix_plan' per l'instradamento fra le fonti.

Tutte le fonti sono mockate: i test descrivono il comportamento, non la
disponibilita' dei servizi.
"""

import pytest

import cve
import msrc
import nvd


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def _osv(monkeypatch, handler):
    """Sostituisce requests.post e registra le chiamate ricevute."""
    calls = []

    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append(json)
        return handler(json)

    monkeypatch.setattr(cve.requests, "post", fake_post)
    return calls


def _vuln(vid, name, ecosystem, fixed, range_type="ECOSYSTEM"):
    return {"id": vid, "affected": [{
        "package": {"name": name, "ecosystem": ecosystem},
        "ranges": [{"type": range_type,
                    "events": [{"introduced": "0"}, {"fixed": fixed}]}],
    }]}


# ------------------------------------------- ecosistema non supportato da OSV

def test_osv_reports_windows_as_unsupported_not_as_an_error(monkeypatch):
    _osv(monkeypatch, lambda body: FakeResponse(
        400, {"code": 3, "message": "invalid ecosystem"}))
    plan = cve._osv_fix_plan("Notepad++", "Windows", "7.8.1")
    assert plan["supported"] is False
    assert plan["error"] is None          # niente invito a ritentare
    assert plan["detail"] == "invalid ecosystem"
    assert plan["fix_version"] is None


def test_osv_does_not_fall_back_to_other_platforms(monkeypatch):
    """
    Una query senza ecosistema per 'putty' risponde con i pacchetti Linux
    omonimi: proporre una versione Mageia per un PuTTY installato su Windows
    sarebbe un'istruzione di remediation sbagliata. Meglio nessuna risposta.
    """
    calls = _osv(monkeypatch, lambda body: FakeResponse(
        400, {"code": 3, "message": "invalid ecosystem"}))
    cve._osv_fix_plan("PuTTY", "Windows", "0.70")
    assert len(calls) == 1
    assert calls[0]["package"]["ecosystem"] == "Windows"


def test_osv_query_is_skipped_when_there_is_nothing_valid_to_ask(monkeypatch):
    calls = _osv(monkeypatch, lambda body: FakeResponse(200, {"vulns": []}))
    plan = cve._osv_fix_plan("something", None, None)
    assert calls == []
    assert plan["supported"] is False


# ---------------------------------------------------- guasti vs non copertura

def test_network_failure_stays_a_retryable_error(monkeypatch):
    def boom(url, json=None, headers=None, timeout=None):
        raise cve.requests.RequestException("connection reset")

    monkeypatch.setattr(cve.requests, "post", boom)
    plan = cve.compute_fix_plan("openssl", "Debian", "1.0.1f")
    assert plan["supported"] is True
    assert "connection reset" in plan["error"]


def test_server_error_stays_a_retryable_error(monkeypatch):
    _osv(monkeypatch, lambda body: FakeResponse(503, {}))
    plan = cve.compute_fix_plan("openssl", "Debian", "1.0.1f")
    assert plan["error"] == "OSV HTTP 503"
    assert plan["supported"] is True


# ------------------------------------------------------------ calcolo del fix

def test_fix_version_is_the_highest_across_the_matching_cves(monkeypatch):
    _osv(monkeypatch, lambda body: FakeResponse(200, {"vulns": [
        _vuln("CVE-1", "openssl", "Debian:11", "1.0.2"),
        _vuln("CVE-2", "openssl", "Debian:11", "1.1.1k"),
    ]}))
    plan = cve.compute_fix_plan("openssl", "Debian", "1.0.1f")
    assert plan["fix_version"] == "1.1.1k"
    assert plan["unfixed"] == 0
    assert len(plan["cves"]) == 2


def test_commit_hashes_are_never_offered_as_a_fix_version(monkeypatch):
    """Un range GIT ha come 'fixed' uno SHA: non e' una versione installabile."""
    _osv(monkeypatch, lambda body: FakeResponse(200, {"vulns": [
        _vuln("CVE-1", "django", "PyPI", "5.2.8"),
        _vuln("CVE-2", "django", "PyPI",
              "eb31d845323618d688ad429479c6dda973056136", range_type="GIT"),
    ]}))
    plan = cve.compute_fix_plan("django", "PyPI", "1.11")
    assert plan["fix_version"] == "5.2.8"
    # La CVE resta elencata, ma senza fix utilizzabile.
    assert plan["unfixed"] == 1


def test_installed_version_narrows_the_query(monkeypatch):
    """Il fix plan riguarda le CVE che colpiscono la versione installata."""
    calls = _osv(monkeypatch, lambda body: FakeResponse(200, {"vulns": []}))
    cve.compute_fix_plan("django", "PyPI", "1.11")
    assert calls[0]["version"] == "1.11"
    assert calls[0]["package"] == {"name": "django", "ecosystem": "PyPI"}


def test_other_ecosystems_in_the_response_are_filtered_out(monkeypatch):
    _osv(monkeypatch, lambda body: FakeResponse(200, {"vulns": [
        _vuln("CVE-1", "putty", "Debian:12", "0.76"),
        _vuln("CVE-2", "putty", "Mageia:9", "0.84-1.mga9"),
    ]}))
    plan = cve.compute_fix_plan("PuTTY", "Debian", "0.70")
    assert plan["fix_version"] == "0.76"


def test_ecosystem_matches_its_release_suffixes(monkeypatch):
    _osv(monkeypatch, lambda body: FakeResponse(200, {"vulns": [
        _vuln("CVE-1", "openssl", "Debian:11", "1.1.1k"),
    ]}))
    assert cve.compute_fix_plan("openssl", "Debian", "1.0.1f")["fix_version"] == "1.1.1k"


def test_no_ecosystem_result_is_flagged_approximate(monkeypatch):
    _osv(monkeypatch, lambda body: FakeResponse(200, {"vulns": [
        _vuln("CVE-1", "somelib", "npm", "2.0.0"),
    ]}))
    plan = cve.compute_fix_plan("somelib", None, "1.0.0")
    assert plan["cross_ecosystem"] is True
    assert plan["fix_version"] == "2.0.0"


def test_empty_package_name_short_circuits(monkeypatch):
    calls = _osv(monkeypatch, lambda body: FakeResponse(200, {"vulns": []}))
    plan = cve.compute_fix_plan("", "Debian", "1.0")
    assert calls == []
    assert plan["supported"] is True and plan["fix_version"] is None


@pytest.mark.parametrize("status,message,expect_detail", [
    (400, "invalid ecosystem", "invalid ecosystem"),
    (400, "invalid query", "invalid query"),
    (400, "", "invalid query"),
])
def test_osv_bad_request_variants_are_all_permanent(monkeypatch, status, message,
                                                    expect_detail):
    _osv(monkeypatch, lambda body: FakeResponse(status, {"message": message}))
    plan = cve._osv_fix_plan("x", "Windows", "1.0")
    assert plan["supported"] is False
    assert plan["error"] is None
    assert plan["detail"] == expect_detail


# ------------------------------------------------------ cascata fra le fonti

@pytest.fixture
def sources(monkeypatch):
    """Sostituisce i tre resolver e registra l'ordine in cui vengono chiamati."""
    order = []
    plans = {"osv": {"supported": False, "detail": "no osv"},
             "nvd": {"supported": False, "detail": "no nvd"},
             "msrc": {"supported": False, "detail": "no msrc"}}

    def fake_osv(name, ecosystem=None, version=None, timeout=None):
        order.append("osv")
        return {"cves": [], "fix_version": None, "unfixed": 0, "error": None,
                **plans["osv"]}

    def fake_nvd(name, version=None, timeout=None):
        order.append("nvd")
        return {"cves": [], "fix_version": None, "unfixed": 0, "error": None,
                **plans["nvd"]}

    def fake_msrc(name, version=None):
        order.append("msrc")
        return {"cves": [], "fix_version": None, "unfixed": 0, "error": None,
                **plans["msrc"]}

    monkeypatch.setattr(cve, "_osv_fix_plan", fake_osv)
    monkeypatch.setattr(nvd, "fix_plan", fake_nvd)
    monkeypatch.setattr(msrc, "fix_plan", fake_msrc)
    return {"order": order, "plans": plans}


def test_package_ecosystem_is_served_by_osv_alone(sources):
    sources["plans"]["osv"] = {"supported": True, "fix_version": "3.6.3-1"}
    plan = cve.compute_fix_plan("openssl", "Debian", "1.0.1f")
    assert plan["source"] == "osv"
    assert plan["source_label"] == "OSV.dev"
    assert sources["order"] == ["osv"]        # nessuna fonte di troppo


def test_windows_app_skips_osv_and_lands_on_nvd(sources):
    """Interrogare OSV con ecosystem 'Windows' e' una 400 garantita."""
    sources["plans"]["nvd"] = {"supported": True, "fix_version": "8.9.6.4"}
    plan = cve.compute_fix_plan("Notepad++", "Windows", "7.8.1")
    assert plan["source"] == "nvd"
    assert "osv" not in sources["order"]
    assert plan["fix_version"] == "8.9.6.4"


def test_microsoft_product_prefers_msrc_for_the_kb_numbers(sources):
    sources["plans"]["msrc"] = {"supported": True, "fix_version": "10.0.28000.2269",
                                "kbs": ["5087538"]}
    sources["plans"]["nvd"] = {"supported": True, "fix_version": "10.0.1"}
    plan = cve.compute_fix_plan("Microsoft Edge", "Windows", "120.0.2210.91")
    assert plan["source"] == "msrc"
    assert plan["kbs"] == ["5087538"]
    assert sources["order"] == ["msrc"]       # NVD nemmeno interrogata


def test_microsoft_product_falls_through_to_nvd_when_msrc_has_nothing(sources):
    sources["plans"]["nvd"] = {"supported": True, "fix_version": "14.40.0"}
    plan = cve.compute_fix_plan("Microsoft Visual C++ Redistributable",
                                "Windows", "14.36.32532")
    assert sources["order"] == ["msrc", "nvd"]
    assert plan["source"] == "nvd"


def test_msrc_is_not_consulted_for_packaged_ecosystems(sources):
    """Un 'dotnet' pacchettizzato su Debian lo cura Debian, non Microsoft."""
    sources["plans"]["osv"] = {"supported": True, "fix_version": "8.0.1"}
    cve.compute_fix_plan("dotnet-runtime", "Debian", "6.0")
    assert "msrc" not in sources["order"]


def test_osv_transient_failure_is_not_masked_by_another_source(sources):
    """Un guasto di rete non deve diventare silenziosamente 'nessun dato'."""
    sources["plans"]["osv"] = {"supported": True, "error": "connection reset"}
    plan = cve.compute_fix_plan("openssl", "Debian", "1.0.1f")
    assert plan["error"] == "connection reset"
    assert plan["source"] == "osv"
    assert "nvd" not in sources["order"]


def test_no_source_indexes_the_package(sources):
    plan = cve.compute_fix_plan("Some Vendor Tool", "Windows", "1.0")
    assert plan["supported"] is False
    assert plan["error"] is None
    assert sources["order"] == ["nvd"]
    assert "NVD" in plan["detail"]


def test_result_always_declares_its_provenance(sources):
    sources["plans"]["nvd"] = {"supported": True, "fix_version": "2.0"}
    plan = cve.compute_fix_plan("Thing", "Windows", "1.0")
    assert plan["source"] and plan["source_label"]
    assert plan["sources_tried"] == ["nvd"]


def test_endpoint_exposes_source_over_http(monkeypatch, sources, role_clients):
    """Il percorso completo: e' quello che la pagina Security Posture consuma."""
    sources["plans"]["nvd"] = {"supported": True, "fix_version": "8.9.6.4"}
    r = role_clients["admin"].get(
        "/api/posture/fixplan?package=Notepad%2B%2B&ecosystem=Windows&version=7.8.1")
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "nvd"
    assert body["source_label"] == "NVD (NIST)"
    assert body["fix_version"] == "8.9.6.4"

"""
Fonti NVD e MSRC.

NVD copre il software desktop Windows che OSV non indicizza; MSRC copre i soli
prodotti Microsoft ma e' l'unica a pubblicare i numeri KB.

Il rischio dominante qui non e' il falso positivo, e' il FALSO NEGATIVO: una
riga che sembra pulita perche' la query e' stata costruita male. Diversi test
sotto esistono solo per quello.

Rete mockata: nessun test dipende dalla disponibilita' dei servizi.
"""

import pytest

import msrc
import nvd


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


@pytest.fixture(autouse=True)
def _clean_caches():
    nvd.clear_cache()
    msrc.clear_cache()
    yield
    nvd.clear_cache()
    msrc.clear_cache()


# =========================================================================
# NVD
# =========================================================================

def _cpe_entry(vendor, product, version="1.0"):
    return {"cpe": {"cpeName": f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"}}


def _cve_entry(cid, product, vendor="acme", end_excluding=None,
               end_including=None, severity="HIGH"):
    match = {"criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"}
    if end_excluding:
        match["versionEndExcluding"] = end_excluding
    if end_including:
        match["versionEndIncluding"] = end_including
    return {"cve": {
        "id": cid,
        "configurations": [{"nodes": [{"cpeMatch": [match]}]}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": severity}}]},
    }}


def _nvd(monkeypatch, cpe_payload, cve_payload):
    """Mocka le due chiamate NVD e registra i parametri ricevuti."""
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append({"url": url, "params": params or {}, "headers": headers or {}})
        if "cpes" in url:
            return cpe_payload
        return cve_payload

    monkeypatch.setattr(nvd.requests, "get", fake_get)
    return calls


def test_vendor_stays_wildcard_to_avoid_a_false_negative(monkeypatch):
    """
    Notepad++ convive a dizionario sotto piu' vendor e le CVE sono attaccate
    solo ad alcuni: fissare il vendor sbagliato darebbe zero risultati su un
    prodotto che ne ha tredici — una riga apparentemente pulita.
    """
    cpe = FakeResponse(200, {"products": [
        _cpe_entry("don_ho", "notepad\\+\\+"),
        _cpe_entry("notepad-plus-plus", "notepad\\+\\+"),
    ]})
    cves = FakeResponse(200, {"vulnerabilities": [
        _cve_entry("CVE-1", "notepad\\+\\+", vendor="notepad-plus-plus",
                   end_excluding="8.9.6.4")]})
    calls = _nvd(monkeypatch, cpe, cves)
    plan = nvd.fix_plan("Notepad++", "7.8.1")
    query = calls[-1]["params"]["virtualMatchString"]
    assert query.split(":")[3] == "*"          # vendor jolly
    assert plan["fix_version"] == "8.9.6.4"
    assert plan["vendors"] == ["notepad-plus-plus"]


def test_exact_product_name_wins_over_a_derivative(monkeypatch):
    """Una ricerca per parola chiave restituisce anche plugin e derivati."""
    cpe = FakeResponse(200, {"products": [
        _cpe_entry("x", "notepad\\+\\+_plugin", "1"),
        _cpe_entry("x", "notepad\\+\\+_plugin", "2"),
        _cpe_entry("y", "notepad\\+\\+", "3"),
    ]})
    _nvd(monkeypatch, cpe, FakeResponse(200, {"vulnerabilities": []}))
    assert nvd.resolve_cpe("notepad++")[0] == "notepad\\+\\+"


def test_version_range_produces_the_fix_version(monkeypatch):
    cpe = FakeResponse(200, {"products": [_cpe_entry("7-zip", "7-zip")]})
    cves = FakeResponse(200, {"vulnerabilities": [
        _cve_entry("CVE-1", "7-zip", vendor="7-zip", end_excluding="22.01"),
        _cve_entry("CVE-2", "7-zip", vendor="7-zip", end_excluding="24.07"),
    ]})
    _nvd(monkeypatch, cpe, cves)
    plan = nvd.fix_plan("7-Zip", "19.00")
    assert plan["fix_version"] == "24.07"
    assert plan["unfixed"] == 0


def test_last_affected_version_is_not_sold_as_a_safe_version(monkeypatch):
    """
    versionEndIncluding dice "questa e' ancora vulnerabile". Proporla come fix
    manderebbe l'operatore su una versione bucata.
    """
    cpe = FakeResponse(200, {"products": [_cpe_entry("acme", "thing")]})
    cves = FakeResponse(200, {"vulnerabilities": [
        _cve_entry("CVE-1", "thing", end_excluding="2.0"),
        _cve_entry("CVE-2", "thing", end_including="3.5"),
    ]})
    _nvd(monkeypatch, cpe, cves)
    plan = nvd.fix_plan("thing", "1.0")
    assert plan["fix_version"] == "2.0"
    assert plan["fix_after"] == "3.5"     # 2.0 NON basta, e va detto
    assert plan["unfixed"] == 1


def test_fix_after_is_absent_when_the_computed_fix_already_covers_it(monkeypatch):
    cpe = FakeResponse(200, {"products": [_cpe_entry("acme", "thing")]})
    cves = FakeResponse(200, {"vulnerabilities": [
        _cve_entry("CVE-1", "thing", end_excluding="9.0"),
        _cve_entry("CVE-2", "thing", end_including="3.5"),
    ]})
    _nvd(monkeypatch, cpe, cves)
    assert nvd.fix_plan("thing", "1.0")["fix_after"] is None


def test_unknown_product_is_unsupported_not_an_error(monkeypatch):
    _nvd(monkeypatch, FakeResponse(200, {"products": []}),
         FakeResponse(200, {"vulnerabilities": []}))
    plan = nvd.fix_plan("Totally Unknown Tool", "1.0")
    assert plan["supported"] is False
    assert plan["error"] is None


def test_rate_limit_is_a_retryable_error_with_a_usable_message(monkeypatch):
    _nvd(monkeypatch, FakeResponse(403, {}), FakeResponse(403, {}))
    plan = nvd.fix_plan("anything", "1.0")
    assert plan["supported"] is True
    assert "rate limit" in plan["error"]
    assert "API key" in plan["error"]      # dice anche come uscirne


def test_api_key_is_sent_when_configured(monkeypatch):
    monkeypatch.setattr(nvd, "_cfg", lambda: {
        "url": "u", "cpe_url": "cpes", "api_key": "secret-key",
        "timeout": 5, "cache_ttl_hours": 1})
    calls = _nvd(monkeypatch, FakeResponse(200, {"products": [_cpe_entry("a", "b")]}),
                 FakeResponse(200, {"vulnerabilities": []}))
    nvd.fix_plan("b", "1.0")
    assert calls[0]["headers"]["apiKey"] == "secret-key"


def test_cpe_lookup_is_cached_across_calls(monkeypatch):
    calls = _nvd(monkeypatch, FakeResponse(200, {"products": [_cpe_entry("a", "b")]}),
                 FakeResponse(200, {"vulnerabilities": []}))
    nvd.fix_plan("b", "1.0")
    nvd.fix_plan("b", "1.0")
    assert sum(1 for c in calls if "cpes" in c["url"]) == 1


def test_other_products_in_the_response_are_ignored(monkeypatch):
    cpe = FakeResponse(200, {"products": [_cpe_entry("acme", "thing")]})
    cves = FakeResponse(200, {"vulnerabilities": [
        _cve_entry("CVE-1", "thing", end_excluding="2.0"),
        _cve_entry("CVE-2", "something_else", end_excluding="99.0"),
    ]})
    _nvd(monkeypatch, cpe, cves)
    assert nvd.fix_plan("thing", "1.0")["fix_version"] == "2.0"


# =========================================================================
# MSRC
# =========================================================================

def _cvrf(products, vulns):
    return {"ProductTree": {"FullProductName": products}, "Vulnerability": vulns}


def _msrc(monkeypatch, doc):
    def fake_get(url, headers=None, timeout=None):
        if url.endswith("/updates"):
            return FakeResponse(200, {"value": [
                {"ID": "2026-Jun", "CvrfUrl": "https://msrc/doc"}]})
        return FakeResponse(200, doc)

    monkeypatch.setattr(msrc.requests, "get", fake_get)


DOC = _cvrf(
    products=[
        {"ProductID": "1", "Value": "Windows 11 Version 24H2"},
        {"ProductID": "2", "Value": "Microsoft Edge (Chromium-based)"},
        {"ProductID": "3", "Value": "Copilot Chat (Microsoft Edge)"},
    ],
    vulns=[
        {"CVE": "CVE-2026-1",
         "Threats": [{"Type": 3, "Description": {"Value": "Critical"}}],
         "Remediations": [{"Description": {"Value": "5087538"},
                           "FixedBuild": "10.0.26200.8655", "ProductID": ["1"]}]},
        {"CVE": "CVE-2026-2",
         "Threats": [{"Type": 3, "Description": {"Value": "Important"}}],
         "Remediations": [{"Description": {"Value": "Release Notes"},
                           "FixedBuild": "148.0.3967.97", "ProductID": ["2"]}]},
        {"CVE": "CVE-2026-3",
         "Remediations": [{"Description": {"Value": "Release Notes"},
                           "FixedBuild": "1.0.0", "ProductID": ["3"]}]},
    ])


def test_windows_result_carries_the_kb_to_install(monkeypatch):
    """Su Windows la remediation e' la KB, non solo il numero di build."""
    _msrc(monkeypatch, DOC)
    plan = msrc.fix_plan("Windows 11", "10.0.26200.1000")
    assert plan["supported"] is True
    assert plan["fix_version"] == "10.0.26200.8655"
    assert plan["kbs"] == ["5087538"]
    assert plan["cves"][0]["severity"] == "CRITICAL"


def test_product_match_is_by_prefix_not_containment(monkeypatch):
    """
    'Microsoft Edge' non deve catturare 'Copilot Chat (Microsoft Edge)':
    e' un altro prodotto con un altro ciclo di patch.
    """
    _msrc(monkeypatch, DOC)
    ids = [c["id"] for c in msrc.fix_plan("Microsoft Edge", "120.0.0.0")["cves"]]
    assert ids == ["CVE-2026-2"]


def test_already_patched_cves_are_excluded(monkeypatch):
    """Una build gia' installata non e' lavoro da fare."""
    _msrc(monkeypatch, DOC)
    assert msrc.fix_plan("Windows 11", "10.0.26200.9999")["cves"] == []


def test_unknown_product_is_unsupported(monkeypatch):
    _msrc(monkeypatch, DOC)
    plan = msrc.fix_plan("Adobe Acrobat Reader DC", "2019.012")
    assert plan["supported"] is False
    assert plan["error"] is None


def test_index_reports_the_window_it_covers(monkeypatch):
    """La finestra e' mensile: il report deve dire cosa ha guardato."""
    _msrc(monkeypatch, DOC)
    assert msrc.fix_plan("Windows 11", None)["window"] == "2026-Jun"


def test_index_is_cached(monkeypatch):
    calls = []

    def fake_get(url, headers=None, timeout=None):
        calls.append(url)
        if url.endswith("/updates"):
            return FakeResponse(200, {"value": [
                {"ID": "2026-Jun", "CvrfUrl": "https://msrc/doc"}]})
        return FakeResponse(200, DOC)

    monkeypatch.setattr(msrc.requests, "get", fake_get)
    msrc.fix_plan("Windows 11", None)
    msrc.fix_plan("Microsoft Edge", None)
    assert calls.count("https://msrc/doc") == 1


def test_unreachable_service_is_an_error_not_an_empty_result(monkeypatch):
    def boom(url, headers=None, timeout=None):
        raise RuntimeError("dns failure")

    monkeypatch.setattr(msrc.requests, "get", boom)
    plan = msrc.fix_plan("Windows 11", None)
    assert plan["error"] and "dns failure" in plan["error"]


@pytest.mark.parametrize("name,expected", [
    ("Microsoft Edge", True),
    ("Windows 11", True),
    ("Microsoft Visual C++ Redistributable", True),
    ("Notepad++", False),
    ("PuTTY", False),
    ("VLC media player", False),
])
def test_microsoft_product_detection(name, expected):
    assert msrc.is_microsoft(name) is expected

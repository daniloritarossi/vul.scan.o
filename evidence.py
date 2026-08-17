"""
evidence.py
-----------
Report di evidenza per audit esterno: un documento firmato che mette insieme,
in un unico file consegnabile, le tre cose che un auditor chiede.

1) I NUMERI      — quante vulnerabilita' erano aperte a una certa data, quante
                   ne restavano a una data successiva, quante ne sono state
                   risolte nel mezzo (da findings.reconstruct_as_of).
2) LA PROVA      — l'esito della verifica delle catene hash (ledger scansioni,
                   registro eventi dei finding, run di postura) allo stesso
                   istante in cui i numeri sono stati estratti. Numeri e prova
                   di integrita' viaggiano insieme: un report che dice "12
                   aperte" senza dire se il registro e' intatto non prova nulla.
3) LA FIRMA      — HMAC-SHA256 sul contenuto canonicalizzato del report, con il
                   segreto dell'istanza. Chi riceve il file puo' farselo
                   riverificare dall'applicazione (POST /api/audit/evidence/verify)
                   e scoprire se una singola cifra e' stata ritoccata dopo
                   l'export.

Formati: JSON (macchina), CSV (foglio di calcolo), HTML stampabile (-> PDF dal
browser). Nessuna dipendenza aggiuntiva: generare PDF richiederebbe una libreria
esterna, e la stampa del browser produce lo stesso documento.

Il modulo e' puro: riceve dati gia' estratti, non tocca DB ne' rete.
"""

import csv
import hashlib
import hmac
import io
import json
from datetime import datetime, timezone
from html import escape

REPORT_VERSION = "1"
SIGNATURE_ALGO = "HMAC-SHA256"

# Chiavi che NON entrano nel calcolo della firma (le contiene, non le copre).
_UNSIGNED_KEYS = ("integrity",)


def _canonical(report: dict) -> str:
    """
    Serializzazione deterministica del report ai fini di hash e firma.
    Ordinamento delle chiavi e separatori fissi: due esecuzioni sugli stessi
    dati producono lo stesso byte-stream, su qualunque macchina.
    """
    body = {k: v for k, v in report.items() if k not in _UNSIGNED_KEYS}
    return json.dumps(body, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), default=str)


def build_report(state: dict, before: dict | None, delta: dict | None,
                 chains: dict, actor: str, scope: str,
                 generated_at: datetime | None = None) -> dict:
    """
    Compone il report a partire dagli stati point-in-time gia' ricostruiti.

    - state/before: output di findings.reconstruct_as_of (before opzionale)
    - delta:        output di findings.compare_states (opzionale)
    - chains:       {'scans': {...}, 'finding_events': {...}, 'posture': {...}},
                    ogni valore e' l'output di un verify_* (None se DB muto)
    - actor/scope:  chi ha generato il report e su quale perimetro
    """
    now = generated_at or datetime.now(timezone.utc)
    report = {
        "report_version": REPORT_VERSION,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "generated_by": actor,
        "scope": scope,
        "period": {"from": (before or {}).get("as_of"), "to": state.get("as_of")},
        "counts": {
            "at_from": _counts(before),
            "at_to": _counts(state),
        },
        "delta": _delta(delta),
        "integrity_checks": {
            name: _chain(result) for name, result in (chains or {}).items()
        },
    }
    # Verdetto complessivo sulle sole catene effettivamente verificate. Se non
    # se n'e' potuta verificare NESSUNA il verdetto e' negativo: un report che
    # dichiara integrita' senza aver controllato nulla e' peggio di nessun
    # report.
    # Una catena VUOTA non e' una catena integra: non e' stato verificato
    # nulla. Contarla fra le prove faceva stampare "all chains intact" a un
    # report che non aveva controllato una sola riga — lo stesso errore, di
    # nuovo, sul lato "checked nothing".
    checked = [c for c in report["integrity_checks"].values() if c["available"]]
    with_entries = [c for c in checked if (c.get("total") or 0) > 0]
    report["integrity_ok"] = bool(with_entries) and all(c["ok"] for c in with_entries)
    # 'integrity_ok' da solo non distingue una catena ROTTA da una catena
    # semplicemente non dimostrabile su tutte le righe. Sono due cose diverse
    # per chi riceve il documento: la prima e' un incidente, la seconda un
    # limite di copertura da dichiarare.
    report["integrity_verdict"] = (
        "tampered" if any(c.get("tamper_free") is False for c in checked)
        # Nessuna catena con righe = nessuna prova, non "tutto integro".
        else "unknown" if not with_entries
        else "intact" if all(c["ok"] for c in with_entries)
        else "partial")
    # Quante catene reggono davvero il verdetto, e quante sono vuote: un
    # lettore deve poterlo vedere senza contare le righe della tabella.
    report["chains_with_entries"] = len(with_entries)
    report["chains_empty"] = len(checked) - len(with_entries)
    report["coverage"] = {
        name: c.get("coverage")
        for name, c in report["integrity_checks"].items() if c["available"]
    }
    report["protected_coverage"] = {
        name: c.get("protected_coverage")
        for name, c in report["integrity_checks"].items() if c["available"]
    }
    return report


def _counts(state: dict | None) -> dict | None:
    """Estratto dei conteggi di uno stato point-in-time (None se assente)."""
    if not state:
        return None
    return {
        "as_of": state.get("as_of"),
        "total": state.get("total"),
        "unresolved": state.get("unresolved"),
        "by_status": state.get("by_status"),
        "by_severity": state.get("by_severity"),
        "proven": state.get("proven"),
        "estimated": state.get("estimated"),
    }


def _delta(delta: dict | None) -> dict | None:
    if not delta:
        return None
    return {k: v for k, v in delta.items() if k != "fingerprints"}


def _chain(result: dict | None) -> dict:
    """
    Normalizza l'esito di una verifica di catena. 'available' distingue il DB
    irraggiungibile (verifica non eseguita) da una catena effettivamente rotta:
    confonderli renderebbe il report inutile proprio quando serve.

    Il report porta la COPERTURA, non solo l'esito: un "ok" calcolato su una
    frazione delle righe non e' una prova di integrita', e chi legge il
    documento deve poterlo vedere senza aprire il database.
    """
    if result is None:
        return {"available": False, "ok": False, "verdict": "unknown",
                "detail": "DB unreachable"}
    anchor = result.get("anchor") or {}
    return {
        "available": True,
        "ok": bool(result.get("ok")),
        "verdict": result.get("verdict"),
        "tamper_free": result.get("tamper_free"),
        "total": result.get("total"),
        "verified": result.get("verified"),
        "unsigned": result.get("unsigned"),
        "anchored": result.get("anchored"),
        "unprotected": result.get("unprotected"),
        # Prova e protezione sono due cose diverse: la prima dice "verificato",
        # la seconda "da qui in poi una modifica si vedrebbe".
        "coverage": result.get("coverage"),
        "protected_coverage": result.get("protected_coverage"),
        "anchored_at": anchor.get("at") if anchor.get("present") else None,
        # Perche' la catena e' considerata manomessa, e se la coda e' testimoniata:
        # senza testimone, cancellare le ultime righe non sarebbe rilevabile.
        "tamper_reasons": result.get("tamper_reasons") or [],
        "tail_witnessed": bool((result.get("head") or {}).get("present")),
        "broken": result.get("broken") or [],
        "finals_verified": result.get("finals_verified"),
        "finals_pending": result.get("finals_pending"),
        "finals_broken": result.get("finals_broken") or [],
    }


def sign(report: dict, key: bytes) -> dict:
    """Aggiunge il blocco 'integrity' (hash + firma HMAC). Muta e ritorna."""
    canon = _canonical(report)
    report["integrity"] = {
        "algo": SIGNATURE_ALGO,
        "report_hash": hashlib.sha256(canon.encode("utf-8")).hexdigest(),
        "signature": hmac.new(key, canon.encode("utf-8"), hashlib.sha256).hexdigest(),
    }
    return report


def verify(report: dict, key: bytes) -> dict:
    """
    Riverifica un report esportato. Ritorna {ok, reason}.

    Confronto a tempo costante: la firma e' un segreto, e un confronto ingenuo
    perderebbe informazione utile a forgiarne una.
    """
    block = (report or {}).get("integrity") or {}
    if not block.get("signature"):
        return {"ok": False, "reason": "Report senza firma"}
    if block.get("algo") != SIGNATURE_ALGO:
        return {"ok": False, "reason": f"Algoritmo non supportato: {block.get('algo')}"}
    canon = _canonical(report)
    expected = hmac.new(key, canon.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(block["signature"]), expected):
        return {"ok": False, "reason": "Firma non valida: il report e' stato modificato "
                                       "dopo l'export, oppure proviene da un'altra istanza"}
    digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()
    if block.get("report_hash") and not hmac.compare_digest(str(block["report_hash"]), digest):
        return {"ok": False, "reason": "Hash del report incoerente con il contenuto"}
    return {"ok": True, "reason": "Firma valida: il report e' quello emesso dall'istanza"}


# --------------------------------------------------------------------------
# RESE (CSV / HTML)
# --------------------------------------------------------------------------

def _rows(report: dict) -> list:
    """Report appiattito in righe (section, key, value) — base di CSV e HTML."""
    out = [
        ("report", "report_version", report.get("report_version")),
        ("report", "generated_at", report.get("generated_at")),
        ("report", "generated_by", report.get("generated_by")),
        ("report", "scope", report.get("scope")),
        ("report", "period_from", (report.get("period") or {}).get("from")),
        ("report", "period_to", (report.get("period") or {}).get("to")),
    ]
    for label, counts in (("counts_at_from", (report.get("counts") or {}).get("at_from")),
                          ("counts_at_to", (report.get("counts") or {}).get("at_to"))):
        if not counts:
            continue
        out.append((label, "as_of", counts.get("as_of")))
        out.append((label, "total", counts.get("total")))
        out.append((label, "unresolved", counts.get("unresolved")))
        for k, v in (counts.get("by_status") or {}).items():
            out.append((label, f"status_{k}", v))
        for k, v in (counts.get("by_severity") or {}).items():
            out.append((label, f"unresolved_severity_{k}", v))
        out.append((label, "proven", counts.get("proven")))
        out.append((label, "estimated", counts.get("estimated")))
    for k, v in (report.get("delta") or {}).items():
        out.append(("delta", k, v))
    for name, chain in (report.get("integrity_checks") or {}).items():
        out.append(("integrity_checks", f"{name}_available", chain.get("available")))
        out.append(("integrity_checks", f"{name}_verdict", chain.get("verdict")))
        out.append(("integrity_checks", f"{name}_ok", chain.get("ok")))
        out.append(("integrity_checks", f"{name}_total", chain.get("total")))
        out.append(("integrity_checks", f"{name}_verified", chain.get("verified")))
        # Le righe non dimostrabili sono parte del risultato quanto le rotture:
        # un conteggio "verificato" senza il denominatore non dice niente.
        out.append(("integrity_checks", f"{name}_anchored", chain.get("anchored")))
        out.append(("integrity_checks", f"{name}_unprotected", chain.get("unprotected")))
        out.append(("integrity_checks", f"{name}_coverage_proven", chain.get("coverage")))
        out.append(("integrity_checks", f"{name}_coverage_protected",
                    chain.get("protected_coverage")))
        out.append(("integrity_checks", f"{name}_anchored_at", chain.get("anchored_at")))
        out.append(("integrity_checks", f"{name}_tail_witnessed", chain.get("tail_witnessed")))
        out.append(("integrity_checks", f"{name}_tamper_reasons",
                    ";".join(chain.get("tamper_reasons") or [])))
        out.append(("integrity_checks", f"{name}_broken",
                    ";".join(str(i) for i in (chain.get("broken") or []))))
        out.append(("integrity_checks", f"{name}_finals_broken",
                    ";".join(str(i) for i in (chain.get("finals_broken") or []))))
    out.append(("integrity", "overall_verdict", report.get("integrity_verdict")))
    out.append(("integrity", "chains_with_entries", report.get("chains_with_entries")))
    out.append(("integrity", "chains_empty", report.get("chains_empty")))
    out.append(("integrity", "overall_ok", report.get("integrity_ok")))
    block = report.get("integrity") or {}
    out.append(("integrity", "algo", block.get("algo")))
    out.append(("integrity", "report_hash", block.get("report_hash")))
    out.append(("integrity", "signature", block.get("signature")))
    return out


def to_csv(report: dict) -> str:
    """Report in CSV (section,key,value) — apribile in un foglio di calcolo."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["section", "key", "value"])
    for section, key, value in _rows(report):
        w.writerow([section, key, "" if value is None else value])
    return buf.getvalue()


_HTML_CSS = """
:root { color-scheme: light; }
body { font: 14px/1.5 ui-sans-serif, system-ui, sans-serif; color: #111827;
       background: #fff; margin: 0; padding: 32px; }
h1 { font-size: 20px; margin: 0 0 4px; letter-spacing: .02em; }
h2 { font-size: 14px; text-transform: uppercase; letter-spacing: .08em;
     color: #6b7280; margin: 28px 0 8px; }
.sub { color: #6b7280; margin: 0 0 24px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 8px; }
th, td { border: 1px solid #e5e7eb; padding: 6px 10px; text-align: left;
         vertical-align: top; }
th { background: #f9fafb; font-weight: 600; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
.big { font-size: 26px; font-weight: 700; font-variant-numeric: tabular-nums; }
.ok { color: #047857; font-weight: 600; }
.bad { color: #b91c1c; font-weight: 600; }
.warn { color: #b45309; font-weight: 600; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        font-size: 11px; word-break: break-all; }
.note { color: #6b7280; font-size: 12px; margin-top: 6px; }
@media print { body { padding: 0; } h2 { break-after: avoid; }
               table { break-inside: avoid; } }
"""


def _esc(v) -> str:
    return escape("" if v is None else str(v))


def to_html(report: dict) -> str:
    """
    Report in HTML stampabile: la via al PDF senza aggiungere dipendenze
    (Ctrl+P -> Salva come PDF produce il documento consegnabile).
    """
    counts_to = (report.get("counts") or {}).get("at_to") or {}
    counts_from = (report.get("counts") or {}).get("at_from") or {}
    delta = report.get("delta") or {}
    block = report.get("integrity") or {}

    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<title>VUL.SCAN.O — Audit evidence report</title>",
        f"<style>{_HTML_CSS}</style></head><body>",
        "<h1>Audit evidence report</h1>",
        f"<p class='sub'>Generated {_esc(report.get('generated_at'))} "
        f"by {_esc(report.get('generated_by'))} &middot; scope: "
        f"{_esc(report.get('scope'))} &middot; format v{_esc(report.get('report_version'))}</p>",
    ]

    if counts_from:
        parts += [
            "<h2>Remediation over the period</h2>",
            "<table><thead><tr><th>Measure</th><th>Value</th></tr></thead><tbody>",
            f"<tr><td>Unresolved at {_esc(counts_from.get('as_of'))}</td>"
            f"<td class='num big'>{_esc(delta.get('unresolved_before'))}</td></tr>",
            f"<tr><td>Unresolved at {_esc(counts_to.get('as_of'))}</td>"
            f"<td class='num big'>{_esc(delta.get('unresolved_after'))}</td></tr>",
            f"<tr><td>Resolved (fixed) in the period</td>"
            f"<td class='num big'>{_esc(delta.get('resolved'))}</td></tr>",
            f"<tr><td>Risk formally accepted</td>"
            f"<td class='num'>{_esc(delta.get('accepted'))}</td></tr>",
            f"<tr><td>Newly opened</td><td class='num'>{_esc(delta.get('new'))}</td></tr>",
            f"<tr><td>Still open at period end</td>"
            f"<td class='num'>{_esc(delta.get('still_open'))}</td></tr>",
            f"<tr><td>Vanished (data removed — investigate)</td>"
            f"<td class='num'>{_esc(delta.get('vanished'))}</td></tr>",
            "</tbody></table>",
            "<p class='note'>Accepted risk is reported separately and is never "
            "counted as resolved.</p>",
        ]

    parts.append("<h2>State by date</h2><table><thead><tr><th>Measure</th>")
    cols = [c for c in (counts_from, counts_to) if c]
    for c in cols:
        parts.append(f"<th>{_esc(c.get('as_of'))}</th>")
    parts.append("</tr></thead><tbody>")
    rows = [("Findings on record", "total"), ("Unresolved (open + triaged)", "unresolved")]
    for label, key in rows:
        parts.append(f"<tr><td>{label}</td>")
        parts += [f"<td class='num'>{_esc(c.get(key))}</td>" for c in cols]
        parts.append("</tr>")
    for status in ("open", "triaged", "accepted", "fixed"):
        parts.append(f"<tr><td>Status: {status}</td>")
        parts += [f"<td class='num'>{_esc((c.get('by_status') or {}).get(status))}</td>"
                  for c in cols]
        parts.append("</tr>")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        parts.append(f"<tr><td>Unresolved, severity {sev}</td>")
        parts += [f"<td class='num'>{_esc((c.get('by_severity') or {}).get(sev))}</td>"
                  for c in cols]
        parts.append("</tr>")
    for label, key in (("Proven by ledger events", "proven"),
                       ("Estimated (pre-ledger)", "estimated")):
        parts.append(f"<tr><td>{label}</td>")
        parts += [f"<td class='num'>{_esc(c.get(key))}</td>" for c in cols]
        parts.append("</tr>")
    parts.append("</tbody></table>")
    parts.append("<p class='note'>“Estimated” findings predate the append-only "
                 "ledger: their state is inferred from first/last-change "
                 "timestamps, not proved by recorded events.</p>")

    parts += ["<h2>Integrity verification</h2>",
              "<table><thead><tr><th>Chain</th><th>Result</th><th>Verified</th>"
              "<th>Proven</th><th>Anchored</th><th>Protected</th>"
              "<th>Unprotected</th><th>Tail witnessed</th>"
              "<th>Broken entries</th></tr></thead><tbody>"]
    for name, chain in (report.get("integrity_checks") or {}).items():
        # Tre esiti distinti, non due: "non dimostrabile" non e' "manomesso",
        # e nessuno dei due e' "integro".
        if not chain.get("available"):
            verdict = "<span class='bad'>NOT CHECKED</span>"
        elif chain.get("verdict") == "tampered":
            verdict = "<span class='bad'>TAMPERED</span>"
        elif chain.get("verdict") == "partial":
            verdict = "<span class='warn'>PARTIAL COVERAGE</span>"
        elif chain.get("verdict") == "empty":
            verdict = "<span class='note'>EMPTY</span>"
        else:
            verdict = "<span class='ok'>INTACT</span>"
        broken = (chain.get("broken") or []) + (chain.get("finals_broken") or [])
        cov = chain.get("coverage")
        cov_txt = "—" if cov is None else f"{cov * 100:.1f}%"
        prot = chain.get("protected_coverage")
        prot_txt = "—" if prot is None else f"{prot * 100:.1f}%"
        # Copertura DIMOSTRATA a zero: va detto a parole, non lasciato dedurre
        # da una percentuale in mezzo ad altre.
        if cov == 0:
            cov_txt = f"<span class='warn'>{cov_txt} — nothing proven</span>"
        anchored_at = chain.get("anchored_at")
        unprot = chain.get("unprotected")
        unprot_txt = "—" if unprot is None else str(unprot)
        if anchored_at:
            unprot_txt += f" <span class='note'>(anchored {_esc(anchored_at[:10])})</span>"
        parts.append(
            f"<tr><td>{_esc(name)}</td><td>{verdict}</td>"
            f"<td class='num'>{_esc(chain.get('verified'))} / {_esc(chain.get('total'))}</td>"
            f"<td class='num'>{cov_txt}</td>"
            f"<td class='num'>{_esc(chain.get('anchored'))}</td>"
            f"<td class='num'>{prot_txt}</td>"
            f"<td class='num'>{unprot_txt}</td>"
            # Se la coda non e' testimoniata, cancellare le ultime righe non
            # sarebbe rilevabile: e' un limite che deve stare NEL documento.
            f"<td>{'yes' if chain.get('tail_witnessed') else "<span class='warn'>no</span>"}</td>"
            f"<td class='mono'>{_esc(', '.join(str(i) for i in broken) or '—')}</td></tr>")
    parts.append("</tbody></table>")
    overall = report.get("integrity_verdict")
    empty_n = report.get("chains_empty") or 0
    # Le catene vuote non dimostrano nulla: se ce ne sono, il titolo lo dice
    # invece di lasciar intendere che il controllo le abbia coperte.
    empty_note = (f" {empty_n} chain(s) contained no entries and prove nothing."
                  if empty_n else "")
    if overall == "intact":
        parts.append("<p class='ok'>Overall integrity: every chain with entries "
                     f"is intact, with full proven coverage.{empty_note}</p>")
    elif overall == "tampered":
        parts.append("<p class='bad'>Overall integrity: VERIFICATION FAILED — "
                     "do not submit this report before investigating.</p>")
    elif overall == "partial":
        # Il punto dell'intera modifica: un report non deve MAI far passare una
        # copertura parziale per integrita' dimostrata.
        parts.append(
            "<p class='warn'>Overall integrity: <b>partial</b>. No tampering was "
            "detected, but part of the ledger cannot be proven intact — rows "
            "written before the hash chains existed, or values never sealed. "
            "<b>Proven</b> is the share actually covered by a verified hash; "
            "<b>protected</b> adds the rows that are merely anchored, i.e. any "
            "change to them from the anchor date onward would be detected, "
            "which is not the same as proving what they contained before it."
            f"{empty_note}</p>")
    else:
        # 'unknown' copre due casi che vanno detti, non taciuti: nessuna catena
        # verificabile (DB muto) e nessuna catena con righe da verificare.
        parts.append("<p class='bad'>Overall integrity: <b>not proven</b> — no "
                     "chain with entries could be checked. This report makes no "
                     "claim about the integrity of the figures above.</p>")

    parts += ["<h2>Signature</h2>",
              "<table><tbody>",
              f"<tr><th>Algorithm</th><td class='mono'>{_esc(block.get('algo'))}</td></tr>",
              f"<tr><th>Report hash</th><td class='mono'>{_esc(block.get('report_hash'))}</td></tr>",
              f"<tr><th>Signature</th><td class='mono'>{_esc(block.get('signature'))}</td></tr>",
              "</tbody></table>",
              "<p class='note'>Re-verify by posting the JSON version of this "
              "report to <code>/api/audit/evidence/verify</code>. The signature "
              "covers every figure above; changing any one of them invalidates it.</p>",
              "</body></html>"]
    return "".join(parts)

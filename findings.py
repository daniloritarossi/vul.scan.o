"""
findings.py
-----------
Ciclo di vita UNIFICATO dei finding (capability ASPM: dedup + workflow + SLA).

Tutti i finding — postura interna (SCA) e report di scanner esterni ingeriti
via ingest.py — confluiscono nella tabella 'findings' con:

1) DEDUP per fingerprint
   Identita' stabile calcolata su (asset, pacchetto/regola, CVE primaria o
   titolo, location). La sorgente NON fa parte della chiave: lo stesso
   difetto riportato da Trivy e Grype e' UN solo finding. Ricomparire in una
   run successiva aggiorna last_seen/times_seen invece di duplicare.

2) STATI del workflow
   open -> triaged -> accepted | fixed  (transizioni libere via API).
   Un finding 'fixed' che riappare viene RIAPERTO automaticamente
   (status=open, reopened+1).

3) SLA per severita'
   Scadenza di remediation calcolata alla prima osservazione:
   critical 7g, high 30g, medium 90g, low 180g (configurabile, sezione 'sla'
   di config.json). 'breached' se oltre scadenza e non fixed/accepted.

Il modulo e' puro (nessun accesso a DB): prepara le righe, db.py le persiste.
"""

import hashlib
from datetime import datetime, timedelta, timezone

STATUSES = ("open", "triaged", "accepted", "fixed")

# Giorni di SLA per severita' (default; override da config.json sezione 'sla').
DEFAULT_SLA_DAYS = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180, "UNKNOWN": 90}

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _parse_ts(raw) -> datetime | None:
    """Parsa i timestamp ISO restituiti da PostgREST (vari formati di offset)."""
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def fingerprint(f: dict) -> str:
    """
    Identita' stabile del finding, indipendente dalla sorgente e dalla
    versione installata (l'upgrade parziale non crea un finding nuovo).

    Con CVE nota l'identita' e' (asset, pacchetto, CVE primaria): la location
    e' esclusa perche' ogni tool la descrive a modo suo (Trivy 'ubuntu 22.04',
    Grype il path) e romperebbe il dedup cross-tool dello stesso difetto.
    Senza CVE (es. SAST, template) la location distingue i finding.
    """
    cves = sorted(f.get("cve_ids") or [])
    key = "|".join([
        (f.get("asset_ip") or "").strip().lower(),
        (f.get("package") or "").strip().lower(),
        (cves[0] if cves else (f.get("title") or "").strip().lower()),
        ("" if cves else (f.get("location") or "").strip().lower()),
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def sla_days(severity: str, cfg_sla: dict | None = None) -> int:
    sev = (severity or "UNKNOWN").upper()
    table = {**DEFAULT_SLA_DAYS, **{k.upper(): int(v) for k, v in (cfg_sla or {}).items()}}
    return table.get(sev, table["UNKNOWN"])


def posture_findings(report: dict) -> list:
    """
    Converte il report di postura di UN asset (scan_asset_posture) nello schema
    normalizzato di ingest.py, cosi' da confluire nello stesso ciclo di vita.
    """
    ip = report.get("ip") or ""
    out = []
    for f in (report.get("findings") or []):
        pkg = f.get("package") or ""
        out.append({
            "source": "posture",
            "asset_ip": ip,
            "title": f"{pkg} {f.get('version') or ''} vulnerable "
                     f"({f.get('vuln_count') or 0} CVE)".strip(),
            "package": pkg,
            "version": f.get("version") or "",
            "ecosystem": f.get("ecosystem") or "",
            "location": f"pkg:{f.get('ecosystem') or 'os'}",
            "severity": (f.get("max_severity") or "UNKNOWN").upper(),
            "cve_ids": f.get("cve_ids") or [],
            "cwe_ids": [],
            "detail": f"Category: {f.get('category') or 'n/a'}",
        })
    return out


def merge_findings(normalized: list, existing_by_fp: dict,
                   cfg_sla: dict | None = None) -> tuple:
    """
    Fonde i finding normalizzati con quelli gia' presenti a DB.

    Ritorna (rows, stats):
      rows  -> righe pronte per l'upsert (on_conflict=fingerprint)
      stats -> {"new": n, "updated": n, "reopened": n}

    Regole:
      - nuovo fingerprint            -> status 'open', sla_due da severita'
      - fingerprint esistente        -> last_seen/now, times_seen+1; severita'
                                        alzata se il nuovo report e' peggiore
      - esistente con status 'fixed' -> RIAPERTO (open, reopened+1, nuova SLA)
    """
    now = _now()
    stats = {"new": 0, "updated": 0, "reopened": 0}
    merged: dict = {}   # fp -> row (dedup anche DENTRO lo stesso report)

    for f in normalized:
        fp = fingerprint(f)
        sev = (f.get("severity") or "UNKNOWN").upper()
        if fp in merged:
            # Stesso finding ripetuto nel report: tieni la severita' peggiore.
            row = merged[fp]
            if SEV_ORDER.index(sev) < SEV_ORDER.index(row["severity"]):
                row["severity"] = sev
            continue

        prev = existing_by_fp.get(fp)
        if prev is None:
            merged[fp] = {
                "fingerprint": fp,
                "source": f.get("source") or "",
                "asset_ip": f.get("asset_ip") or "",
                "title": f.get("title") or "",
                "package": f.get("package") or "",
                "version": f.get("version") or "",
                "ecosystem": f.get("ecosystem") or "",
                "location": f.get("location") or "",
                "severity": sev,
                "cve_ids": f.get("cve_ids") or [],
                "cwe_ids": f.get("cwe_ids") or [],
                "detail": f.get("detail") or "",
                "status": "open",
                "status_note": "",
                "status_changed_at": _iso(now),
                "first_seen": _iso(now),
                "last_seen": _iso(now),
                "times_seen": 1,
                "reopened": 0,
                "sla_due": _iso(now + timedelta(days=sla_days(sev, cfg_sla))),
            }
            stats["new"] += 1
            continue

        # Fingerprint gia' noto: aggiorna osservazione, preserva workflow.
        prev_sev = (prev.get("severity") or "UNKNOWN").upper()
        worst = sev if SEV_ORDER.index(sev) < SEV_ORDER.index(prev_sev) else prev_sev
        row = {
            "fingerprint": fp,
            "source": prev.get("source") or f.get("source") or "",
            "asset_ip": prev.get("asset_ip") or "",
            "title": f.get("title") or prev.get("title") or "",
            "package": prev.get("package") or "",
            "version": f.get("version") or prev.get("version") or "",
            "ecosystem": prev.get("ecosystem") or f.get("ecosystem") or "",
            "location": prev.get("location") or "",
            "severity": worst,
            "cve_ids": sorted(set((prev.get("cve_ids") or []) + (f.get("cve_ids") or []))),
            "cwe_ids": sorted(set((prev.get("cwe_ids") or []) + (f.get("cwe_ids") or []))),
            "detail": f.get("detail") or prev.get("detail") or "",
            "status": prev.get("status") or "open",
            "status_note": prev.get("status_note") or "",
            "status_changed_at": prev.get("status_changed_at") or _iso(now),
            "first_seen": prev.get("first_seen") or _iso(now),
            "last_seen": _iso(now),
            "times_seen": int(prev.get("times_seen") or 1) + 1,
            "reopened": int(prev.get("reopened") or 0),
            "sla_due": prev.get("sla_due") or _iso(now + timedelta(days=sla_days(worst, cfg_sla))),
        }
        # Sorgente diversa che conferma lo stesso difetto: traccia entrambe.
        new_src = f.get("source") or ""
        if new_src and new_src not in (row["source"] or "").split("+"):
            row["source"] = "+".join(filter(None, [row["source"], new_src]))
        if row["status"] == "fixed":
            row["status"] = "open"
            row["reopened"] += 1
            row["status_changed_at"] = _iso(now)
            row["status_note"] = "Reopened: reappeared in a new report"
            row["sla_due"] = _iso(now + timedelta(days=sla_days(worst, cfg_sla)))
            stats["reopened"] += 1
        else:
            stats["updated"] += 1
        merged[fp] = row

    return list(merged.values()), stats


# --------------------------------------------------------------------------
# REGISTRO EVENTI E RICOSTRUZIONE POINT-IN-TIME
#
# La tabella 'findings' e' aggiornata in place: lo stato di ieri non esiste
# piu'. Per rispondere a un auditor ("quante vulnerabilita' aperte al 31/03?
# quante risolte al 30/06?") ogni transizione viene appesa a 'finding_events'
# (db.log_finding_events) e lo stato a una data si ottiene per replay.
# --------------------------------------------------------------------------

# Stati che contano come vulnerabilita' ANCORA APERTA in un conteggio di audit.
# 'accepted' e' escluso: e' rischio accettato formalmente, non aperto; viene
# comunque riportato a parte, mai fuso con i 'fixed'.
UNRESOLVED = ("open", "triaged")


def lifecycle_events(rows: list, existing_by_fp: dict,
                     actor: dict | None = None) -> list:
    """
    Eventi di ciclo di vita impliciti in un merge (funzione pura).

    'rows' e' l'output di merge_findings, 'existing_by_fp' lo stesso dizionario
    passato al merge. Produce un evento per:
      - fingerprint mai visto  -> 'created'  (None -> open)
      - 'fixed' riapparso      -> 'reopened' (fixed -> open)
    Le semplici riosservazioni (last_seen/times_seen) NON generano eventi: non
    cambiano lo stato e gonfierebbero il registro senza valore probatorio.
    """
    out = []
    for row in rows:
        fp = row.get("fingerprint")
        prev = existing_by_fp.get(fp)
        if prev is None:
            event, from_status = "created", None
        elif (prev.get("status") or "open") == "fixed" and row.get("status") == "open":
            event, from_status = "reopened", "fixed"
        else:
            continue
        out.append({
            "event": event,
            "finding_id": (prev or {}).get("id"),
            "fingerprint": fp,
            "from_status": from_status,
            "to_status": row.get("status") or "open",
            "severity": row.get("severity"),
            "asset_ip": row.get("asset_ip"),
            "source": row.get("source"),
            "event_ts": row.get("status_changed_at") or _iso(_now()),
            "actor": actor or {},
            "note": row.get("status_note") or "",
        })
    return out


def parse_as_of(raw: str | None) -> datetime:
    """
    Normalizza il parametro data di un'interrogazione point-in-time.

    Una data nuda ('2026-03-31') significa FINE giornata: chi chiede "quante
    ne avevo il 31 marzo" intende a fine giornata, non a mezzanotte. None =
    adesso. Solleva ValueError su input non interpretabile.
    """
    if not raw:
        return _now()
    txt = str(raw).strip()
    if len(txt) == 10:
        txt += "T23:59:59+00:00"
    dt = _parse_ts(txt)
    if dt is None:
        raise ValueError(f"Data non valida: {raw}")
    return dt


def reconstruct_as_of(events: list, current: list, as_of: datetime) -> dict:
    """
    Stato dei finding a una data, ricostruito per replay del registro eventi.

    - events:  righe di finding_events (ordine di scrittura)
    - current: righe attuali di 'findings' (metadati: titolo, severita', asset)
    - as_of:   istante di riferimento

    Per ogni fingerprint si applicano in ordine gli eventi con event_ts <=
    as_of; lo stato e' il 'to_status' dell'ultimo. I finding SENZA eventi (nati
    prima dell'introduzione del registro) sono ricostruiti in modo approssimato
    da first_seen/status_changed_at e marcati basis='estimated': un auditor
    deve poter distinguere cio' che e' provato da cio' che e' stimato.

    Ritorna {as_of, total, by_status, by_severity, proven, estimated, findings}.
    """
    by_fp: dict = {}
    for e in events or []:
        ts = _parse_ts(e.get("event_ts"))
        if ts is None or ts > as_of:
            continue
        fp = e.get("fingerprint") or ""
        by_fp.setdefault(fp, []).append(e)

    meta = {r.get("fingerprint"): r for r in (current or [])}
    rows = []
    for fp, evs in by_fp.items():
        last = evs[-1]
        m = meta.get(fp, {})
        rows.append({
            "fingerprint": fp,
            "status": last.get("to_status") or "open",
            "severity": (last.get("severity") or m.get("severity") or "UNKNOWN").upper(),
            "asset_ip": last.get("asset_ip") or m.get("asset_ip") or "",
            "source": last.get("source") or m.get("source") or "",
            "title": m.get("title") or "",
            "basis": "event",
            "last_event": last.get("event"),
            "last_event_ts": last.get("event_ts"),
        })

    # Fallback per i finding non coperti dal registro.
    for r in (current or []):
        fp = r.get("fingerprint")
        if fp in by_fp:
            continue
        first_seen = _parse_ts(r.get("first_seen"))
        if first_seen is None or first_seen > as_of:
            continue                       # non esisteva ancora a quella data
        changed = _parse_ts(r.get("status_changed_at"))
        status = (r.get("status") or "open") if (changed and changed <= as_of) else "open"
        rows.append({
            "fingerprint": fp,
            "status": status,
            "severity": (r.get("severity") or "UNKNOWN").upper(),
            "asset_ip": r.get("asset_ip") or "",
            "source": r.get("source") or "",
            "title": r.get("title") or "",
            "basis": "estimated",
            "last_event": None,
            "last_event_ts": r.get("status_changed_at"),
        })

    by_status = {s: 0 for s in STATUSES}
    by_sev = {s: 0 for s in SEV_ORDER}
    proven = 0
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        if r["status"] in UNRESOLVED:
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        if r["basis"] == "event":
            proven += 1
    return {
        "as_of": _iso(as_of),
        "total": len(rows),
        "unresolved": sum(by_status.get(s, 0) for s in UNRESOLVED),
        "by_status": by_status,
        "by_severity": by_sev,
        "proven": proven,
        "estimated": len(rows) - proven,
        "findings": rows,
    }


def compare_states(before: dict, after: dict) -> dict:
    """
    Delta fra due stati point-in-time: la risposta letterale alla domanda di
    audit "a T0 ne avevo N, a T1 ne ho risolte K".

    - fixed:      aperta a T0 -> 'fixed' a T1        (risolta)
    - accepted:   aperta a T0 -> 'accepted' a T1     (rischio accettato)
    - vanished:   aperta a T0 -> assente a T1        (dato cancellato: anomalia)
    - new:        non aperta a T0 -> aperta a T1
    - still_open: aperta a entrambe le date
    """
    b = {r["fingerprint"]: r for r in before.get("findings", [])}
    a = {r["fingerprint"]: r for r in after.get("findings", [])}
    open_b = {fp for fp, r in b.items() if r["status"] in UNRESOLVED}
    open_a = {fp for fp, r in a.items() if r["status"] in UNRESOLVED}
    delta = {"fixed": [], "accepted": [], "vanished": [],
             "new": sorted(open_a - open_b), "still_open": sorted(open_a & open_b)}
    for fp in sorted(open_b - open_a):
        st = a.get(fp, {}).get("status")
        key = "fixed" if st == "fixed" else "accepted" if st == "accepted" else "vanished"
        delta[key].append(fp)
    return {
        "unresolved_before": len(open_b),
        "unresolved_after": len(open_a),
        "resolved": len(delta["fixed"]),
        "accepted": len(delta["accepted"]),
        "vanished": len(delta["vanished"]),
        "new": len(delta["new"]),
        "still_open": len(delta["still_open"]),
        "fingerprints": delta,
    }


def is_breached(row: dict, now: datetime | None = None) -> bool:
    """SLA violata: oltre scadenza e ancora aperta/triaged."""
    if (row.get("status") or "open") in ("fixed", "accepted"):
        return False
    due = _parse_ts(row.get("sla_due"))
    return bool(due and (now or _now()) > due)


def summarize(rows: list) -> dict:
    """Aggregati per la UI: conteggi per stato/severita' + violazioni SLA."""
    now = _now()
    by_status = {s: 0 for s in STATUSES}
    by_sev = {s: 0 for s in SEV_ORDER}
    sources: dict = {}
    breached = 0
    for r in rows:
        st = (r.get("status") or "open")
        by_status[st] = by_status.get(st, 0) + 1
        if st in ("open", "triaged"):
            sev = (r.get("severity") or "UNKNOWN").upper()
            by_sev[sev] = by_sev.get(sev, 0) + 1
        if is_breached(r, now):
            breached += 1
        for s in (r.get("source") or "").split("+"):
            if s:
                sources[s] = sources.get(s, 0) + 1
    return {"total": len(rows), "by_status": by_status, "by_severity": by_sev,
            "sla_breached": breached, "sources": sources}

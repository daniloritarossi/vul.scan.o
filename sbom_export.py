"""
sbom_export.py
--------------
Genera una SBOM conforme dai componenti raccolti nell'ultima run di postura.

Formati:
  - righe piatte (sbom_rows)   -> tabella UI
  - CycloneDX 1.5 (build_cyclonedx)
  - SPDX 2.3 (build_spdx)

Sorgente dati: fetch_posture_sbom(run) -> run con posture_assets[].posture_components[].
Ogni componente porta gia' purl, cpe, licenza, fornitore, sha256, cve, depends_on.
"""

import re
import uuid
from datetime import datetime, timezone


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _assets(run: dict) -> list:
    return (run or {}).get("posture_assets") or []


def _components(asset: dict) -> list:
    return asset.get("posture_components") or []


# --- righe piatte per la tabella UI --------------------------------------

def sbom_rows(run: dict) -> list:
    """Appiattisce run -> righe {asset_ip, package, ..., license, purl, ...}."""
    rows = []
    for a in _assets(run):
        ip = a.get("ip") or ""
        for c in _components(a):
            rows.append({
                "asset_ip":  ip,
                "package":   c.get("package") or "",
                "version":   c.get("version") or "",
                "ecosystem": c.get("ecosystem") or "",
                "category":  c.get("category") or "",
                "license":   c.get("license") or "NOASSERTION",
                "supplier":  c.get("supplier") or "NOASSERTION",
                "purl":      c.get("purl") or "",
                "cpe":       c.get("cpe") or "",
                "sha256":    c.get("sha256") or "",
                "cve_count": c.get("vuln_count") or 0,
                "max_severity": (c.get("max_severity") or "NONE").upper(),
                "depends_on": c.get("depends_on") or [],
                "license_class": license_class(c.get("license")),
            })
    return rows


# --- classificazione licenze + filtri/gruppi/sort/summary (UI) ------------

SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NONE")
_SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}
# Marcatori copyleft (case-insensitive). MIT/BSD/Apache/ISC ecc. = permissive.
_COPYLEFT = ("GPL", "AGPL", "LGPL", "MPL", "EPL", "CDDL", "OSL", "EUPL", "CECILL")


def license_class(lic) -> str:
    """'unknown' | 'copyleft' | 'permissive' — per badge e filtro compliance."""
    s = (lic or "").strip().upper()
    if not s or s == "NOASSERTION" or s.startswith("LICENSEREF-"):
        return "unknown"
    if any(tok in s for tok in _COPYLEFT):
        return "copyleft"
    return "permissive"


def filter_rows(rows: list, asset: str = "", pkg: str = "", q: str = "",
                vuln: str = "", license: str = "") -> list:
    """Filtra le righe SBOM. 'q' = ricerca ampia (pkg/purl/cpe/licenza/eco/cve)."""
    a, p, ql = asset.lower(), pkg.lower(), q.lower()
    out = []
    for r in rows:
        if a and a not in (r.get("asset_ip") or "").lower():
            continue
        if p and p not in (r.get("package") or "").lower():
            continue
        cc = r.get("cve_count") or 0
        if vuln == "vuln" and cc <= 0:
            continue
        if vuln == "safe" and cc > 0:
            continue
        if license and r.get("license_class") != license:
            continue
        if ql:
            hay = " ".join(str(r.get(k) or "") for k in (
                "package", "purl", "cpe", "license", "ecosystem", "asset_ip",
                "version", "supplier")).lower()
            if ql not in hay:
                continue
        out.append(r)
    return out


def group_by_component(rows: list) -> list:
    """Collassa per (package, version, ecosystem): 1 riga, N asset."""
    groups: dict = {}
    for r in rows:
        key = (r.get("package"), r.get("version"), r.get("ecosystem"))
        g = groups.get(key)
        if g is None:
            g = {**r, "assets": set(), "cve_count": 0, "max_severity": "NONE"}
            groups[key] = g
        if r.get("asset_ip"):
            g["assets"].add(r["asset_ip"])
        g["cve_count"] = max(g["cve_count"], r.get("cve_count") or 0)
        if _SEV_RANK.get((r.get("max_severity") or "NONE"), 99) < _SEV_RANK.get(g["max_severity"], 99):
            g["max_severity"] = r.get("max_severity") or "NONE"
    out = []
    for g in groups.values():
        assets = sorted(g.pop("assets"))
        g["asset_count"] = len(assets)
        g["assets"] = assets
        g["asset_ip"] = assets[0] if len(assets) == 1 else f"{len(assets)} assets"
        out.append(g)
    return out


def sort_rows(rows: list, field: str, dir: str = "asc") -> list:
    """Ordina in-place-safe. 'max_severity' usa l'ordine di gravita'."""
    if not field:
        return rows
    rev = (dir == "desc")
    if field == "max_severity":
        keyf = lambda r: _SEV_RANK.get(r.get("max_severity") or "NONE", 99)
    elif field in ("cve_count", "asset_count"):
        keyf = lambda r: r.get(field) or 0
    else:
        keyf = lambda r: str(r.get(field) or "").lower()
    return sorted(rows, key=keyf, reverse=rev)


def summarize_sbom(rows: list) -> dict:
    """KPI: componenti, pacchetti unici, vulnerabili, licenze, ecosistema top."""
    unique_pkgs = {(r.get("package"), r.get("version"), r.get("ecosystem")) for r in rows}
    vulnerable = sum(1 for r in rows if (r.get("cve_count") or 0) > 0)
    licenses = {(r.get("license") or "NOASSERTION") for r in rows}
    lic_class = {"permissive": 0, "copyleft": 0, "unknown": 0}
    eco: dict = {}
    for r in rows:
        lic_class[r.get("license_class", "unknown")] = lic_class.get(r.get("license_class", "unknown"), 0) + 1
        e = r.get("ecosystem") or "?"
        eco[e] = eco.get(e, 0) + 1
    top_eco = max(eco.items(), key=lambda kv: kv[1])[0] if eco else "—"
    return {
        "components": len(rows), "unique": len(unique_pkgs), "vulnerable": vulnerable,
        "licenses": len(licenses), "license_class": lic_class, "top_ecosystem": top_eco,
    }


# --- helper comuni --------------------------------------------------------

def _spdx_id(*parts: str) -> str:
    """SPDXID valido: SPDXRef-[A-Za-z0-9.-]+ ."""
    raw = "-".join(str(p) for p in parts if p)
    return "SPDXRef-" + (re.sub(r"[^A-Za-z0-9.-]+", "-", raw).strip("-") or "pkg")


def _is_library(eco: str) -> bool:
    return (eco or "") != "Windows"


# --- CycloneDX 1.5 --------------------------------------------------------

def build_cyclonedx(run: dict) -> dict:
    components = []
    dependencies = []
    vuln_map = {}   # cve_id -> set(bom-ref)

    for a in _assets(run):
        ip = a.get("ip") or "unknown"
        ref_by_name = {}   # name.lower() -> bom-ref (per le relazioni, per-asset)
        comp_refs = []
        for c in _components(a):
            name = c.get("package") or ""
            purl = c.get("purl") or ""
            ref = f"{ip}:{purl or name}"
            ref_by_name[name.lower()] = ref
            comp_refs.append((c, ref))

        for c, ref in comp_refs:
            name = c.get("package") or ""
            lic = c.get("license") or "NOASSERTION"
            comp = {
                "bom-ref": ref,
                "type": "library" if _is_library(c.get("ecosystem")) else "application",
                "name": name,
                "version": c.get("version") or "",
                "purl": c.get("purl") or "",
                "cpe": c.get("cpe") or "",
                "supplier": {"name": c.get("supplier") or "NOASSERTION"},
                "hashes": [{"alg": "SHA-256", "content": c.get("sha256") or ""}],
                "properties": [
                    {"name": "asset:ip", "value": ip},
                    {"name": "ecosystem", "value": c.get("ecosystem") or ""},
                    {"name": "category", "value": c.get("category") or ""},
                ],
            }
            if lic and lic != "NOASSERTION":
                comp["licenses"] = [{"license": {"name": lic}}]
            components.append(comp)

            # relazioni: dipendenze presenti nello stesso asset
            deps = [ref_by_name[d.lower()] for d in (c.get("depends_on") or [])
                    if d.lower() in ref_by_name]
            if deps:
                dependencies.append({"ref": ref, "dependsOn": deps})

            for cve in (c.get("cve_ids") or []):
                vuln_map.setdefault(cve, set()).add(ref)

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _iso_now(),
            "tools": [{"vendor": "VUL.SCAN.O", "name": "posture-sbom", "version": "1.0"}],
            "component": {"type": "application", "name": "asset-fleet"},
        },
        "components": components,
        "dependencies": dependencies,
    }
    if vuln_map:
        doc["vulnerabilities"] = [
            {"id": cve, "affects": [{"ref": r} for r in sorted(refs)]}
            for cve, refs in sorted(vuln_map.items())
        ]
    return doc


# --- SPDX 2.3 -------------------------------------------------------------

def build_spdx(run: dict) -> dict:
    packages = []
    relationships = []

    for idx, a in enumerate(_assets(run)):
        ip = a.get("ip") or "unknown"
        id_by_name = {}
        comp_ids = []
        for c in _components(a):
            name = c.get("package") or "pkg"
            ver = c.get("version") or ""
            sid = _spdx_id(idx, name, ver)
            id_by_name[name.lower()] = sid
            comp_ids.append((c, sid))

        for c, sid in comp_ids:
            name = c.get("package") or "pkg"
            lic = c.get("license") or "NOASSERTION"
            supplier = c.get("supplier") or "NOASSERTION"
            pkg = {
                "SPDXID": sid,
                "name": name,
                "versionInfo": c.get("version") or "",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": lic,
                "licenseDeclared": lic,
                "supplier": ("NOASSERTION" if supplier == "NOASSERTION"
                             else f"Organization: {supplier}"),
                "checksums": [{"algorithm": "SHA256", "checksumValue": c.get("sha256") or ""}],
                "externalRefs": [],
                "comment": f"asset={ip} ecosystem={c.get('ecosystem') or ''}",
            }
            if c.get("purl"):
                pkg["externalRefs"].append({
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": c["purl"],
                })
            if c.get("cpe"):
                pkg["externalRefs"].append({
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": c["cpe"],
                })
            packages.append(pkg)
            relationships.append({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": sid,
                "relationshipType": "DESCRIBES",
            })
            for d in (c.get("depends_on") or []):
                dep_sid = id_by_name.get(d.lower())
                if dep_sid:
                    relationships.append({
                        "spdxElementId": sid,
                        "relatedSpdxElement": dep_sid,
                        "relationshipType": "DEPENDS_ON",
                    })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "asset-fleet-sbom",
        "documentNamespace": f"https://vul.scan.o/spdx/{uuid.uuid4()}",
        "creationInfo": {
            "created": _iso_now(),
            "creators": ["Tool: VUL.SCAN.O-posture-sbom-1.0"],
        },
        "packages": packages,
        "relationships": relationships,
    }

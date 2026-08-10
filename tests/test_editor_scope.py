"""
test_editor_scope.py
---------------------
Cono di visibilita' dei ruoli scoped: devono vedere SOLO gli asset e i gruppi
assegnati a loro (o a un loro gruppo). 'editor' scrive dentro il cono,
'stakeholder' lo legge soltanto. admin/manager/auditor/viewer restano
"unscoped": auditor e viewer sono di sola lettura ma vedono tutto
l'inventario, con lo username dell'asset redatto.
"""


def _ips(assets_json):
    return {a["ip"] for a in assets_json["assets"]}


def _ids(assets_json):
    return {a["index"] if "index" in a else a.get("id") for a in assets_json["assets"]}


def test_editor_sees_only_assigned_asset(role_clients, cone_fixture):
    r = role_clients["editor"].get("/api/assets")
    assert r.status_code == 200
    ips = _ips(r.json())
    assert "10.99.0.1" in ips          # asset_in: assegnato
    assert "10.99.0.2" not in ips      # asset_out: fuori cono


def test_unscoped_roles_see_both_assets(role_clients, cone_fixture):
    for role in ("admin", "manager", "auditor", "viewer"):
        r = role_clients[role].get("/api/assets")
        assert r.status_code == 200
        ips = _ips(r.json())
        assert {"10.99.0.1", "10.99.0.2"} <= ips, f"{role} dovrebbe vedere tutti gli asset"


def test_readonly_roles_username_redacted(role_clients, cone_fixture):
    """auditor, viewer e stakeholder non operano sugli host: niente credenziali."""
    for role in ("auditor", "viewer", "stakeholder"):
        r = role_clients[role].get("/api/assets")
        assert r.status_code == 200
        for a in r.json()["assets"]:
            assert a["username"] is None, f"{role} non deve vedere lo username"

        r = role_clients[role].get("/api/assets/all")
        assert r.status_code == 200
        for a in r.json()["assets"]:
            assert a["username"] == "", f"{role} non deve vedere lo username"
            assert a["has_password"] is False


def test_auditor_reads_audit_but_writes_nothing(role_clients, cone_fixture):
    """Il ruolo esiste per questo: legge le prove, non tocca lo stato."""
    c = role_clients["auditor"]
    for path in ("/api/audit", "/api/audit/verify", "/api/audit/findings-verify",
                 "/api/audit/posture-verify", "/api/findings/as-of"):
        assert c.get(path).status_code == 200, f"auditor deve poter leggere {path}"

    asset_in = cone_fixture["asset_in"]
    assert c.post("/api/assets", json={"ip": "10.99.0.9"}).status_code == 403
    assert c.delete(f"/api/assets/{asset_in}").status_code == 403
    assert c.patch("/api/findings/1/status", json={"status": "fixed"}).status_code == 403
    assert c.post("/api/findings/import", json={}).status_code == 403
    assert c.get("/api/scan").status_code == 403
    assert c.get("/api/posture/scan").status_code == 403
    assert c.get("/api/settings").status_code == 403


def test_stakeholder_sees_only_assigned_asset(role_clients, cone_fixture):
    """Lo stakeholder e' scoped come l'editor: il cono vale anche in lettura."""
    for path in ("/api/assets", "/api/assets/all"):
        r = role_clients["stakeholder"].get(path)
        assert r.status_code == 200, f"{path}: {r.text}"
        ips = _ips(r.json())
        assert "10.99.0.1" in ips, f"{path}: manca l'asset assegnato"
        assert "10.99.0.2" not in ips, f"{path}: asset fuori cono visibile"


def test_stakeholder_findings_scoped(role_clients, cone_fixture, findings_fixture):
    """Anche i finding sono filtrati sul cono: niente leak dal resto della flotta."""
    r = role_clients["stakeholder"].get("/api/findings")
    assert r.status_code == 200, r.text
    ips = {f.get("asset_ip") for f in r.json()["findings"]}
    assert "10.99.0.2" not in ips


def test_stakeholder_writes_nothing(role_clients, cone_fixture, findings_fixture):
    """Sola lettura anche DENTRO il proprio cono: e' la differenza con l'editor."""
    c = role_clients["stakeholder"]
    asset_in = cone_fixture["asset_in"]

    assert c.post("/api/assets", json={"ip": "10.99.0.8"}).status_code == 403
    assert c.patch(f"/api/assets/{asset_in}/enabled",
                   json={"enabled": False}).status_code == 403
    assert c.delete(f"/api/assets/{asset_in}").status_code == 403
    assert c.patch(f"/api/findings/{findings_fixture['in']}/status",
                   json={"status": "fixed"}).status_code == 403
    assert c.get("/api/scan").status_code == 403
    assert c.get("/api/posture/scan").status_code == 403
    assert c.get("/api/settings").status_code == 403


def test_stakeholder_has_no_audit_access(role_clients, cone_fixture):
    """Il registro espone 'actor_name': resta fuori dal ruolo, come per viewer."""
    c = role_clients["stakeholder"]
    for path in ("/api/audit", "/api/audit/verify", "/api/findings/as-of",
                 "/api/audit/evidence"):
        assert c.get(path).status_code == 403, f"stakeholder non deve leggere {path}"
    assert c.get("/api/sbom/export",
                 params={"format": "cyclonedx"}).status_code == 403


def test_editor_all_view_includes_assignment(role_clients, cone_fixture):
    r = role_clients["editor"].get("/api/assets/all")
    assert r.status_code == 200
    by_ip = {a["ip"]: a for a in r.json()["assets"]}
    assert "10.99.0.1" in by_ip
    assert "10.99.0.2" not in by_ip


def test_editor_forbidden_outside_cone(role_clients, cone_fixture):
    editor_c = role_clients["editor"]
    asset_out = cone_fixture["asset_out"]

    r = editor_c.patch(f"/api/assets/{asset_out}/enabled", json={"enabled": False})
    assert r.status_code == 403

    r = editor_c.delete(f"/api/assets/{asset_out}")
    assert r.status_code == 403

    r = editor_c.put(f"/api/assets/{asset_out}",
                      json={"ip": "10.99.0.2", "os_type": "linux"})
    assert r.status_code == 403


def test_editor_allowed_inside_cone(role_clients, cone_fixture):
    editor_c = role_clients["editor"]
    asset_in = cone_fixture["asset_in"]

    # toggle e poi ripristino: nessun cambio di stato residuo
    r = editor_c.patch(f"/api/assets/{asset_in}/enabled", json={"enabled": False})
    assert r.status_code == 200
    r = editor_c.patch(f"/api/assets/{asset_in}/enabled", json={"enabled": True})
    assert r.status_code == 200


def test_editor_cannot_reassign_assets(role_clients, cone_fixture):
    """Riassegnare un asset e' riservato ad admin/manager: l'editor non puo'
    farlo nemmeno su un asset del proprio cono (rischio self-escalation)."""
    editor_c = role_clients["editor"]
    asset_in = cone_fixture["asset_in"]
    r = editor_c.put(f"/api/assets/{asset_in}/assignments",
                      json={"user_ids": [], "group_ids": []})
    assert r.status_code == 403


def test_editor_create_asset_is_self_assigned(role_clients, role_user_ids):
    editor_c = role_clients["editor"]
    r = editor_c.post("/api/assets", json={"ip": "10.99.0.50", "os_type": "linux"})
    assert r.status_code == 200, r.text
    new_id = r.json()["index"]
    try:
        # subito visibile all'editor (auto-assegnato)
        r2 = editor_c.get("/api/assets")
        assert "10.99.0.50" in _ips(r2.json())
        # e l'editor stesso puo' cancellarlo (dentro il proprio cono)
    finally:
        editor_c.delete(f"/api/assets/{new_id}")


def test_editor_sees_only_own_group(role_clients, cone_fixture):
    r = role_clients["editor"].get("/api/groups")
    assert r.status_code == 200
    names = {g["name"] for g in r.json()["groups"]}
    assert "_ftest_group_in" in names
    assert "_ftest_group_out" not in names


def test_admin_sees_all_groups(role_clients, cone_fixture):
    r = role_clients["admin"].get("/api/groups")
    assert r.status_code == 200
    names = {g["name"] for g in r.json()["groups"]}
    assert {"_ftest_group_in", "_ftest_group_out"} <= names


def test_findings_status_scope(role_clients, cone_fixture, findings_fixture):
    """PATCH /api/findings/{id}/status: l'editor puo' operare solo sul
    finding dell'asset nel proprio cono (10.99.0.1), non su quello fuori
    cono (10.99.0.2), anche se lo status_change altrimenti sarebbe valido."""
    editor_c = role_clients["editor"]

    r = editor_c.patch(f"/api/findings/{findings_fixture['in']}/status",
                        json={"status": "triaged"})
    assert r.status_code == 200, r.text

    r = editor_c.patch(f"/api/findings/{findings_fixture['out']}/status",
                        json={"status": "triaged"})
    assert r.status_code == 403, r.text

    # admin/manager (unscoped) possono operare su entrambi
    for role in ("admin", "manager"):
        r = role_clients[role].patch(f"/api/findings/{findings_fixture['out']}/status",
                                      json={"status": "triaged"})
        assert r.status_code == 200, f"{role}: {r.text}"

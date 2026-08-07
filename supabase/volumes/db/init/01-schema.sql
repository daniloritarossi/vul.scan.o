-- Schema del Vulnerability Feed Aggregator.
-- Applicato in modo idempotente da setup.sh dopo l'avvio del DB.
--
-- Due tabelle:
--   scans         -> una riga per esecuzione di scansione (target + sintesi CVE)
--   scan_results  -> una riga per asset scansionato, con esito + CVE rilevate

-- 1) Ruoli (anon/authenticated/service_role/authenticator) sono gia' forniti
--    dall'immagine supabase/postgres e sono riservati: non li tocchiamo qui.
--    authenticator accede con POSTGRES_PASSWORD (vedi PGRST_DB_URI nel compose).

-- 2) Tabelle.
CREATE TABLE IF NOT EXISTS public.scans (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at    timestamptz NOT NULL DEFAULT now(),
  description   text,                 -- testo vulnerabilita' in input
  product       text,                 -- prodotto canonico identificato
  version       text,                 -- versione target
  matched_alias text,                 -- alias trovato nel testo
  source        text,                 -- local | osint | none
  candidates    jsonb DEFAULT '[]'::jsonb,
  dependencies  jsonb DEFAULT '[]'::jsonb,
  cve_count     integer,              -- conteggio CVE ufficiale (OSV)
  cve_ids       jsonb DEFAULT '[]'::jsonb,
  cve_summary   text,                 -- sintesi LLM locale
  cve_error     text
);

CREATE TABLE IF NOT EXISTS public.scan_results (
  id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_id          bigint REFERENCES public.scans(id) ON DELETE CASCADE,
  created_at       timestamptz NOT NULL DEFAULT now(),
  ip               text NOT NULL,
  auth_required    boolean,
  method           text,              -- banner-grab | auth-sim | auth-ssh
  product_found    boolean,
  detected_version text,
  raw_evidence     text,
  vuln_match       text,              -- VULNERABILE | NON VULNERABILE | INCERTO
  cve_count        integer,
  cve_ids          jsonb DEFAULT '[]'::jsonb,
  cve_error        text
);

-- Advisory AI (vulnerabilita' SENZA CVE): versione affetta dedotta dall'LLM e
-- base del verdetto. Tenute DISTINTE dai campi CVE (cve_count/cve_ids).
ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS affected_version text,   -- vincolo AI (es. '<2.5.0')
  ADD COLUMN IF NOT EXISTS affected_source  text;   -- 'input' | 'ai' | null
ALTER TABLE public.scan_results
  ADD COLUMN IF NOT EXISTS affected_version  text,   -- vincolo valutato per l'asset
  ADD COLUMN IF NOT EXISTS match_basis       text,   -- 'input-version'|'ai-advisory'|'none'
  ADD COLUMN IF NOT EXISTS os_type           text,   -- 'linux' | 'windows' (da inventario)
  ADD COLUMN IF NOT EXISTS os_major_version  text;   -- es. '22.04', '10', '2019'

-- Audit ledger: attore (chi ha lanciato la scansione) + catena hash tamper-evident.
--   actor_id/actor_name  -> utente autore (snapshot), immutabili
--   hash_ts              -> timestamp usato nel calcolo hash (deterministico)
--   prev_hash            -> row_hash della scansione precedente (linkatura catena)
--   row_hash             -> sha256(prev_hash | campi immutabili) alla creazione
-- Solo i campi immutabili entrano nell'hash (description/product/source/actor_id/
-- hash_ts): version e cve_* vengono aggiornati a fine scan e NON sono coperti.
ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS actor_id   bigint,
  ADD COLUMN IF NOT EXISTS actor_name text,
  ADD COLUMN IF NOT EXISTS hash_ts    text,
  ADD COLUMN IF NOT EXISTS prev_hash  text,
  ADD COLUMN IF NOT EXISTS row_hash   text;

CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON public.scan_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_ip      ON public.scan_results(ip);
CREATE INDEX IF NOT EXISTS idx_scans_created_at     ON public.scans(created_at DESC);

-- 3) Permessi (locale: nessuna RLS; service_role bypassa comunque).
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL TABLES    IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON TABLES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON SEQUENCES TO anon, authenticated, service_role;

-- 4b) INVENTARIO ASSET: sostituisce assets.txt. Una riga per asset.
--     La password e' memorizzata cifrata (prefisso 'ENC:', vedi crypto.py).
CREATE TABLE IF NOT EXISTS public.assets (
  id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  ip               text NOT NULL,        -- IP o hostname
  username         text NOT NULL DEFAULT '',
  password         text NOT NULL DEFAULT '',  -- 'ENC:<hex>' oppure vuota
  os_type          text NOT NULL DEFAULT '',  -- 'linux' | 'windows' | ''
  os_major_version text NOT NULL DEFAULT '',  -- es. '22.04', '10', '2019'
  enabled          boolean NOT NULL DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_assets_ip ON public.assets(ip);

-- Contesto business dell'asset (capability ASPM: prioritizzazione contestuale).
-- Pesano il risk score: un critical su asset prod internet-facing conta di piu'.
ALTER TABLE public.assets
  ADD COLUMN IF NOT EXISTS environment     text    NOT NULL DEFAULT 'unknown', -- prod|staging|dev|unknown
  ADD COLUMN IF NOT EXISTS internet_facing boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS criticality     integer NOT NULL DEFAULT 3;          -- 1 (basso) .. 5 (alto)

-- 5) FULL POSTURE (SCA): run manuale -> asset -> finding per pacchetto.
CREATE TABLE IF NOT EXISTS public.posture_runs (
  id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at      timestamptz NOT NULL DEFAULT now(),
  assets_scanned  integer,
  total_packages  integer,
  total_vulnerable integer,
  total_vulns     integer,
  avg_score       integer
);

CREATE TABLE IF NOT EXISTS public.posture_assets (
  id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  run_id              bigint REFERENCES public.posture_runs(id) ON DELETE CASCADE,
  created_at          timestamptz NOT NULL DEFAULT now(),
  ip                  text NOT NULL,
  os_guess            text,
  method              text,            -- 'ssh' | 'sim'
  total_packages      integer,
  vulnerable_packages integer,
  total_vulns         integer,
  score               integer,
  sev_critical        integer,
  sev_high            integer,
  sev_medium          integer,
  sev_low             integer,
  sev_unknown         integer,
  os_type             text,    -- 'linux' | 'windows' (da inventario asset)
  os_major_version    text     -- es. '22.04', '10', '2019'
);

CREATE TABLE IF NOT EXISTS public.posture_findings (
  id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  asset_id     bigint REFERENCES public.posture_assets(id) ON DELETE CASCADE,
  package      text NOT NULL,
  version      text,
  ecosystem    text,
  category     text,
  vuln_count   integer,
  max_severity text,
  cve_ids      jsonb DEFAULT '[]'::jsonb
);

ALTER TABLE public.posture_assets
  ADD COLUMN IF NOT EXISTS os_type          text,
  ADD COLUMN IF NOT EXISTS os_major_version text;

-- Inventario software COMPLETO per asset (SBOM): tutti i pacchetti installati,
-- non solo i vulnerabili. Arricchito con identificatori e metadati SBOM.
CREATE TABLE IF NOT EXISTS public.posture_components (
  id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  asset_id     bigint REFERENCES public.posture_assets(id) ON DELETE CASCADE,
  package      text NOT NULL,
  version      text,
  ecosystem    text,
  category     text,
  purl         text,      -- Package URL (spec purl)
  cpe          text,      -- CPE 2.3 (best-effort)
  license      text,      -- SPDX id o NOASSERTION
  supplier     text,      -- fornitore o NOASSERTION
  sha256       text,      -- digest coordinate (identita' deterministica)
  vuln_count   integer DEFAULT 0,
  max_severity text,
  cve_ids      jsonb DEFAULT '[]'::jsonb,
  depends_on   jsonb DEFAULT '[]'::jsonb   -- nomi pacchetti dipendenti (relazioni)
);

CREATE INDEX IF NOT EXISTS idx_posture_assets_run    ON public.posture_assets(run_id);
CREATE INDEX IF NOT EXISTS idx_posture_findings_asset ON public.posture_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_posture_components_asset ON public.posture_components(asset_id);

-- Permessi anche sulle nuove tabelle.
GRANT ALL ON ALL TABLES    IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;

-- 6) FINDINGS UNIFICATI (ciclo di vita ASPM): dedup per fingerprint, stati di
--    workflow (open|triaged|accepted|fixed) e SLA di remediation.
--    Alimentata dalla postura interna (SCA) e dai report di scanner esterni
--    ingeriti via /api/findings/import (Trivy, Grype, Nuclei, Semgrep).
CREATE TABLE IF NOT EXISTS public.findings (
  id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  fingerprint       text NOT NULL UNIQUE,   -- identita' stabile (dedup cross-tool)
  source            text NOT NULL,          -- posture|trivy|grype|nuclei|semgrep (o 'a+b')
  asset_ip          text,
  title             text,
  package           text,
  version           text,
  ecosystem         text,
  location          text,                   -- target/percorso/URL del finding
  severity          text,                   -- CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN
  cve_ids           jsonb DEFAULT '[]'::jsonb,
  detail            text,
  status            text NOT NULL DEFAULT 'open',  -- open|triaged|accepted|fixed
  status_note       text DEFAULT '',
  status_changed_at timestamptz DEFAULT now(),
  first_seen        timestamptz NOT NULL DEFAULT now(),
  last_seen         timestamptz NOT NULL DEFAULT now(),
  times_seen        integer NOT NULL DEFAULT 1,    -- osservazioni (report che lo confermano)
  reopened          integer NOT NULL DEFAULT 0,    -- riaperture automatiche post-fixed
  sla_due           timestamptz                    -- scadenza remediation per severita'
);

-- Compliance tagging (CWE dai report; OWASP/NIS2 derivati a runtime) e
-- riferimento al ticket di remediation (GitHub Issue / Jira).
ALTER TABLE public.findings
  ADD COLUMN IF NOT EXISTS cwe_ids    jsonb DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS ticket_ref text,   -- '#42' | 'SEC-101'
  ADD COLUMN IF NOT EXISTS ticket_url text;

CREATE INDEX IF NOT EXISTS idx_findings_status   ON public.findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_asset_ip ON public.findings(asset_ip);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON public.findings(severity);

GRANT ALL ON ALL TABLES    IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;

-- 7) RBAC / CONO DI VISIBILITA': utenti, gruppi e assegnazioni asset.
--    Ruoli applicativi: admin | manager | editor | viewer.
--    Lo scope dell'editor e' definito dalle assegnazioni asset -> utente/gruppo.
CREATE TABLE IF NOT EXISTS public.users (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at    timestamptz NOT NULL DEFAULT now(),
  username      text NOT NULL UNIQUE,
  password_hash text NOT NULL,             -- PBKDF2-HMAC-SHA256 (vedi auth.py)
  role          text NOT NULL DEFAULT 'viewer'
                CHECK (role IN ('admin','manager','editor','viewer'))
);

CREATE TABLE IF NOT EXISTS public.groups (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  name       text NOT NULL UNIQUE
);

-- Membership N:N utente <-> gruppo (un utente puo' stare in piu' gruppi).
CREATE TABLE IF NOT EXISTS public.user_groups (
  user_id  bigint NOT NULL REFERENCES public.users(id)  ON DELETE CASCADE,
  group_id bigint NOT NULL REFERENCES public.groups(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, group_id)
);

-- Assegnazione asset -> utente O gruppo (mai entrambi sulla stessa riga).
CREATE TABLE IF NOT EXISTS public.asset_assignments (
  id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  asset_id bigint NOT NULL REFERENCES public.assets(id)  ON DELETE CASCADE,
  user_id  bigint REFERENCES public.users(id)  ON DELETE CASCADE,
  group_id bigint REFERENCES public.groups(id) ON DELETE CASCADE,
  CHECK (num_nonnulls(user_id, group_id) = 1),
  UNIQUE (asset_id, user_id, group_id)
);

CREATE INDEX IF NOT EXISTS idx_asset_assignments_asset ON public.asset_assignments(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_assignments_user  ON public.asset_assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_asset_assignments_group ON public.asset_assignments(group_id);
CREATE INDEX IF NOT EXISTS idx_user_groups_user        ON public.user_groups(user_id);

-- Onboarding via email (invito con link one-time, mai password via mail):
--   email/email_verified_at    -> validazione implicita all'attivazione
--   is_active                  -> false finche' l'utente non imposta la password
--   must_change_password       -> cambio forzato al prossimo accesso
--   password_changed_at        -> rotation policy + invalidazione sessioni emesse prima
ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS email                text UNIQUE,
  ADD COLUMN IF NOT EXISTS email_verified_at    timestamptz,
  ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS password_changed_at  timestamptz DEFAULT now(),
  ADD COLUMN IF NOT EXISTS is_active            boolean NOT NULL DEFAULT true;
ALTER TABLE public.users ALTER COLUMN password_hash DROP NOT NULL;

-- Token one-time (attivazione account / reset password). In tabella va SOLO
-- l'hash SHA-256 del token: se il DB leaka, i token non sono spendibili.
CREATE TABLE IF NOT EXISTS public.auth_tokens (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  user_id    bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  purpose    text NOT NULL CHECK (purpose IN ('activation','reset')),
  expires_at timestamptz NOT NULL,
  used_at    timestamptz
);

CREATE INDEX IF NOT EXISTS idx_auth_tokens_user ON public.auth_tokens(user_id);

-- 8) AUDIT POINT-IN-TIME: registro append-only degli eventi di ciclo di vita.
--    La tabella 'findings' e' aggiornata IN PLACE (UPDATE su status) e quindi
--    NON conserva la storia: senza questo registro non e' possibile dimostrare
--    a un auditor quante vulnerabilita' erano aperte a una certa data e quante
--    ne sono state risolte in seguito. Qui ogni transizione e' una riga NUOVA,
--    mai modificata, concatenata in hash come il ledger delle scansioni.
--      fingerprint -> identita' stabile del finding (sopravvive a re-insert)
--      event       -> created | reopened | status_change | auto_fixed
--      event_ts    -> timestamp deterministico usato nel calcolo dell'hash
--      prev_hash   -> row_hash dell'evento precedente (linkatura catena)
--      row_hash    -> sha256(prev_hash | campi immutabili) alla creazione
CREATE TABLE IF NOT EXISTS public.finding_events (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),
  event_ts    text NOT NULL,
  finding_id  bigint,
  fingerprint text NOT NULL,
  event       text NOT NULL,
  from_status text,
  to_status   text,
  severity    text,
  asset_ip    text,
  source      text,
  actor_id    bigint,
  actor_name  text,
  note        text DEFAULT '',
  prev_hash   text,
  row_hash    text
);

CREATE INDEX IF NOT EXISTS idx_finding_events_fp ON public.finding_events(fingerprint);
CREATE INDEX IF NOT EXISTS idx_finding_events_ts ON public.finding_events(event_ts);

-- Hash FINALE della scansione: copre i campi MUTABILI (version + cve_count +
-- cve_ids) che update_scan_summary riscrive a fine scansione e che row_hash,
-- calcolato all'insert, non puo' coprire. E' ancorato a row_hash, quindi il
-- CONTEGGIO CVE — la cifra che un audit esterno contesta — diventa
-- tamper-evident quanto il resto della riga.
ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS final_ts   text,
  ADD COLUMN IF NOT EXISTS final_hash text;

-- 9) CATENA HASH DELLE RUN DI POSTURA.
--    posture_runs regge i CONTEGGI point-in-time (quante vulnerabilita' a una
--    certa data): era la tabella con i numeri piu' probanti e la protezione
--    minore. Stessa costruzione di 'scans': row_hash sui campi noti alla
--    creazione, final_hash sui totali sigillati a fine run.
ALTER TABLE public.posture_runs
  ADD COLUMN IF NOT EXISTS actor_id   bigint,
  ADD COLUMN IF NOT EXISTS actor_name text,
  ADD COLUMN IF NOT EXISTS hash_ts    text,
  ADD COLUMN IF NOT EXISTS prev_hash  text,
  ADD COLUMN IF NOT EXISTS row_hash   text,
  ADD COLUMN IF NOT EXISTS final_ts   text,
  ADD COLUMN IF NOT EXISTS final_hash text;

-- 10) APPEND-ONLY A LIVELLO DATABASE.
--     Le catene hash dimostrano che una riga NON e' stata modificata, ma da
--     sole non impediscono nulla: con le credenziali dell'app si poteva ancora
--     cancellare la coda di una catena, e una catena troncata resta valida.
--     Qui l'append-only diventa un vincolo del DB, non una convenzione.
--
--     Bypass: i ruoli 'postgres'/'supabase_admin' (accesso diretto a Postgres)
--     restano liberi. Non e' una svista — un superuser puo' comunque disattivare
--     i trigger, e fingere il contrario sarebbe teatro di sicurezza. Il punto e'
--     che le credenziali usate dall'applicazione (service_role, anon,
--     authenticated) non possono piu' riscrivere ne' cancellare la storia.

-- Tabelle puramente append-only: nessun UPDATE, nessun DELETE.
CREATE OR REPLACE FUNCTION public.ledger_immutable_row() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF current_user IN ('postgres', 'supabase_admin') THEN
    RETURN CASE TG_OP WHEN 'DELETE' THEN OLD ELSE NEW END;
  END IF;
  RAISE EXCEPTION 'ledger: % non consentito su %.% (tabella append-only)',
    TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '42501';
END;
$$;

-- 'scans': un solo UPDATE lecito, quello di fine scansione che scrive i valori
-- definitivi. I campi firmati non si toccano mai; i valori sigillati (version,
-- conteggio CVE) diventano immutabili nel momento in cui il sigillo esiste.
CREATE OR REPLACE FUNCTION public.scans_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF current_user IN ('postgres', 'supabase_admin') THEN
    RETURN CASE TG_OP WHEN 'DELETE' THEN OLD ELSE NEW END;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'ledger: DELETE non consentito su public.scans'
      USING ERRCODE = '42501';
  END IF;
  IF (OLD.created_at, OLD.description, OLD.product, OLD.source, OLD.actor_id,
      OLD.actor_name, OLD.hash_ts, OLD.prev_hash, OLD.row_hash)
     IS DISTINCT FROM
     (NEW.created_at, NEW.description, NEW.product, NEW.source, NEW.actor_id,
      NEW.actor_name, NEW.hash_ts, NEW.prev_hash, NEW.row_hash) THEN
    RAISE EXCEPTION 'ledger: campi firmati di public.scans non modificabili'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.final_hash IS NOT NULL AND
     (OLD.final_hash, OLD.final_ts, OLD.version, OLD.cve_count, OLD.cve_ids)
     IS DISTINCT FROM
     (NEW.final_hash, NEW.final_ts, NEW.version, NEW.cve_count, NEW.cve_ids) THEN
    RAISE EXCEPTION 'ledger: sigillo di public.scans gia apposto (write-once)'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

-- 'posture_runs': stessa regola, applicata ai totali della run.
CREATE OR REPLACE FUNCTION public.posture_runs_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF current_user IN ('postgres', 'supabase_admin') THEN
    RETURN CASE TG_OP WHEN 'DELETE' THEN OLD ELSE NEW END;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'ledger: DELETE non consentito su public.posture_runs'
      USING ERRCODE = '42501';
  END IF;
  IF (OLD.created_at, OLD.actor_id, OLD.actor_name, OLD.hash_ts,
      OLD.prev_hash, OLD.row_hash)
     IS DISTINCT FROM
     (NEW.created_at, NEW.actor_id, NEW.actor_name, NEW.hash_ts,
      NEW.prev_hash, NEW.row_hash) THEN
    RAISE EXCEPTION 'ledger: campi firmati di public.posture_runs non modificabili'
      USING ERRCODE = '42501';
  END IF;
  IF OLD.final_hash IS NOT NULL AND
     (OLD.final_hash, OLD.final_ts, OLD.assets_scanned, OLD.total_packages,
      OLD.total_vulnerable, OLD.total_vulns, OLD.avg_score)
     IS DISTINCT FROM
     (NEW.final_hash, NEW.final_ts, NEW.assets_scanned, NEW.total_packages,
      NEW.total_vulnerable, NEW.total_vulns, NEW.avg_score) THEN
    RAISE EXCEPTION 'ledger: sigillo di public.posture_runs gia apposto (write-once)'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_scans_append_only        ON public.scans;
DROP TRIGGER IF EXISTS trg_posture_runs_append_only ON public.posture_runs;
DROP TRIGGER IF EXISTS trg_scan_results_immutable       ON public.scan_results;
DROP TRIGGER IF EXISTS trg_posture_assets_immutable     ON public.posture_assets;
DROP TRIGGER IF EXISTS trg_posture_findings_immutable   ON public.posture_findings;
DROP TRIGGER IF EXISTS trg_posture_components_immutable ON public.posture_components;
DROP TRIGGER IF EXISTS trg_finding_events_immutable     ON public.finding_events;

CREATE TRIGGER trg_scans_append_only
  BEFORE UPDATE OR DELETE ON public.scans
  FOR EACH ROW EXECUTE FUNCTION public.scans_append_only();
CREATE TRIGGER trg_posture_runs_append_only
  BEFORE UPDATE OR DELETE ON public.posture_runs
  FOR EACH ROW EXECUTE FUNCTION public.posture_runs_append_only();
CREATE TRIGGER trg_scan_results_immutable
  BEFORE UPDATE OR DELETE ON public.scan_results
  FOR EACH ROW EXECUTE FUNCTION public.ledger_immutable_row();
CREATE TRIGGER trg_posture_assets_immutable
  BEFORE UPDATE OR DELETE ON public.posture_assets
  FOR EACH ROW EXECUTE FUNCTION public.ledger_immutable_row();
CREATE TRIGGER trg_posture_findings_immutable
  BEFORE UPDATE OR DELETE ON public.posture_findings
  FOR EACH ROW EXECUTE FUNCTION public.ledger_immutable_row();
CREATE TRIGGER trg_posture_components_immutable
  BEFORE UPDATE OR DELETE ON public.posture_components
  FOR EACH ROW EXECUTE FUNCTION public.ledger_immutable_row();
CREATE TRIGGER trg_finding_events_immutable
  BEFORE UPDATE OR DELETE ON public.finding_events
  FOR EACH ROW EXECUTE FUNCTION public.ledger_immutable_row();

-- Valvola di sfogo per la suite di test, che esercita gli endpoint reali e
-- quindi scrive nel registro. Puo' cancellare SOLO le righe con marcatore di
-- test '_ftest_': non e' un bypass generico del registro.
CREATE OR REPLACE FUNCTION public.purge_test_ledger() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE removed integer;
BEGIN
  DELETE FROM public.finding_events WHERE fingerprint LIKE '\_ftest\_%';
  GET DIAGNOSTICS removed = ROW_COUNT;
  RETURN removed;
END;
$$;

GRANT ALL ON ALL TABLES    IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;

-- I GRANT sopra sono volutamente larghi (ambiente locale): le revoche vanno
-- DOPO, altrimenti verrebbero riconcesse a ogni riesecuzione dello schema.
-- Difesa in profondita': i trigger bloccano comunque, ma un permesso mai
-- concesso e' meglio di un permesso revocato da un'eccezione.
REVOKE UPDATE, DELETE, TRUNCATE ON
  public.scans, public.scan_results, public.posture_runs, public.posture_assets,
  public.posture_findings, public.posture_components, public.finding_events
  FROM anon, authenticated;
REVOKE DELETE, TRUNCATE ON
  public.scans, public.scan_results, public.posture_runs, public.posture_assets,
  public.posture_findings, public.posture_components, public.finding_events
  FROM service_role;
-- service_role conserva UPDATE solo dove l'app deve davvero scrivere il
-- risultato finale (scans, posture_runs); i trigger delimitano cosa puo' toccare.
REVOKE UPDATE ON
  public.scan_results, public.posture_assets, public.posture_findings,
  public.posture_components, public.finding_events
  FROM service_role;

REVOKE ALL ON FUNCTION public.purge_test_ledger() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.purge_test_ledger() TO service_role;

-- 11) Ricarica la cache schema di PostgREST.
NOTIFY pgrst, 'reload schema';

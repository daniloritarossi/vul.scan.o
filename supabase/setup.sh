#!/usr/bin/env bash
# Avvia lo stack Supabase locale e applica lo schema in modo idempotente.
# Rilanciabile a piacere: i dati restano in ./volumes/db/data.
set -euo pipefail

cd "$(dirname "$0")"

# Segreti PER INSTALLAZIONE (JWT secret, chiavi anon/service_role, password
# Postgres). Generati al primo avvio; un .env con i vecchi valori demo, che
# erano versionati e quindi pubblici, viene sostituito. Vedi gen_secrets.py.
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERRORE: python3 richiesto per generare i segreti di supabase/.env" >&2
  exit 1
fi
umask 077
_secrets_status=$(python3 -I ./gen_secrets.py .env)
umask 022
case "$_secrets_status" in
  generated) echo "==> generati segreti nuovi per questa installazione (supabase/.env)" ;;
  resigned)  echo "==> chiavi JWT rifirmate con il JWT_SECRET di questa installazione" ;;
esac

# Carica le variabili (.env) anche nello shell, non solo in docker compose.
set -a; . ./.env; set +a

echo "==> docker compose up -d"
docker compose up -d

echo "==> attendo che il DB sia healthy..."
for i in $(seq 1 40); do
  if docker compose exec -T db pg_isready -U postgres -d postgres >/dev/null 2>&1; then
    echo "    DB pronto."
    break
  fi
  sleep 2
  if [ "$i" = "40" ]; then echo "ERRORE: DB non pronto in tempo."; exit 1; fi
done

# Password di TUTTI i ruoli con login = POSTGRES_PASSWORD di questa
# installazione. L'immagine Postgres applica POSTGRES_PASSWORD solo quando
# inizializza un volume vuoto: su un volume esistente i ruoli terrebbero la
# password di prima (per le installazioni vecchie quella demo, pubblica, anche
# per il superuser supabase_admin raggiungibile su 5432). Lo fa supabase_admin
# via socket locale, che non chiede password: funziona anche dopo la rotazione.
# authenticator deve combaciare con PGRST_DB_URI, postgres con meta/studio.
# La password passa da stdin, non dalla riga di comando (visibile in ps).
echo "==> allineo la password dei ruoli Postgres (via supabase_admin)"
docker compose exec -T db psql -v ON_ERROR_STOP=1 -qX -U supabase_admin -d postgres \
  >/dev/null <<SQL
\set pw '${POSTGRES_PASSWORD}'
ALTER ROLE authenticator WITH LOGIN;
SELECT format('ALTER ROLE %I WITH PASSWORD %L', rolname, :'pw')
  FROM pg_roles WHERE rolcanlogin
\gexec
SQL
# gateway incluso: se 'up' ha ricreato rest (env cambiato), nginx ha ancora in
# cache il vecchio indirizzo del container e risponderebbe 502.
docker compose restart rest meta studio >/dev/null
docker compose restart gateway >/dev/null

echo "==> applico schema (volumes/db/init/01-schema.sql)"
docker compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d postgres \
  < volumes/db/init/01-schema.sql

echo "==> ricarico cache PostgREST"
docker compose exec -T db psql -U postgres -d postgres \
  -c "NOTIFY pgrst, 'reload schema';" >/dev/null

# Lo schema abilita RLS ovunque (sezione 11), ma se qualcuno la disattiva a mano
# o aggiunge una tabella fuori dallo schema, PostgREST la espone in chiaro alla
# chiave anon. Qui la verifica e' bloccante: meglio non avviare che avviare
# aperti.
echo "==> verifico RLS su tutte le tabelle di public"
_no_rls=$(docker compose exec -T db psql -tAqX -U postgres -d postgres \
  -c "SELECT coalesce(string_agg(tablename, ', ' ORDER BY tablename), '')
        FROM pg_tables WHERE schemaname = 'public' AND NOT rowsecurity;" | tr -d '\r')
if [ -n "$_no_rls" ]; then
  echo "ERRORE: RLS non attiva su: ${_no_rls}" >&2
  echo "       Riapplica volumes/db/init/01-schema.sql oppure abilitala a mano:" >&2
  echo "       ALTER TABLE public.<tabella> ENABLE ROW LEVEL SECURITY;" >&2
  exit 1
fi
echo "    RLS attiva su tutte le tabelle di public."

cat <<'EOF'

==> FATTO.
  Studio GUI : http://localhost:3001
  REST API   : http://localhost:8001/rest/v1/   (header: apikey + Authorization Bearer)
  Postgres   : localhost:5432  (user=postgres)
  Segreti    : ./.env  (generati per questa installazione, permessi 600)
  Dati       : ./volumes/db/data  (persistenti)

EOF

#!/usr/bin/env bash
# Avvia lo stack Supabase locale e applica lo schema in modo idempotente.
# Rilanciabile a piacere: i dati restano in ./volumes/db/data.
set -euo pipefail

cd "$(dirname "$0")"

# Carica le variabili (.env) anche nello shell, non solo in docker compose.
set -a; [ -f .env ] && . ./.env; set +a

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

# authenticator e' un ruolo riservato: la password va impostata dal superuser
# supabase_admin (non da 'postgres'). Deve combaciare con PGRST_DB_URI nel compose.
echo "==> imposto password ruolo authenticator (via supabase_admin)"
docker compose exec -T db psql -U supabase_admin -d postgres \
  -c "ALTER ROLE authenticator WITH LOGIN PASSWORD '${POSTGRES_PASSWORD:-postgres-local-pw}';" >/dev/null
docker compose restart rest >/dev/null

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
  Dati       : ./volumes/db/data  (persistenti)

EOF

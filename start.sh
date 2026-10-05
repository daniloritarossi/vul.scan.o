#!/usr/bin/env bash
# Vulnerability Feed Aggregator — avvio + configurazione
#
# Uso:
#   ./start.sh                 primo avvio: wizard, poi lancia
#   ./start.sh                 avvio normale se config.json esiste
#   ./start.sh update          modifica configurazione esistente via CLI
#   ./start.sh --no-supabase   salta Supabase (qualunque altro arg combinabile)
#   PORT=9000 ./start.sh       porta diversa per FastAPI
set -euo pipefail

cd "$(dirname "$0")"

PORT="${PORT:-8000}"
WITH_SUPABASE=1
MODE="normal"
LAUNCH_APP=1
CONFIG_FILE="config.json"

for _arg in "$@"; do
  case "$_arg" in
    update)        MODE="update"   ;;
    --no-supabase) WITH_SUPABASE=0 ;;
  esac
done

# ── Preflight: dipendenze di sistema richieste da wizard/encdec/venv ─────────
# Se mancano, tenta l'installazione automatica col package manager della
# distro (apt/dnf/yum/apk/pacman/zypper). Fallback: hint manuale.

_pkg_mgr() {
  local _m
  for _m in apt-get dnf yum apk pacman zypper; do
    command -v "$_m" >/dev/null 2>&1 && { echo "$_m"; return 0; }
  done
  return 1
}

_pkg_map() {
  # _pkg_map MGR nome-logico → nome pacchetto per quel manager.
  # I nomi logici usati nello script sono quelli Debian.
  local _mgr="$1" _p="$2"
  case "$_mgr:$_p" in
    apt-get:*)                    echo "$_p" ;;
    pacman:python3|pacman:python3-venv)
                                  echo "python" ;;
    *:python3-venv)               echo "python3" ;;  # venv incluso fuori da Debian
    dnf:golang|yum:golang)        echo "golang" ;;
    *:golang)                     echo "go" ;;
    dnf:docker.io|yum:docker.io)  echo "moby-engine" ;;
    *:docker.io)                  echo "docker" ;;
    apk:docker-compose-plugin|apk:docker-compose-v2)
                                  echo "docker-cli-compose" ;;
    *:docker-compose-plugin|*:docker-compose-v2)
                                  echo "docker-compose" ;;
    *)                            echo "$_p" ;;
  esac
}

_pkg_install() {
  # _pkg_install pkg... (nomi logici stile Debian) → true se installazione riuscita
  local _mgr _sudo="" _p _pkgs=()
  if ! _mgr="$(_pkg_mgr)"; then
    printf 'No known package manager (apt/dnf/yum/apk/pacman/zypper) — install manually: %s\n' "$*" >&2
    return 1
  fi
  if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
      _sudo="sudo"
    else
      printf 'Root privileges required and sudo is not installed — run as root: %s install %s\n' "$_mgr" "$*" >&2
      return 1
    fi
  fi
  for _p in "$@"; do _pkgs+=("$(_pkg_map "$_mgr" "$_p")"); done
  printf '==> auto-installing (%s): %s\n' "$_mgr" "${_pkgs[*]}" >&2
  case "$_mgr" in
    apt-get) $_sudo apt-get update -qq >&2 || true
             $_sudo apt-get install -y "${_pkgs[@]}" >&2 ;;
    dnf|yum) $_sudo "$_mgr" install -y "${_pkgs[@]}" >&2 ;;
    apk)     $_sudo apk add "${_pkgs[@]}" >&2 ;;
    pacman)  $_sudo pacman -Sy --noconfirm "${_pkgs[@]}" >&2 ;;
    zypper)  $_sudo zypper --non-interactive install "${_pkgs[@]}" >&2 ;;
  esac
}

# retrocompatibilità con i call-site esistenti
_apt_install() { _pkg_install "$@"; }

_install_go_tarball() {
  # Installa l'ultima release ufficiale di Go in /usr/local/go.
  # Fallback quando il package manager non offre Go >= 1.21 (es. Debian 12).
  local _sudo="" _v _arch _tmp
  if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 && _sudo="sudo" || return 1
  fi
  case "$(uname -m)" in
    x86_64)        _arch=amd64 ;;
    aarch64|arm64) _arch=arm64 ;;
    *)             return 1 ;;
  esac
  _v=$(curl -fsSL 'https://go.dev/VERSION?m=text' 2>/dev/null | head -n1)
  case "$_v" in go[0-9]*) ;; *) return 1 ;; esac   # sanity: atteso "go1.XX.Y"
  printf '==> installing %s from go.dev into /usr/local/go\n' "$_v" >&2
  _tmp=$(mktemp)
  curl -fsSL "https://go.dev/dl/${_v}.linux-${_arch}.tar.gz" -o "$_tmp" || { rm -f "$_tmp"; return 1; }
  $_sudo rm -rf /usr/local/go
  $_sudo tar -C /usr/local -xzf "$_tmp" || { rm -f "$_tmp"; return 1; }
  rm -f "$_tmp"
  export PATH="/usr/local/go/bin:$PATH"
  hash -r 2>/dev/null || true   # invalida path cache di bash (es. /usr/bin/go di apt)
}

_install_compose_plugin() {
  # Installa il plugin 'docker compose' v2 da GitHub releases.
  # Fallback quando il package manager non lo offre (es. Debian 12 senza repo Docker).
  local _sudo="" _arch _dir=/usr/local/lib/docker/cli-plugins
  if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 && _sudo="sudo" || return 1
  fi
  case "$(uname -m)" in
    x86_64)        _arch=x86_64 ;;
    aarch64|arm64) _arch=aarch64 ;;
    *)             return 1 ;;
  esac
  printf '==> installing docker compose v2 from GitHub releases into %s\n' "$_dir" >&2
  $_sudo mkdir -p "$_dir"
  $_sudo curl -fsSL \
    "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${_arch}" \
    -o "$_dir/docker-compose" || return 1
  $_sudo chmod +x "$_dir/docker-compose"
}

_preflight() {
  local _missing=()
  for _b in python3 curl git; do
    command -v "$_b" >/dev/null 2>&1 || _missing+=("$_b")
  done
  # 'import venv' passa anche senza python3-venv (Debian): serve ensurepip
  command -v python3 >/dev/null 2>&1 && ! python3 -c 'import venv, ensurepip' 2>/dev/null \
    && _missing+=("python3-venv")
  [ "${#_missing[@]}" -eq 0 ] && return 0

  printf 'Missing system dependencies: %s\n' "${_missing[*]}" >&2
  if ! _apt_install "${_missing[@]}"; then
    printf 'ERROR: installation failed. Install manually with your distro package manager: %s\n' "${_missing[*]}" >&2
    exit 1
  fi
  # ricontrollo post-install
  for _b in python3 curl git; do
    if ! command -v "$_b" >/dev/null 2>&1; then
      printf 'ERROR: %s still missing after installation.\n' "$_b" >&2
      exit 1
    fi
  done
  if ! python3 -c 'import venv, ensurepip' 2>/dev/null; then
    printf 'ERROR: venv/ensurepip module still missing (python3-venv).\n' >&2
    exit 1
  fi
  printf '✓ Dependencies installed.\n' >&2
}
_preflight

# ── Ollama: installazione, avvio e verifica modello (LLM di default) ─────────
# Usata dal wizard AI e dal precheck a ogni avvio. Se URL locale: installa
# ollama (script ufficiale) e avvia il server se serve. In ogni caso: pull del
# modello se assente e verifica finale via /api/tags.

_ensure_ollama() {
  # _ensure_ollama URL MODEL [INSTALL]
  # INSTALL=1 (default): installa ollama se assente. INSTALL=0: non installare
  # (scelta dell'utente nel wizard, salvata in ai.ollama_autoinstall).
  local _url="$1" _model="$2" _install="${3:-1}"
  local _base="${_url%/api/generate}"
  local _is_local=0
  case "$_base" in *localhost*|*127.0.0.1*) _is_local=1 ;; esac

  # URL locale + binario assente -> installazione (script ufficiale), se consentita
  if [ "$_is_local" = "1" ] && ! command -v ollama >/dev/null 2>&1; then
    if [ "$_install" = "1" ]; then
      printf '  Ollama not installed — installing (official ollama.com script, sudo required).\n' >&2
      # l'installer ollama richiede zstd per estrarre l'archivio
      command -v zstd >/dev/null 2>&1 || _pkg_install zstd || true
      curl -fsSL https://ollama.com/install.sh | sh >&2 \
        || printf '  ⚠  Installation failed — install manually: https://ollama.com/download\n' >&2
    else
      printf '  ⚠  Ollama missing and auto-install disabled (wizard choice).\n' >&2
      printf '     To change: ./start.sh update -> AI provider.\n' >&2
    fi
  fi

  # server locale installato ma non attivo -> avvialo in background
  if [ "$_is_local" = "1" ] && command -v ollama >/dev/null 2>&1 \
     && ! curl -sf --max-time 3 "$_base" >/dev/null 2>&1; then
    printf '  ==> starting ollama serve (background)...\n' >&2
    (ollama serve >/dev/null 2>&1 &)
    sleep 2
  fi

  # verifica raggiungibilità + presenza modello (via /api/tags)
  if curl -sf --max-time 3 "$_base" >/dev/null 2>&1; then
    printf '  ✓  Ollama reachable.\n' >&2
    if ! curl -sf --max-time 5 "$_base/api/tags" 2>/dev/null | grep -q "\"$_model"; then
      if command -v ollama >/dev/null 2>&1; then
        printf '  ==> ollama pull %s\n' "$_model" >&2
        ollama pull "$_model" >&2 \
          || printf '  ⚠  pull failed — run manually: ollama pull %s\n' "$_model" >&2
      else
        printf '  ⚠  Model missing on remote server: run "ollama pull %s" there.\n' "$_model" >&2
      fi
    fi
    if curl -sf --max-time 5 "$_base/api/tags" 2>/dev/null | grep -q "\"$_model"; then
      printf '  ✓  Model %s present.\n' "$_model" >&2
    else
      printf '  ⚠  Model %s NOT verified — AI features will fail until it is available.\n' "$_model" >&2
    fi
  else
    printf '  ⚠  Ollama not reachable at %s\n     Make sure it is running before using AI features.\n' "$_base" >&2
  fi
}

# ── UI helpers ────────────────────────────────────────────────────────────────

_ask() {
  # _ask "Prompt" "default" → stampa la risposta su stdout
  printf "  %s [%s]: " "$1" "$2" >&2
  read -r _ans
  printf '%s' "${_ans:-$2}"
}

_ask_secret() {
  printf "  %s: " "$1" >&2
  read -rs _secret
  printf '\n' >&2
  printf '%s' "$_secret"
}

_choose() {
  # _choose "Titolo" opt1 opt2 ... → stampa numero scelto (1-based) su stdout
  local _title="$1"; shift
  local _opts=("$@")
  printf '\n' >&2
  printf '  %s\n' "$_title" >&2
  local _i=1
  for _o in "${_opts[@]}"; do
    printf '    %d) %s\n' "$_i" "$_o" >&2
    ((_i++))
  done
  while true; do
    printf '  Choice [1]: ' >&2
    # EOF (stdin chiuso) non e' "ha premuto Invio": senza distinguerlo la riga
    # sotto lo trasformerebbe nella scelta 1, il menu chiamante ripartirebbe e
    # la voce di uscita non arriverebbe mai — un ciclo che non si blocca su
    # nessuna lettura, brucia una CPU e riempie il terminale.
    #
    # Si termina l'intero script, non questa funzione: _choose gira dentro
    # $(...), e un exit qui chiuderebbe solo la subshell lasciando il menu a
    # girare a vuoto. $$ resta il PID della shell principale anche in subshell.
    if ! read -r _sel; then
      printf '\n  No input available (stdin closed) — aborted.\n' >&2
      kill -TERM $$
      exit 1
    fi
    _sel="${_sel:-1}"
    if [[ "$_sel" =~ ^[0-9]+$ ]] && [ "$_sel" -ge 1 ] && [ "$_sel" -le "${#_opts[@]}" ]; then
      printf '%s' "$_sel"
      return
    fi
    printf '  Invalid choice.\n' >&2
  done
}

_sep() { printf '\n  %-44s\n' "── $1 " | tr ' ' '─' | head -c 48; printf '\n' >&2; }

# ── JSON helpers (python3 di sistema, non serve il venv) ──────────────────────

_json_read() {
  # _json_read section key
  python3 -c "
import json, pathlib
d = {}
p = pathlib.Path('$CONFIG_FILE')
if p.exists():
    try: d = json.loads(p.read_text())
    except Exception: pass
print(d.get('$1', {}).get('$2', ''))
"
}

_json_write() {
  # _json_write section.key=value ...
  python3 - "$@" <<'PYEOF'
import json, sys, pathlib

CONFIG = pathlib.Path("config.json")
DEFAULTS = {
    "search_engine": {
        "provider": "duckduckgo", "serper_api_key": "",
        "min_osint_hits": 2, "min_osint_query": 4,
    },
    "ai": {
        "provider": "ollama",
        "ollama_url": "http://localhost:11434/api/generate",
        "ollama_model": "qwen2.5:7b", "ollama_autoinstall": True,
        "claude_api_key": "", "claude_model": "claude-haiku-4-5-20251001",
        "summary_timeout": 60, "advisory_timeout": 60,
        "extract_timeout": 30, "remediation_timeout": 30,
        "triage_timeout": 60, "ai_remediation": False,
    },
    "scanner": {"simulate_auth": True, "socket_timeout": 4},
    "osv": {"url": "https://api.osv.dev/v1/query", "timeout": 15},
    "agent": {"license_key": "", "summary_timeout": 180},
}
# Si parte da cio' che c'e' su disco, non dai DEFAULTS: config.py ha sezioni
# che questo script non conosce (nvd, msrc, ticketing, smtp, auth, sla) e
# ricostruire il file dai soli DEFAULTS le cancellerebbe, credenziali SMTP e
# politica password comprese.
data = {}
if CONFIG.exists():
    try:
        loaded = json.loads(CONFIG.read_text())
        if isinstance(loaded, dict):
            data = loaded
    except Exception:
        pass
for sec, defaults in DEFAULTS.items():
    merged = dict(defaults)
    merged.update(data.get(sec) or {})
    data[sec] = merged

for arg in sys.argv[1:]:
    sec, rest = arg.split(".", 1)
    key, val  = rest.split("=", 1)
    if val.lower() in ("true", "false"):
        val = val.lower() == "true"
    else:
        try:    val = int(val)
        except ValueError:
            try: val = float(val)
            except ValueError: pass
    data.setdefault(sec, {})[key] = val

CONFIG.write_text(json.dumps(data, indent=2, ensure_ascii=False))
PYEOF
}

# ── Wizard: AI ────────────────────────────────────────────────────────────────

_wizard_ai() {
  _sep "AI Configuration" >&2
  local _c
  _c=$(_choose "AI model type:" \
    "Local  — Ollama (model runs on your machine)" \
    "Remote — Claude API (Anthropic, requires API key)")

  if [ "$_c" = "1" ]; then
    local _url _model _install=1
    _url=$(_ask "Ollama URL" "http://localhost:11434/api/generate")

    # scelta modello LLM: default qwen2.5:7b, alternative comuni o nome libero
    local _mc
    _mc=$(_choose "Which LLM model to use? (default: qwen2.5:7b)" \
      "qwen2.5:7b   — Qwen 2.5 7B (recommended, ~4.7 GB)" \
      "llama3.1:8b  — Meta Llama 3.1 8B (~4.9 GB)" \
      "mistral:7b   — Mistral 7B (~4.1 GB)" \
      "Other        — enter the model name (e.g. gemma2:9b)")
    case "$_mc" in
      1) _model="qwen2.5:7b"  ;;
      2) _model="llama3.1:8b" ;;
      3) _model="mistral:7b"  ;;
      4) _model=$(_ask "Ollama model name" "qwen2.5:7b") ;;
    esac

    # se URL locale e ollama assente: chiedi se installarlo
    case "$_url" in
      *localhost*|*127.0.0.1*)
        if ! command -v ollama >/dev/null 2>&1; then
          local _yn
          _yn=$(_ask "Ollama is not installed. Install it now? (y/n)" "y")
          case "$_yn" in
            s|S|y|Y) _install=1 ;;
            *)       _install=0
                     printf '  ⚠  Installation skipped — AI features inactive while Ollama is missing.\n' >&2 ;;
          esac
        fi
        ;;
    esac

    local _auto="false"; [ "$_install" = "1" ] && _auto="true"
    _json_write "ai.provider=ollama" "ai.ollama_url=$_url" \
                "ai.ollama_model=$_model" "ai.ollama_autoinstall=$_auto"
    printf '  ✓  Provider: Ollama (%s)\n' "$_model" >&2
    _ensure_ollama "$_url" "$_model" "$_install"
  else
    local _key _model
    _key=$(_ask_secret "Claude API Key")
    _model=$(_ask "Claude model" "claude-haiku-4-5-20251001")
    _json_write "ai.provider=claude" "ai.claude_api_key=$_key" "ai.claude_model=$_model"
    printf '  ✓  Provider: Claude API (%s)\n' "$_model" >&2
  fi
}

# ── Wizard: Search Engine ─────────────────────────────────────────────────────

_wizard_search() {
  _sep "Search Engine Configuration" >&2
  local _c
  _c=$(_choose "OSINT search engine:" \
    "DuckDuckGo — free, no API key" \
    "Serper     — Google results, requires API key")

  if [ "$_c" = "1" ]; then
    _json_write "search_engine.provider=duckduckgo"
    printf '  ✓  Search engine: DuckDuckGo\n' >&2
  else
    local _key
    _key=$(_ask_secret "Serper API Key")
    _json_write "search_engine.provider=serper" "search_engine.serper_api_key=$_key"
    printf '  ✓  Search engine: Serper\n' >&2
  fi
}

# ── Helper: aggiunta asset all'inventario Supabase (cifrata/chiaro/no) ────────

_add_to_assets() {
  # _add_to_assets IP OSTYPE OSVER
  local _ip="$1" _os="$2" _osver="$3"
  local _add
  _add=$(_choose "Add to asset inventory?" \
    "Yes — add with encrypted credentials" \
    "Yes — add with plaintext password" \
    "No")
  [ "$_add" = "3" ] && return
  local _stored_pw="admin"
  if [ "$_add" = "1" ]; then
    if [ -x "${ENCDEC_BIN:-}" ]; then
      local _enc
      _enc=$("$ENCDEC_BIN" ENC "admin" 2>/dev/null | sed 's/^encrypted : //')
      if [ -n "$_enc" ]; then
        _stored_pw="ENC:$_enc"
      else
        printf '  ⚠  Encryption failed — password stored in plaintext.\n' >&2
      fi
    else
      printf '  ⚠  Encryption not configured (encdec) — password stored in plaintext.\n' >&2
    fi
  fi
  # Inserimento nella tabella 'assets' via PostgREST (Supabase locale).
  local _sb_url="${SUPABASE_URL:-http://localhost:8001}"
  local _sb_key="${SUPABASE_SERVICE_KEY:-}"
  if [ -z "$_sb_key" ] && [ -f supabase/.env ]; then
    _sb_key=$(grep -m1 '^SERVICE_ROLE_KEY=' supabase/.env | cut -d= -f2-)
  fi
  local _payload
  _payload=$(printf '{"ip":"%s","username":"admin","password":"%s","os_type":"%s","os_major_version":"%s","enabled":true}' \
    "$_ip" "$_stored_pw" "$_os" "$_osver")
  if curl -sf -X POST "$_sb_url/rest/v1/assets" \
       -H "apikey: $_sb_key" -H "Authorization: Bearer $_sb_key" \
       -H "Content-Type: application/json" \
       -d "$_payload" >/dev/null 2>&1; then
    printf '  ✓  Added to inventory (Supabase): %s (os=%s)\n' "$_ip" "$_os" >&2
  else
    printf '  ⚠  Supabase not reachable — asset NOT added: %s\n' "$_ip" >&2
  fi
}

# ── Wizard: scelta macchina di test (Linux | Windows) ─────────────────────────

_wizard_test_machine() {
  _sep "Test machine (Docker)" >&2
  if ! docker info >/dev/null 2>&1; then
    printf '  ⚠  Docker not running — wizard skipped.\n' >&2
    return
  fi
  local _c
  _c=$(_choose "Which test machine do you want to create?" \
    "Linux   — Ubuntu 20.04 + SSH + Python 3.6 (outdated)" \
    "Windows — Win 11 (KVM) + Notepad++ 7.8.1 + PuTTY 0.70 (vulnerable)" \
    "None    — skip")
  case "$_c" in
    1) _wizard_test_machine_linux   ;;
    2) _wizard_test_machine_windows ;;
    *) return ;;
  esac
}

# ── Wizard: macchina Linux Docker di test ────────────────────────────────────

_wizard_test_machine_linux() {
  _sep "Linux test machine (Docker)" >&2

  local _dir="$PWD/docker-test-machine"
  mkdir -p "$_dir"

  cat > "$_dir/Dockerfile" << 'DOCKEREOF'
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server sudo software-properties-common gnupg binutils && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && apt-get install -y python3.6 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash admin && \
    echo 'admin:admin' | chpasswd && \
    adduser admin sudo

RUN mkdir /var/run/sshd && \
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
DOCKEREOF

  printf '\n  ==> building vuln-test-linux image (ubuntu:20.04 + python3.6 + sshd)...\n' >&2
  docker build -t vuln-test-linux "$_dir" >&2 || {
    printf '  ERROR: image build failed.\n' >&2; return
  }

  docker rm -f vuln-test-linux-1 >/dev/null 2>&1 || true

  printf '  ==> starting container vuln-test-linux-1...\n' >&2
  docker run -d --name vuln-test-linux-1 vuln-test-linux </dev/null >/dev/null || {
    printf '  ERROR: container start failed.\n' >&2; return
  }

  sleep 1
  local _ip
  _ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vuln-test-linux-1 2>/dev/null)

  printf '\n  ✓  Container started\n' >&2
  printf '     IP  : %s\n' "$_ip" >&2
  printf '     SSH : ssh admin@%s  (password: admin)\n' "$_ip" >&2
  printf '     Test: ssh admin@%s python3.6 --version\n\n' "$_ip" >&2

  if [ -n "$_ip" ]; then
    _add_to_assets "$_ip" linux ""
  fi
}

# ── Guida: abilitare la virtualizzazione (SVM/VT-x) nel BIOS/UEFI ────────────
# Stampata SOLO quando KVM non e' attivo (vedi _wizard_test_machine_windows).

_bios_virt_help() {
  local _vendor="${1:-VT-x / AMD-V}"
  printf '\n  >> Enable virtualization in BIOS/UEFI (%s):\n' "$_vendor" >&2
  printf '     1. FULLY restart the PC (not suspend).\n' >&2
  printf '     2. At power-on press F2 (Lenovo: F2 or Fn+F2; alternatively the\n' >&2
  printf '        "Novo" pinhole/button -> "BIOS Setup").\n' >&2
  printf '     3. Go to "Configuration" (or "Advanced").\n' >&2
  printf '     4. Set "SVM Mode" (alias: AMD-V / Virtualization / VT-x) = Enabled.\n' >&2
  printf '     5. F10 -> Save and Exit -> confirm. Let the system restart.\n\n' >&2
}

# ── Wizard: macchina Windows di test (Docker + KVM, dockurr/windows) ──────────
# Windows non gira come container nativo su Linux: si usa dockurr/windows, che
# avvia una VM Windows via QEMU/KVM dentro un container. Richiede /dev/kvm.
# La VM espone SSH (OpenSSH) per la scansione autenticata PowerShell e installa
# versioni vulnerabili di Notepad++ e PuTTY tramite gli script in ./oem.

_wizard_test_machine_windows() {
  _sep "Windows test machine (Docker + KVM)" >&2

  # KVM non attivo -> la VM Windows non puo' partire. Mostra una guida coerente
  # (compresa l'abilitazione della virtualizzazione nel BIOS) SOLO in questo caso.
  if [ ! -e /dev/kvm ]; then
    local _mod="kvm_intel" _vendor="VT-x"
    if grep -qi "AuthenticAMD" /proc/cpuinfo; then _mod="kvm_amd"; _vendor="AMD-V (SVM)"; fi

    printf '  ⚠  KVM not active: /dev/kvm missing. The Windows VM cannot start.\n' >&2
    printf '     (Native Windows nanoserver/servercore does NOT run on a Linux Docker host;\n' >&2
    printf '      a real VM via QEMU/KVM is required, which needs HW virtualization.)\n\n' >&2

    if ! grep -qiE "vmx|svm" /proc/cpuinfo; then
      # Caso A: nessun flag -> virtualizzazione spenta a livello BIOS.
      printf '  The CPU exposes no virtualization flag: it is DISABLED in the BIOS.\n' >&2
      _bios_virt_help "$_vendor"
    else
      # Caso B: flag presente ma /dev/kvm assente -> modulo non caricato OPPURE
      # virtualizzazione bloccata/lockata nel BIOS (modprobe: "Operation not supported").
      printf '  Step 1 — load the KVM module:\n' >&2
      printf '       sudo modprobe %s\n' "$_mod" >&2
      printf '       ls -l /dev/kvm                 # must appear\n\n' >&2
      printf '  If "modprobe" says "Operation not supported", virtualization is\n' >&2
      printf '  locked in the BIOS (flag visible but SVM/VT-x locked): enable it.\n' >&2
      _bios_virt_help "$_vendor"
      printf '  Step 2 — make it persistent and grant permissions:\n' >&2
      printf '       echo "%s" | sudo tee /etc/modules-load.d/kvm.conf\n' "$_mod" >&2
      printf '       sudo usermod -aG kvm "$USER"   # then logout/login\n\n' >&2
    fi

    printf '  Then retry:  ./start.sh update  ->  3  ->  2 (Windows)\n' >&2
    printf '  Alternatively, without BIOS: software emulation (slow) by setting\n' >&2
    printf '  KVM:"N" in the compose file, or an external Windows host (see README).\n' >&2
    return
  fi

  local _dir="$PWD/docker-test-machine-windows"
  mkdir -p "$_dir/oem"

  # docker-compose: VM Windows 11, utente admin/admin, SSH (22) e RDP (3389).
  cat > "$_dir/compose.yml" << 'COMPOSEEOF'
services:
  windows:
    image: dockurr/windows
    container_name: vuln-test-windows-1
    environment:
      VERSION: "11"
      USERNAME: "admin"
      PASSWORD: "admin"
      RAM_SIZE: "4G"
      CPU_CORES: "2"
    devices:
      - /dev/kvm
      - /dev/net/tun
    cap_add:
      - NET_ADMIN
    ports:
      - "8006:8006/tcp"   # viewer web installazione dockurr
      - "3389:3389/tcp"   # RDP
      - "2222:22/tcp"     # SSH (host:2222 -> guest:22)
    volumes:
      - ./storage:/storage
      - ./oem:/oem        # script eseguiti al primo boot di Windows
    stop_grace_period: 2m
    restart: on-failure
COMPOSEEOF

  # Script post-install (eseguito da dockurr al primo boot): abilita OpenSSH con
  # shell PowerShell e installa Notepad++ 7.8.1 + PuTTY 0.70 (vulnerabili).
  cat > "$_dir/oem/install.bat" << 'BATEOF'
@echo off
REM --- OpenSSH Server con shell PowerShell (per winget / Get-ItemProperty) ---
powershell -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
powershell -Command "Set-Service -Name sshd -StartupType Automatic; Start-Service sshd"
powershell -Command "New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22"
powershell -Command "New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force"

REM --- Notepad++ 7.8.1 (vulnerabile) ---
powershell -Command "Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v7.8.1/npp.7.8.1.Installer.x64.exe' -OutFile C:\npp.exe"
C:\npp.exe /S

REM --- PuTTY 0.70 (vulnerabile) ---
powershell -Command "Invoke-WebRequest -UseBasicParsing -Uri 'https://the.earth.li/~sgtatham/putty/0.70/w64/putty-64bit-0.70-installer.msi' -OutFile C:\putty.msi"
msiexec /i C:\putty.msi /quiet /norestart
BATEOF

  docker rm -f vuln-test-windows-1 >/dev/null 2>&1 || true

  printf '\n  ==> starting Windows VM (dockurr/windows). The first boot downloads and\n' >&2
  printf '      installs Windows: it may take quite a few minutes.\n' >&2
  ( cd "$_dir" && docker compose up -d ) </dev/null >&2 || {
    printf '  ERROR: Windows container start failed.\n' >&2; return
  }

  sleep 2
  local _ip
  _ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vuln-test-windows-1 2>/dev/null)

  printf '\n  ✓  Windows container started (installation in progress)\n' >&2
  printf '     IP   : %s\n' "$_ip" >&2
  printf '     RDP  : localhost:3389        (admin / admin)\n' >&2
  printf '     SSH  : ssh admin@%s     (password: admin, after install)\n' "$_ip" >&2
  printf '     Web  : http://localhost:8006 (dockurr install viewer)\n\n' >&2
  printf '  Note: authenticated scanning only works once installation completes\n' >&2
  printf '        (OpenSSH active + Notepad++/PuTTY installed).\n' >&2

  if [ -n "$_ip" ]; then
    _add_to_assets "$_ip" windows 11
  fi
}

# ── Aggiornamento applicazione (check tag GitHub + download sorgenti) ────────

GITHUB_REPO="${VFA_GITHUB_REPO:-daniloritarossi/vul.scan.o}"

_local_version() {
  # Tag base locale: 'v1.0.11-alfa-3-gabc' -> 'v1.0.11-alfa'.
  # Senza git (installazione da zip/tarball) si legge .vfa_version, scritto da
  # _download_update; 'dev' solo se non si sa davvero nulla.
  local _v
  _v=$(git describe --tags --always 2>/dev/null | sed -E 's/-[0-9]+-g[0-9a-f]+$//')
  if [ -z "$_v" ] && [ -f .vfa_version ]; then
    _v=$(tr -d '[:space:]' < .vfa_version)
  fi
  printf '%s' "${_v:-dev}"
}

_latest_version() {
  # Ultima RELEASE pubblicata su GitHub. Vuoto se irraggiungibile o se non ne
  # esiste nessuna.
  #
  # Si guardano le release, non i tag: un tag puo' esistere senza release e
  # proporlo come aggiornamento manderebbe l'utente su una versione che nessuno
  # ha pubblicato. Non si usa /releases/latest perche' ESCLUDE le prerelease, e
  # qui si pubblicano solo '-beta': risponderebbe 404 nascondendo tutto.
  curl -fsS --max-time 8 \
    -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/${GITHUB_REPO}/releases?per_page=30" 2>/dev/null \
  | python3 -c "
import json, re, sys
try:
    rels = json.load(sys.stdin)
except Exception:
    sys.exit(0)
def ver(t):
    m = re.match(r'v?(\d+)\.(\d+)(?:\.(\d+))?', t or '')
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None
# draft escluse (non pubbliche); a parita' di versione, stabile > prerelease.
parsed = [((ver(r.get('tag_name')), 0 if r.get('prerelease') else 1), r.get('tag_name'))
          for r in rels if not r.get('draft') and ver(r.get('tag_name'))]
if parsed:
    print(max(parsed)[1])
"
}

_download_update() {
  # Scarica i sorgenti del tag indicato e li applica alla directory corrente.
  # Preferisce git (storia + rollback); fallback tarball GitHub se .git assente.
  # I file runtime (config.json, .venv, .encdec, segreti, dati Supabase) NON
  # vengono toccati in entrambi i percorsi.
  local _tag="$1"
  if [ -d .git ]; then
    printf '  ==> git fetch --tags && checkout %s\n' "$_tag" >&2
    if ! git diff --quiet 2>/dev/null; then
      printf '  WARNING: uncommitted local changes. Update cancelled.\n' >&2
      printf '  Commit or discard the changes, then retry.\n' >&2
      return 1
    fi
    git fetch --tags origin >&2 || { printf '  ERROR: git fetch failed.\n' >&2; return 1; }
    git checkout "$_tag" >&2 || { printf '  ERROR: checkout %s failed.\n' "$_tag" >&2; return 1; }
  else
    printf '  ==> downloading tarball %s from GitHub...\n' "$_tag" >&2
    local _tmp
    _tmp=$(mktemp -d)
    if ! curl -fsSL --max-time 120 \
        "https://github.com/${GITHUB_REPO}/archive/refs/tags/${_tag}.tar.gz" \
        -o "$_tmp/src.tar.gz"; then
      printf '  ERROR: download failed.\n' >&2; rm -rf "$_tmp"; return 1
    fi
    tar -xzf "$_tmp/src.tar.gz" -C "$_tmp" || { rm -rf "$_tmp"; return 1; }
    local _srcdir
    _srcdir=$(find "$_tmp" -maxdepth 1 -mindepth 1 -type d | head -1)
    printf '  ==> applying sources (runtime files preserved)...\n' >&2
    rsync -a \
      --exclude 'config.json' \
      --exclude '.venv/' \
      --exclude '.encdec/' \
      --exclude '.vfa_auth_secret' \
      --exclude 'assets.txt*' \
      --exclude 'supabase/volumes/db/data/' \
      --exclude '*.log' --exclude '*.pid' \
      "$_srcdir/" ./ || { rm -rf "$_tmp"; return 1; }
    rm -rf "$_tmp"
    # Il tarball non porta la storia git: senza questo file l'installazione non
    # saprebbe piu' quale versione sta eseguendo e il check aggiornamenti
    # resterebbe cieco per sempre.
    printf '%s\n' "$_tag" > .vfa_version
  fi
  return 0
}

_version_newer() {
  # 0 (vero) se $2 e' numericamente piu' recente di $1. Confronto numerico, non
  # fra stringhe: due versioni diverse non implicano che la remota sia piu'
  # nuova (un repo di sviluppo puo' stare AVANTI all'ultima release, e proporre
  # il "downgrade" come aggiornamento sarebbe sbagliato).
  python3 - "$1" "$2" <<'PY'
import re, sys
def ver(t):
    m = re.match(r'v?(\d+)\.(\d+)(?:\.(\d+))?', t or '')
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None
cur, new = ver(sys.argv[1]), ver(sys.argv[2])
sys.exit(0 if (cur and new and new > cur) else 1)
PY
}

_check_app_update() {
  _sep "Update Check" >&2
  local _cur _new
  _cur=$(_local_version)
  printf '  Local version   : %s\n' "$_cur" >&2
  printf '  Checking GitHub (%s)...\n' "$GITHUB_REPO" >&2
  _new=$(_latest_version)
  if [ -z "$_new" ]; then
    printf '  GitHub unreachable or no published release found.\n' >&2
    return
  fi
  printf '  Latest release  : %s\n' "$_new" >&2
  if [ "$_new" = "$_cur" ]; then
    printf '\n  ✓ You are already on the latest release.\n' >&2
    return
  fi
  if ! _version_newer "$_cur" "$_new"; then
    if [ "$_cur" = "dev" ]; then
      printf '\n  Local version unknown (no git tag, no .vfa_version):\n' >&2
      printf '  cannot tell whether %s is newer. Nothing done.\n' "$_new" >&2
    else
      printf '\n  ✓ Local version %s is ahead of the latest release (%s).\n' "$_cur" "$_new" >&2
    fi
    return
  fi
  printf '\n  New release available: %s -> %s\n' "$_cur" "$_new" >&2
  local _ok
  _ok=$(_ask "Download and install now? (y/n)" "y")
  case "$_ok" in
    s|S|y|Y)
      if _download_update "$_new"; then
        printf '\n  ✓ Updated to %s.\n' "$_new" >&2
        printf '  Relaunch with ./start.sh to apply (dependencies and DB schema\n' >&2
        printf '  are realigned automatically at startup).\n' >&2
      fi
      ;;
    *) printf '  Update cancelled.\n' >&2 ;;
  esac
}

# ── Add-on di analisi (vfa-agent) ─────────────────────────────────────────────
# Modulo proprietario opzionale. Il core funziona senza: il gancio in app.py
# inghiotte l'ImportError e non succede nulla.
#
# Ordine: prima la chiave, poi il pacchetto — la licenza e' il cancello. Ma il
# verificatore sta DENTRO il pacchetto (chiave pubblica Ed25519 in
# vfa_agent/license.py) e non puo' girare prima dell'installazione. Quindi:
# si installa, si verifica, e se la chiave non regge il pacchetto viene
# disinstallato completamente e config.json non viene mai toccato.
#
# Installare per verificare non espone nulla: senza chiave valida il pacchetto
# e' inerte — nessuna voce di menu (license_active() e' False) e le rotte di
# analisi rispondono 402.

AGENT_PKG="vfa-agent"
AGENT_MOD="vfa_agent"
AGENT_PY=".venv/bin/python"

_agent_venv() {
  # La fase di configurazione gira prima del blocco che crea il virtualenv per
  # l'avvio: qui lo si crea se manca. Le dipendenze del core arrivano dopo, non
  # servono a verificare una licenza.
  [ -x "$AGENT_PY" ] && return 0
  printf '  Creating virtualenv .venv ...\n' >&2
  python3 -m venv .venv >/dev/null 2>&1 || {
    printf '  ✗  Could not create .venv — install python3-venv and retry.\n' >&2
    return 1
  }
}

_agent_installed() {
  [ -x "$AGENT_PY" ] || return 1
  "$AGENT_PY" -c "import importlib.util, sys
sys.exit(0 if importlib.util.find_spec('$AGENT_MOD') else 1)" 2>/dev/null
}

_agent_version() {
  # Versione della distribuzione installata, non $AGENT_MOD.__version__: il
  # secondo e' una stringa scritta a mano in __init__.py e puo' non essere
  # stata aggiornata insieme al pyproject. Chiedendolo al modulo, un
  # aggiornamento riuscito si legge come "versione invariata".
  "$AGENT_PY" -c "
try:
    from importlib.metadata import version
    print(version('$AGENT_PKG'))
except Exception:
    import $AGENT_MOD
    print(getattr($AGENT_MOD, '__version__', '?'))" 2>/dev/null
}

_agent_license_check() {
  # Chiave di licenza su stdin (non in argv: non deve comparire in 'ps').
  # Stampa: state|customer|plan|expires|days_left|max_assets
  "$AGENT_PY" -c '
import sys
# stdin va letto per primo anche quando il modulo manca: uscire prima chiude la
# pipe sotto il naso di chi la scrive, che muore con un BrokenPipeError a video.
key = sys.stdin.read().strip()
try:
    from vfa_agent.license import evaluate
except Exception:
    print("unavailable|||||")
    raise SystemExit(0)
s = evaluate(key)
print("|".join([s.state, s.customer or "", s.plan or "",
                s.expires.isoformat() if s.expires else "",
                "" if s.days_left is None else str(s.days_left),
                "" if s.max_assets is None else str(s.max_assets)]))
' 2>/dev/null
}

_agent_asset_count() {
  # Quanti asset ha l'inventario: "righe|abilitati|host_distinti", niente se non
  # si riesce a leggerlo.
  #
  # Passa da PostgREST con SUPABASE_URL e la service key, cioe' dalla stessa
  # strada che usa l'applicazione (db.py). Contare dal container locale darebbe
  # il numero di un altro database quando SUPABASE_URL punta altrove: un tetto
  # di licenza verificato sull'inventario sbagliato.
  local _url _key
  _url=$(_agent_sb_url)
  _key=$(_agent_sb_key)
  [ -n "$_key" ] || return 1
  curl -sf --max-time 10 "$_url/rest/v1/assets?select=ip,enabled" \
    -H "apikey: $_key" -H "Authorization: Bearer $_key" 2>/dev/null \
  | python3 -c "
import json, sys
try:
    rows = json.load(sys.stdin)
except Exception:
    raise SystemExit(1)
if not isinstance(rows, list):
    raise SystemExit(1)
print('%d|%d|%d' % (len(rows),
                    sum(1 for r in rows if r.get('enabled')),
                    len({r.get('ip') for r in rows})))"
}

_agent_capacity_report() {
  # _agent_capacity_report MAX_ASSETS → stampa il confronto fra tetto di licenza
  # e inventario. rc=1 solo se il tetto e' superato.
  local _max="$1" _counts _rows _en _hosts
  _counts=$(_agent_asset_count) || {
    printf '  Assets   : not counted — %s did not answer\n' "$(_agent_sb_url)" >&2
    return 0
  }
  IFS='|' read -r _rows _en _hosts <<< "$_counts"
  if [ -z "$_max" ]; then
    printf '  Assets   : %s hosts in inventory (licence declares no cap)\n' "${_hosts:-?}" >&2
    return 0
  fi
  # Si contano gli host distinti, non le righe: lo stesso host inserito due
  # volte e' un errore di inventario, non un asset in piu' da pagare. Gli asset
  # disabilitati contano comunque: restano nell'inventario e disabilitarli alla
  # vigilia di un controllo renderebbe il tetto una formalita'.
  printf '  Assets   : %s of %s hosts (%s rows, %s enabled)\n' \
    "${_hosts:-?}" "$_max" "${_rows:-?}" "${_en:-?}" >&2
  if [ -n "$_hosts" ] && [ "$_hosts" -gt "$_max" ] 2>/dev/null; then
    printf '  ⚠  Over the licensed cap by %s hosts.\n' "$((_hosts - _max))" >&2
    return 1
  fi
  return 0
}

_agent_license_explain() {
  # _agent_license_explain STATE → una riga di spiegazione su stderr
  case "$1" in
    active) printf '  ✓  Licence valid.\n' >&2 ;;
    grace)  printf '  ✓  Licence expired but within the %s-day tolerance — renew soon.\n' "14" >&2 ;;
    expired)printf '  ✗  Licence expired beyond the tolerance window.\n' >&2 ;;
    invalid)printf '  ✗  Signature does not verify: key altered, truncated or not issued for this product.\n' >&2 ;;
    missing)printf '  ✗  No licence key.\n' >&2 ;;
    unavailable) printf '  ✗  Verifier not importable — package broken or dependencies missing.\n' >&2 ;;
    *)      printf '  ✗  Unknown licence state: %s\n' "$1" >&2 ;;
  esac
}

_agent_status_line() {
  if ! _agent_installed; then printf 'not installed'; return; fi
  local _v _res
  _v=$(_agent_version)
  _res=$(_json_read agent license_key | _agent_license_check)
  printf 'installed %s — licence: %s' "${_v:-?}" "${_res%%|*}"
}

AGENT_SOURCE_FILE=".agent_source"

_agent_remember_source() {
  # Da dove e' arrivato il pacchetto l'ultima volta. Non va in config.json:
  # e' stato dell'installatore, non configurazione dell'applicazione, e non
  # deve comparire fra le impostazioni che l'utente vede nella UI.
  local _p="$1"
  # Path assoluto: il menu si apre dalla radice del progetto, ma un path
  # relativo salvato oggi puo' non valere piu' domani.
  case "$_p" in
    /*) ;;
    *) _p="$(cd "$(dirname "$_p")" 2>/dev/null && pwd)/$(basename "$_p")" || return 0 ;;
  esac
  printf '%s\n' "$_p" > "$AGENT_SOURCE_FILE" 2>/dev/null || true
}

_agent_default_source() {
  # Il default proposto dal prompt, nell'ordine: cio' che ha funzionato
  # l'ultima volta, poi il wheel piu' recente della cartella sorella, poi la
  # cartella sorella stessa.
  local _saved _whl
  if [ -f "$AGENT_SOURCE_FILE" ]; then
    _saved=$(head -n1 "$AGENT_SOURCE_FILE")
    if [ -n "$_saved" ] && [ -e "$_saved" ]; then
      printf '%s' "$_saved"
      return
    fi
  fi
  # Il wheel, non il sorgente: 'pip install ../vfa-agent' compila dal codice,
  # che sulla macchina di un cliente non c'e'.
  _whl=$(ls -t ../vfa-agent/dist/*.whl 2>/dev/null | head -n1)
  if [ -n "$_whl" ]; then
    printf '%s' "$_whl"
    return
  fi
  [ -d ../vfa-agent ] && printf '%s' "../vfa-agent"
}

_agent_pip_run() {
  # pip silenzioso, ma l'errore per intero quando fallisce: "installation
  # failed" senza il motivo manda chi installa a indovinare.
  local _out
  if ! _out=$("$AGENT_PY" -m pip install "$@" 2>&1); then
    printf '\n' >&2
    printf '%s\n' "$_out" | tail -n 15 >&2
    printf '\n' >&2
    return 1
  fi
}

_agent_pip_install() {
  # _agent_pip_install PATH [flag pip aggiuntivi...] → installa da wheel,
  # sorgente o wheelhouse.
  # --find-links sulla cartella indicata: su una macchina senza rete (il caso
  # normale dal cliente) le dipendenze, PyNaCl in testa, devono stare li'
  # accanto. Nessun download di codice a runtime, mai.
  local _path="$1"; shift
  local _extra=("$@") _dir
  # ${a[@]+"${a[@]}"}: un array vuoto sotto 'set -u' non deve diventare un
  # argomento vuoto ne' far fallire l'espansione.
  if [ -f "$_path" ]; then
    case "$_path" in
      *.whl|*.tar.gz) ;;
      *) printf '  ✗  Not a package file (.whl or .tar.gz): %s\n' "$_path" >&2; return 1 ;;
    esac
    _dir=$(dirname "$_path")
    _agent_pip_run --upgrade ${_extra[@]+"${_extra[@]}"} --find-links "$_dir" "$_path"
  elif [ -d "$_path" ]; then
    if [ -f "$_path/pyproject.toml" ]; then
      # cartella del sorgente
      [ -d "$_path/dist" ] && _dir="$_path/dist" || _dir="$_path"
      _agent_pip_run --upgrade ${_extra[@]+"${_extra[@]}"} --find-links "$_dir" "$_path"
    elif ls "$_path"/*.whl >/dev/null 2>&1; then
      # wheelhouse: tutto in locale, niente indice remoto
      _agent_pip_run --upgrade ${_extra[@]+"${_extra[@]}"} --no-index --find-links "$_path" "$AGENT_PKG"
    else
      printf '  ✗  No pyproject.toml and no .whl in: %s\n' "$_path" >&2
      return 1
    fi
  else
    printf '  ✗  Path not found: %s\n' "$_path" >&2
    return 1
  fi
}

_agent_pip_uninstall() {
  "$AGENT_PY" -m pip uninstall -y "$AGENT_PKG" >/dev/null 2>&1
  # Il wheel installa il package, ma un 'pip install -e' lascia il .pth: se il
  # modulo si importa ancora, la disinstallazione non e' completa e va detto.
  if _agent_installed; then
    printf '  ⚠  %s still importable after uninstall (editable install?).\n' "$AGENT_MOD" >&2
    return 1
  fi
}

# L'applicazione non usa psql: parla HTTP con PostgREST all'indirizzo
# SUPABASE_URL (db.py). Le migrazioni invece hanno bisogno di SQL, e l'unica
# via SQL che questo script ha e' il container Postgres dello stack locale.
# Due strade diverse verso quello che deve essere lo stesso database: tutto
# cio' che segue serve a non dare per scontato che lo sia.

_agent_sb_url() { printf '%s' "${SUPABASE_URL:-http://localhost:8001}"; }

_agent_sb_key() {
  local _k="${SUPABASE_SERVICE_KEY:-}"
  if [ -z "$_k" ] && [ -f supabase/.env ]; then
    _k=$(grep -m1 '^SERVICE_ROLE_KEY=' supabase/.env | cut -d= -f2-)
  fi
  printf '%s' "$_k"
}

_agent_db_is_local() {
  case "$(_agent_sb_url)" in
    *localhost*|*127.0.0.1*|*'[::1]'*) return 0 ;;
    *) return 1 ;;
  esac
}

_agent_pg() {
  # SQL nel container dello stack locale. </dev/null dove non si passa un file:
  # 'docker compose exec' si porta via tutto lo stdin bufferizzato anche quando
  # il comando non lo legge, e dentro un menu vuol dire mangiarsi le risposte
  # successive di chi sta rispondendo.
  [ -d supabase ] || return 1
  ( cd supabase && docker compose exec -T db psql -tAqX -U postgres -d postgres "$@" ) \
    </dev/null 2>/dev/null
}

_agent_db_target() {
  # Con chi si puo' applicare lo schema dell'add-on:
  #   local    container locale, e dentro c'e' lo schema del core
  #   remote   SUPABASE_URL punta altrove: psql non e' la strada
  #   foreign  un Postgres c'e', ma non e' il database dell'applicazione
  #   down     nessun Postgres raggiungibile
  if ! _agent_db_is_local; then printf 'remote'; return; fi
  if ! ( cd supabase && docker compose exec -T db pg_isready -U postgres -d postgres ) \
         </dev/null >/dev/null 2>&1; then
    printf 'down'; return
  fi
  # Prova d'identita' povera ma efficace: il database dell'applicazione ha le
  # sue tabelle. Intercetta il container di un altro progetto, o uno vuoto.
  local _n
  _n=$(_agent_pg -c "select count(*) from pg_tables
                      where schemaname='public' and tablename in ('assets','findings')" \
       | tr -d '\r' | head -n1)
  [ "$_n" = "2" ] && printf 'local' || printf 'foreign'
}

_agent_manual_migration_note() {
  # Quando le migrazioni non si possono applicare da qui, l'unica cosa utile e'
  # dire esattamente cosa deve fare una persona. Una spunta verde falsa e'
  # peggio di nessuna spunta.
  local _dir="$1" _f
  printf '  Apply these to the database the application uses, in order:\n' >&2
  for _f in "$_dir"/*.sql; do
    [ -f "$_f" ] && printf '    %s\n' "$_f" >&2
  done
  printf "    then:  notify pgrst, 'reload schema';\n" >&2
  printf '  Until then the Agent pages fail on tables that do not exist.\n' >&2
}

_agent_db_ready() {
  # Compatibilita' con i chiamanti che vogliono solo sapere se si puo' scrivere.
  [ "$(_agent_db_target)" = "local" ]
}

_agent_migrate() {
  # Migrazioni dell'add-on: separate da quelle del core, da applicare in
  # ordine. Tutte con IF NOT EXISTS, quindi rilanciabili a ogni avvio come fa
  # supabase/setup.sh con lo schema del core.
  _agent_installed || return 0
  local _dir
  _dir=$("$AGENT_PY" -c "import $AGENT_MOD, pathlib
print(pathlib.Path($AGENT_MOD.__file__).parent / 'migrations')" 2>/dev/null) || return 0
  [ -d "$_dir" ] || return 0

  case "$(_agent_db_target)" in
    local) ;;
    remote)
      printf '  ⚠  The application uses a database this script cannot reach with SQL:\n' >&2
      printf '       SUPABASE_URL = %s\n' "$(_agent_sb_url)" >&2
      printf '     Migrations are NOT applied from here.\n' >&2
      _agent_manual_migration_note "$_dir"
      return 1
      ;;
    foreign)
      printf '  ⚠  A local Postgres is running but it is not this application'"'"'s database\n' >&2
      printf '     (no assets/findings tables in it). Nothing was written to it.\n' >&2
      _agent_manual_migration_note "$_dir"
      return 1
      ;;
    down)
      printf '  ⚠  Local database not running — add-on migrations deferred to the next ./start.sh\n' >&2
      return 0
      ;;
  esac

  local _f
  for _f in "$_dir"/*.sql; do
    [ -f "$_f" ] || continue
    printf '  applying %s\n' "$(basename "$_f")" >&2
    # client_min_messages=warning: le migrazioni sono IF NOT EXISTS e a ogni
    # avvio stamperebbero una NOTICE per oggetto gia' presente.
    if ! ( cd supabase && docker compose exec -T -e PGOPTIONS='-c client_min_messages=warning' \
             db psql -q -v ON_ERROR_STOP=1 -U postgres -d postgres ) < "$_f" >/dev/null; then
      printf '  ✗  migration failed: %s\n' "$(basename "$_f")" >&2
      return 1
    fi
  done

  # RLS sulle agent_*: una tabella nuova nasce con RLS spenta e PostgREST
  # pubblica tutto public/* alla chiave anon, che e' pubblica per definizione.
  # Lo schema del core la riaccende, ma solo al prossimo avvio: senza questo
  # blocco le analisi salvate resterebbero leggibili dal gateway per tutta la
  # sessione in corso. RLS attiva senza policy = nega tutto ai ruoli normali;
  # l'app usa la service_role key, che ha BYPASSRLS.
  ( cd supabase && docker compose exec -T db psql -v ON_ERROR_STOP=1 \
      -U postgres -d postgres ) >/dev/null <<'SQLEOF'
DO $$
DECLARE t text;
BEGIN
  FOR t IN SELECT tablename FROM pg_tables
            WHERE schemaname = 'public'
              AND tablename LIKE 'agent\_%'
              AND NOT rowsecurity
  LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
  END LOOP;
END $$;
NOTIFY pgrst, 'reload schema';
SQLEOF
  printf '  ✓  add-on schema applied, RLS enforced, PostgREST reloaded\n' >&2
}

_agent_set_license() {
  # _agent_set_license → chiede la chiave, la verifica con il pacchetto gia'
  # installato e la scrive solo se regge. Non richiede riavvio: il core rilegge
  # la chiave a ogni richiesta.
  local _key _res _state
  _key=$(_ask_secret "Licence key")
  if [ -z "$_key" ]; then
    printf '  Nothing entered — unchanged.\n' >&2
    return 1
  fi
  _res=$(printf '%s' "$_key" | _agent_license_check)
  _state="${_res%%|*}"
  _agent_license_explain "$_state"
  case "$_state" in
    active|grace) ;;
    *) printf '  config.json left untouched.\n' >&2; return 1 ;;
  esac
  _json_write "agent.license_key=$_key"
  _agent_show_license
}

_agent_show_license() {
  local _res _state _cust _plan _exp _days _max
  _res=$(_json_read agent license_key | _agent_license_check)
  IFS='|' read -r _state _cust _plan _exp _days _max <<< "$_res"
  printf '\n  State    : %s\n' "${_state:-unknown}" >&2
  [ -n "$_cust" ] && printf '  Customer : %s\n' "$_cust" >&2
  [ -n "$_plan" ] && printf '  Plan     : %s\n' "$_plan" >&2
  [ -n "$_exp" ]  && printf '  Expires  : %s\n' "$_exp" >&2
  [ -n "$_days" ] && printf '  Days left: %s\n' "$_days" >&2
  case "$_state" in
    active|grace) _agent_capacity_report "$_max" || true ;;
  esac
  printf '\n' >&2
}

_agent_install() {
  _sep "Analysis add-on — install" >&2
  _agent_venv || return

  if _agent_installed; then
    printf '  Already installed (%s). Use "Update package" for a newer wheel,\n' "$(_agent_version)" >&2
    printf '  or "Licence key" to change the key.\n' >&2
    return
  fi

  printf '  The licence key is the gate. The verifier ships inside the package,\n' >&2
  printf '  so the package is installed first, then the key is checked: if it\n' >&2
  printf '  does not validate the package is removed again and config.json is\n' >&2
  printf '  left untouched.\n\n' >&2

  local _key
  _key=$(_ask_secret "Licence key")
  if [ -z "$_key" ]; then
    printf '  Nothing entered — aborted.\n' >&2
    return
  fi

  local _path
  _path=$(_ask "Package path (.whl file, source dir, or wheelhouse dir)" "$(_agent_default_source)")
  if [ -z "$_path" ]; then
    printf '  No path — aborted.\n' >&2
    return
  fi

  printf '\n  Installing %s ...\n' "$_path" >&2
  if ! _agent_pip_install "$_path"; then
    printf '  ✗  Installation failed. On a machine without network access, point\n' >&2
    printf '     this at a directory holding the wheel and its dependencies\n' >&2
    printf '     (PyNaCl included).\n' >&2
    _agent_pip_uninstall >/dev/null 2>&1
    return
  fi

  local _res _state
  _res=$(printf '%s' "$_key" | _agent_license_check)
  _state="${_res%%|*}"
  _agent_license_explain "$_state"

  case "$_state" in
    active|grace) ;;
    *)
      printf '  Rolling back: removing the package.\n' >&2
      if _agent_pip_uninstall; then
        printf '  ✓  package removed, config.json untouched\n' >&2
      fi
      return
      ;;
  esac

  # Conformita' al tetto di asset dichiarato dalla licenza. Non e' un controllo
  # di sicurezza — e' una clausola commerciale, e su un'installazione on-premise
  # chiunque puo' aggirarla: quindi si misura, si dichiara e si fa decidere a
  # una persona, invece di fingere di imporla.
  local _max="${_res##*|}"
  if ! _agent_capacity_report "$_max"; then
    printf '\n  The inventory exceeds what this licence covers.\n' >&2
    local _yn
    _yn=$(_ask "Install anyway? (y/n)" "n")
    case "$_yn" in
      s|S|y|Y)
        printf '  Continuing on the operator'"'"'s decision.\n' >&2
        ;;
      *)
        printf '  Rolling back: removing the package.\n' >&2
        if _agent_pip_uninstall; then
          printf '  ✓  package removed, config.json untouched\n' >&2
        fi
        printf '  Ask for a licence with a higher cap, or reduce the inventory.\n' >&2
        return
        ;;
    esac
  fi

  _json_write "agent.license_key=$_key"
  _agent_remember_source "$_path"
  printf '  ✓  licence key saved in config.json (section "agent")\n' >&2
  _agent_show_license
  # Lo schema non applicato non annulla l'installazione: il pacchetto e la
  # chiave restano, e cio' che manca e' stato detto sopra con i file da
  # applicare. L'avviso sul riavvio serve comunque.
  _agent_migrate || printf '  ⚠  Add-on schema not applied — see the note above.\n' >&2

  printf '  ⚠  Restart required: the router is attached when app.py is imported.\n' >&2
  printf '     Choose "Save and launch the app" below, or run ./start.sh again.\n' >&2
}

_agent_update() {
  # Aggiorna il solo pacchetto. La licenza non c'entra con la versione del
  # codice: non viene chiesta e non viene toccata.
  _sep "Analysis add-on — update package" >&2
  if ! _agent_installed; then
    printf '  Not installed — use "Install add-on" first.\n' >&2
    return
  fi

  local _before
  _before=$(_agent_version)
  printf '  Installed now: %s\n\n' "${_before:-?}" >&2

  local _path
  _path=$(_ask "Package path (.whl file, source dir, or wheelhouse dir)" "$(_agent_default_source)")
  if [ -z "$_path" ]; then
    printf '  No path — unchanged.\n' >&2
    return
  fi

  printf '\n  Installing %s ...\n' "$_path" >&2
  if ! _agent_pip_install "$_path"; then
    printf '  ✗  Update failed — the previously installed version is still in place.\n' >&2
    return
  fi

  local _after
  _after=$(_agent_version)
  if [ "$_after" = "$_before" ]; then
    # pip considera "gia' aggiornato" un wheel con lo stesso numero di
    # versione, anche se ricostruito: in sviluppo e' il caso normale.
    printf '  Version unchanged (%s) — forcing a reinstall of the package.\n' "$_before" >&2
    if ! _agent_pip_install "$_path" --force-reinstall --no-deps; then
      printf '  ✗  Reinstall failed.\n' >&2
      return
    fi
    _after=$(_agent_version)
  fi
  _agent_remember_source "$_path"
  printf '  ✓  package: %s → %s\n' "${_before:-?}" "${_after:-?}" >&2

  # La versione nuova puo' portare migrazioni nuove, e puo' pretendere una
  # licenza che quella salvata non soddisfa piu'. Si dichiara, non si rimedia
  # da soli: tornare indietro richiederebbe il wheel precedente, che non
  # abbiamo, e senza chiave valida il pacchetto e' comunque inerte.
  local _res _state
  _res=$(_json_read agent license_key | _agent_license_check)
  _state="${_res%%|*}"
  _agent_license_explain "$_state"
  case "$_state" in
    active|grace) _agent_capacity_report "${_res##*|}" || true ;;
    *) printf '  The package is installed but produces no analyses until a valid\n' >&2
       printf '  key is entered ("Licence key" in this menu).\n' >&2 ;;
  esac

  _agent_migrate || printf '  ⚠  Add-on schema not applied — see the note above.\n' >&2

  printf '  ⚠  Restart required: the router is attached when app.py is imported.\n' >&2
}

_agent_uninstall() {
  _sep "Analysis add-on — uninstall" >&2
  if ! _agent_installed; then
    printf '  Not installed.\n' >&2
    return
  fi

  local _yn
  _yn=$(_ask "Remove vfa-agent from the virtualenv? (y/n)" "n")
  case "$_yn" in
    s|S|y|Y) ;;
    *) printf '  Cancelled.\n' >&2; return ;;
  esac

  if _agent_pip_uninstall; then
    printf '  ✓  package removed\n' >&2
  fi
  _json_write "agent.license_key="
  printf '  ✓  licence key cleared from config.json\n' >&2

  # Le tabelle restano. Dentro ci sono sintesi salvate e bozze approvate da
  # persone: un default distruttivo qui sarebbe un errore, e reinstallare
  # sopra dati intatti e' il caso normale.
  printf '\n  The agent_* tables hold saved analyses and drafts approved by people.\n' >&2
  printf '  They are kept by default, and reused if you reinstall.\n' >&2
  local _confirm
  _confirm=$(_ask "Drop them anyway? IRREVERSIBLE — type DROP to confirm" "")
  if [ "$_confirm" = "DROP" ]; then
    if _agent_db_ready; then
      ( cd supabase && docker compose exec -T db psql -v ON_ERROR_STOP=1 \
          -U postgres -d postgres ) >/dev/null <<'SQLEOF'
DO $$
DECLARE t text;
BEGIN
  FOR t IN SELECT tablename FROM pg_tables
            WHERE schemaname = 'public' AND tablename LIKE 'agent\_%'
  LOOP
    EXECUTE format('DROP TABLE public.%I CASCADE', t);
  END LOOP;
END $$;
NOTIFY pgrst, 'reload schema';
SQLEOF
      printf '  ✓  agent_* tables dropped\n' >&2
    else
      printf '  ⚠  Cannot reach the database with SQL from here (target: %s) — tables kept.\n' \
        "$(_agent_db_target)" >&2
      printf '     Drop them by hand if you really want them gone.\n' >&2
    fi
  else
    printf '  Tables kept.\n' >&2
  fi

  printf '\n  ⚠  Restart required: the router stays loaded in the running process.\n' >&2
  printf '     The audit ledger keeps the agent.* events already recorded.\n' >&2
}

_agent_menu() {
  while true; do
    _sep "Analysis add-on (vfa-agent)" >&2
    printf '  Status: %s\n' "$(_agent_status_line)" >&2

    local _c
    if _agent_installed; then
      _c=$(_choose "Add-on:" \
        "Licence key — enter or replace it" \
        "Licence status — show details" \
        "Update package (new wheel, keeps the licence)" \
        "Apply database migrations" \
        "Uninstall add-on" \
        "Back")
      case "$_c" in
        1) _agent_set_license || true ;;
        2) _agent_show_license       ;;
        3) _agent_update             ;;
        4) _agent_migrate || true    ;;
        5) _agent_uninstall          ;;
        6) break                     ;;
      esac
    else
      _c=$(_choose "Add-on:" \
        "Install add-on (licence key, then package path)" \
        "Back")
      case "$_c" in
        1) _agent_install ;;
        2) break          ;;
      esac
    fi
  done
}

# ── Update menu ───────────────────────────────────────────────────────────────

_update_menu() {
  while true; do
    _sep "Edit Configuration" >&2
    local _ai _se
    _ai=$(_json_read ai provider)
    _se=$(_json_read search_engine provider)
    printf '  Current AI     : %s\n' "$_ai" >&2
    printf '  Current search : %s\n' "$_se" >&2
    printf '  Analysis add-on: %s\n\n' "$(_agent_status_line)" >&2

    local _c
    _c=$(_choose "What do you want to change?" \
      "AI provider (local/remote)" \
      "Search engine (DuckDuckGo/Serper)" \
      "Docker test machine (Linux/Windows)" \
      "Analysis add-on (vfa-agent: install, licence, uninstall)" \
      "Check application updates (GitHub)" \
      "Save and exit (configuration only, does not launch)" \
      "Save and launch the app")
    case "$_c" in
      1) _wizard_ai           ;;
      2) _wizard_search        ;;
      3) _wizard_test_machine  ;;
      4) _agent_menu           ;;
      5) _check_app_update     ;;
      6) LAUNCH_APP=0; break  ;;
      7) break                ;;
    esac
  done
}

# ── encdec: setup cifratura password ─────────────────────────────────────────
# Il segreto viene chiesto UNA SOLA VOLTA, compilato dentro il binario tramite
# patch di defaultSecretKeyPrefix in lib/lib.go, poi nessun file o env var lo
# contiene — il segreto esiste solo nel binario .encdec/encdec.

ENCDEC_BIN="$PWD/.encdec/encdec"
ENCDEC_DIR="$PWD/.encdec"

if [ ! -x "$ENCDEC_BIN" ]; then
  printf '\n'
  printf '  ╔══════════════════════════════════════════════╗\n'
  printf '  ║   encdec — password encryption setup         ║\n'
  printf '  ╚══════════════════════════════════════════════╝\n'
  printf '\n  encdec binary not found. One-time operation: compilation.\n'
  printf '  The secret prefix will be compiled into the binary and will\n'
  printf '  never be asked again nor stored on disk.\n\n'

  _go_ok() {
    command -v go >/dev/null 2>&1 || return 1
    local _maj _min
    read -r _maj _min <<< "$(go version | sed -E 's/.*go([0-9]+)\.([0-9]+).*/\1 \2/')"
    [ "$_maj" -gt 1 ] || { [ "$_maj" -eq 1 ] && [ "$_min" -ge 21 ]; }
  }
  if ! _go_ok; then
    printf '  Go >= 1.21 not found — trying automatic install (package manager).\n' >&2
    _apt_install golang || true
    if ! _go_ok; then
      printf '  Go from package manager missing or too old — trying official go.dev tarball.\n' >&2
      _install_go_tarball || true
    fi
    if ! _go_ok; then
      printf '  ERROR: Go >= 1.21 not available. Install manually from https://go.dev/dl/\n' >&2
      exit 1
    fi
  fi

  _PFX1=$(_ask_secret "Secret prefix for encryption (entered only once)")
  _PFX2=$(_ask_secret "Confirm secret prefix")
  if [ "$_PFX1" != "$_PFX2" ]; then
    printf '\n  ERROR: prefixes do not match.\n' >&2
    unset _PFX1 _PFX2
    exit 1
  fi

  mkdir -p "$ENCDEC_DIR"
  _TMP_ENCDEC=$(mktemp -d)

  printf '\n  ==> cloning encdec...\n' >&2
  git clone --depth 1 https://github.com/daniloritarossi/encdec "$_TMP_ENCDEC/encdec" >&2

  # Patch: sostituisce defaultSecretKeyPrefix con il segreto scelto
  python3 - "$_TMP_ENCDEC/encdec/lib/lib.go" "$_PFX1" << 'PYEOF'
import sys, re
path, secret = sys.argv[1], sys.argv[2]
src = open(path).read()
src = re.sub(
    r'(defaultSecretKeyPrefix\s*=\s*)"[^"]*"',
    lambda m: m.group(1) + '"' + secret.replace('\\', '\\\\').replace('"', '\\"') + '"',
    src
)
open(path, 'w').write(src)
PYEOF
  unset _PFX1 _PFX2

  printf '  ==> building encdec (secret prefix compiled in)...\n' >&2
  ( cd "$_TMP_ENCDEC/encdec" && go build -o "$ENCDEC_BIN" . ) >&2
  rm -rf "$_TMP_ENCDEC"
  printf '  ✓  encdec built with embedded secret: %s\n\n' "$ENCDEC_BIN" >&2
fi

# ── MAIN: config phase ────────────────────────────────────────────────────────

if [ "$MODE" = "update" ]; then
  if [ ! -f "$CONFIG_FILE" ]; then
    printf '\n  No config.json. Starting first-run wizard...\n\n' >&2
    _wizard_ai
    _wizard_search
    _wizard_test_machine
  else
    _update_menu
  fi
elif [ ! -f "$CONFIG_FILE" ]; then
  printf '\n'
  printf '  ╔══════════════════════════════════════════╗\n'
  printf '  ║  Vulnerability Feed Aggregator — Setup   ║\n'
  printf '  ╚══════════════════════════════════════════╝\n'
  printf '\n  First-time setup. Enter = default value.\n'
  _wizard_ai
  _wizard_search
  _wizard_test_machine
  printf '\n  ✓ config.json created.\n\n'
fi

[ "$LAUNCH_APP" = "0" ] && exit 0

# ── 0b) Precheck AI: ollama + LLM di default presenti a ogni avvio ────────────

AI_PROV=$(_json_read ai provider)
if [ "$AI_PROV" = "ollama" ] || [ -z "$AI_PROV" ]; then
  _OLL_URL=$(_json_read ai ollama_url)
  _OLL_MODEL=$(_json_read ai ollama_model)
  _OLL_URL="${_OLL_URL:-http://localhost:11434/api/generate}"
  _OLL_MODEL="${_OLL_MODEL:-qwen2.5:7b}"
  # rispetta la scelta fatta nel wizard (ai.ollama_autoinstall)
  _OLL_INST=1
  [ "$(_json_read ai ollama_autoinstall)" = "False" ] && _OLL_INST=0
  echo "==> AI precheck: ollama + model ${_OLL_MODEL}"
  _ensure_ollama "$_OLL_URL" "$_OLL_MODEL" "$_OLL_INST"
fi

# ── 1) Virtualenv + dipendenze ────────────────────────────────────────────────

PYBIN=".venv/bin/python"
if [ ! -x "$PYBIN" ]; then
  echo "==> creating virtualenv .venv"
  python3 -m venv .venv
fi
export PATH="$PWD/.venv/bin:$PATH"
echo "==> installing/updating dependencies (requirements.txt)"
"$PYBIN" -m pip install -q --upgrade pip
"$PYBIN" -m pip install -q -r requirements.txt

# ── 1b) UI CSS (Tailwind, compiled) ───────────────────────────────────────────
# Templates load static/vendor/tailwind.css (committed). Rebuild it when npm is
# available so class changes take effect; otherwise the committed file is served
# as-is. Never fatal — the app runs on the committed CSS.
if command -v npm >/dev/null 2>&1; then
  echo "==> building UI CSS (tailwind)"
  [ -d node_modules ] || npm install --no-audit --no-fund --silent || true
  npm run css --silent || echo "   (tailwind build skipped — using committed static/vendor/tailwind.css)"
else
  echo "==> npm not found — using committed static/vendor/tailwind.css"
fi

# ── 2) Stack Supabase (Docker) ────────────────────────────────────────────────

if [ "$WITH_SUPABASE" = "1" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker not installed — trying automatic install (package manager)." >&2
    _apt_install docker.io || true
    if ! command -v docker >/dev/null 2>&1; then
      echo "ERROR: Docker could not be installed automatically. See https://docs.docker.com/engine/install/" >&2
      exit 1
    fi
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "==> Docker daemon stopped — trying to start it" >&2
    _sv=""; [ "$(id -u)" -ne 0 ] && _sv="sudo"
    if command -v systemctl >/dev/null 2>&1; then
      $_sv systemctl start docker >/dev/null 2>&1 || true
    elif command -v rc-service >/dev/null 2>&1; then
      $_sv rc-service docker start >/dev/null 2>&1 || true
      $_sv rc-update add docker default >/dev/null 2>&1 || true
    elif command -v service >/dev/null 2>&1; then
      $_sv service docker start >/dev/null 2>&1 || true
    fi
    # attesa avvio: fino a 20s
    for _i in 1 2 3 4 5 6 7 8 9 10; do
      docker info >/dev/null 2>&1 && break
      sleep 2
    done
    # nessun init system utilizzabile (container/WSL) -> dockerd diretto
    if ! docker info >/dev/null 2>&1 && command -v dockerd >/dev/null 2>&1; then
      echo "==> no init system available — starting dockerd in background (log: /var/log/dockerd.log)" >&2
      $_sv sh -c 'nohup dockerd >/var/log/dockerd.log 2>&1 &' || true
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        docker info >/dev/null 2>&1 && break
        sleep 2
      done
    fi
    if ! docker info >/dev/null 2>&1; then
      echo "ERROR: Docker not running or missing permissions." >&2
      echo "  If the daemon is running but access is denied: sudo usermod -aG docker \$USER  (then logout/login)" >&2
      echo "  If the daemon does not start: check /var/log/dockerd.log or 'journalctl -u docker'." >&2
      if [ "$(id -u)" -eq 0 ] && [ -f /var/log/dockerd.log ] \
         && grep -q "you must be root\|Permission denied" /var/log/dockerd.log 2>/dev/null; then
        echo "" >&2
        echo "  Confined environment detected: the kernel denies iptables/nftables even to root." >&2
        echo "  You are probably in an unprivileged container (e.g. LXC). Options:" >&2
        echo "    - Proxmox LXC (from host): pct set <ID> --features nesting=1,keyctl=1  then restart the container" >&2
        echo "    - use a VM instead of a container" >&2
        echo "    - skip Docker/Supabase: ./start.sh --no-supabase" >&2
      fi
      exit 1
    fi
  fi
  if ! docker compose version >/dev/null 2>&1; then
    echo "'docker compose' plugin (v2) missing — trying automatic install." >&2
    _apt_install docker-compose-plugin || _apt_install docker-compose-v2 || _install_compose_plugin || true
    if ! docker compose version >/dev/null 2>&1; then
      echo "ERROR: 'docker compose' v2 plugin could not be installed. Install the compose v2 plugin for your distro manually." >&2
      exit 1
    fi
  fi
  echo "==> starting local Supabase (Docker)"
  ( cd supabase && ./setup.sh )
else
  echo "==> skipping Supabase (--no-supabase)"
fi

# Migrazioni dell'add-on, se installato. Dopo lo schema del core e prima del
# server: sono idempotenti, e dopo setup.sh il database locale e' certamente in
# piedi (la fase di configurazione gira a stack spento).
#
# Fuori dal ramo --no-supabase di proposito: senza stack locale il database puo'
# essere remoto e vivo, e _agent_migrate distingue da sola i quattro casi. Dentro
# il ramo, con --no-supabase le migrazioni non sarebbero mai state applicate.
if _agent_installed; then
  echo "==> vfa-agent schema"
  _agent_migrate || echo "   (add-on schema NOT applied — see the note above)"
fi

# ── 3) Server FastAPI (foreground) ────────────────────────────────────────────

AI_PROV=$(_json_read ai provider)
SE_PROV=$(_json_read search_engine provider)

cat <<EOF

============================================================
  App        : http://127.0.0.1:${PORT}
  Studio GUI : http://localhost:3001
  REST API   : http://localhost:8001/rest/v1/
  AI         : ${AI_PROV}
  Search     : ${SE_PROV}
============================================================
  Ctrl+C stops the app. Supabase stays running → ./stop.sh

EOF

# Niente --reload: uvicorn entrerebbe in supabase/volumes/db/data (uid 100,
# perms 700) e crasherebbe con PermissionError.
exec "$PYBIN" -m uvicorn app:app --host 127.0.0.1 --port "${PORT}"

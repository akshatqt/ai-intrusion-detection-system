#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  AI Intrusion Detection System — Launcher
# ─────────────────────────────────────────────────────────────
#  Usage:
#    ./run.sh              Start backend + live packet pipeline
#    ./run.sh --sim        Start backend + attack simulator
#    ./run.sh --backend    Start backend only
#    ./run.sh --stream     Start packet pipeline only (backend must be running)
#    ./run.sh --attack     Run attack simulator only (backend must be running)
# ─────────────────────────────────────────────────────────────

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
CORE_DIR="$ROOT_DIR/core"
VENV_DIR="$ROOT_DIR/.venv"

API_URL="http://127.0.0.1:8000"
PREDICT_URL="$API_URL/predict"

# ── Colours ──────────────────────────────────────────────────
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
BOLD='\033[1m'
RESET='\033[0m'

info()  { echo -e "${CYAN}[run]${RESET} $*"; }
ok()    { echo -e "${GREEN}[run]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[run]${RESET} $*"; }
err()   { echo -e "${RED}[run]${RESET} $*" >&2; }

# ── Ensure virtual environment & dependencies ────────────────
setup_env() {
    if [ ! -d "$VENV_DIR" ]; then
        info "Creating virtual environment with uv..."
        uv venv "$VENV_DIR"
    fi

    info "Installing dependencies..."
    uv pip install --quiet \
        fastapi uvicorn scikit-learn requests scapy \
        --python "$VENV_DIR/bin/python"
    ok "Dependencies ready."
}

# ── Start backend (FastAPI) ──────────────────────────────────
start_backend() {
    info "Starting FastAPI backend on ${BOLD}$API_URL${RESET} ..."
    "$VENV_DIR/bin/python" -m uvicorn app.main:app \
        --host 0.0.0.0 \
        --port 8000 \
        --reload \
        --app-dir "$BACKEND_DIR" &
    BACKEND_PID=$!
    sleep 2

    if kill -0 "$BACKEND_PID" 2>/dev/null; then
        ok "Backend running  (PID $BACKEND_PID)"
    else
        err "Backend failed to start!"
        exit 1
    fi
}

# ── Start live packet pipeline ───────────────────────────────
start_stream() {
    info "Starting packet capture pipeline..."
    warn "This requires ${BOLD}sudo${RESET} for raw packet capture."
    sudo "$VENV_DIR/bin/python" "$CORE_DIR/stream.py" --api "$PREDICT_URL"
}

# ── Run attack simulator ────────────────────────────────────
run_attack() {
    info "Running attack simulator..."
    "$VENV_DIR/bin/python" "$CORE_DIR/attack_simulator.py" --api "$PREDICT_URL"
}

# ── Cleanup on exit ─────────────────────────────────────────
cleanup() {
    echo ""
    warn "Shutting down..."
    if [ -n "${BACKEND_PID:-}" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill "$BACKEND_PID" 2>/dev/null
        ok "Backend stopped."
    fi
}
trap cleanup EXIT INT TERM

# ── Main ─────────────────────────────────────────────────────
MODE="${1:-}"

echo -e "${BOLD}${CYAN}"
echo "  ┌──────────────────────────────────────────┐"
echo "  │   AI Intrusion Detection System          │"
echo "  │   Privacy-Preserving Network Defence     │"
echo "  └──────────────────────────────────────────┘"
echo -e "${RESET}"

setup_env

case "$MODE" in
    --backend)
        start_backend
        info "Backend-only mode. Press Ctrl+C to stop."
        wait "$BACKEND_PID"
        ;;
    --stream)
        start_stream
        ;;
    --attack)
        run_attack
        ;;
    --sim)
        start_backend
        echo ""
        run_attack
        ;;
    *)
        start_backend
        echo ""
        start_stream
        ;;
esac

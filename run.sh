#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
    echo "Creating virtual environment..."
    uv venv .venv
    uv pip install -r requirements.txt
fi

source .venv/bin/activate

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8844}"

echo "Starting SafeCode Analyzer on http://${HOST}:${PORT}"
echo "LLM features: ${SAFECODE_LLM_ENABLED:-disabled}"
echo "To enable LLM, set: export SAFECODE_LLM_ENABLED=true"
echo ""

uvicorn backend.main:app --host "$HOST" --port "$PORT" --reload

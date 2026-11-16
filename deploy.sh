#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

EXPECTED_DIR="/srv/nanotechsoft/router"
if [[ "$ROOT_DIR" != "$EXPECTED_DIR" ]]; then
  echo "ERRO: NanotechRouter deve ser implantado em $EXPECTED_DIR"
  echo "Diretório atual: $ROOT_DIR"
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERRO: Docker não encontrado."
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERRO: Docker Compose v2 não encontrado."
  exit 1
fi

if [[ ! -f .env ]]; then
  echo "Criando .env..."
  umask 077
  SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  cat > .env <<EOF
ROUTER_SECRET_KEY=$SECRET_KEY
ROUTER_API_TOKEN=$API_TOKEN
EOF
  chmod 600 .env
  echo ".env criado."
else
  echo ".env existente preservado."
fi

# Fail early if required variables are missing/empty.
set -a
# shellcheck disable=SC1091
source ./.env
set +a

: "${ROUTER_SECRET_KEY:?ROUTER_SECRET_KEY ausente no .env}"
: "${ROUTER_API_TOKEN:?ROUTER_API_TOKEN ausente no .env}"

mkdir -p data config

echo "Validando Docker Compose..."
docker compose config >/dev/null

echo "Construindo imagens..."
docker compose build

echo "Subindo NanotechRouter..."
docker compose up -d --remove-orphans

echo "Aguardando Core..."
for attempt in $(seq 1 30); do
  status="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' nanotechrouter-core 2>/dev/null || true)"
  if [[ "$status" == "healthy" ]]; then
    echo "Core saudável."
    docker compose ps
    echo
    echo "Deploy concluído."
    exit 0
  fi
  if [[ "$status" == "unhealthy" ]]; then
    echo "ERRO: Core ficou unhealthy."
    docker compose logs --tail=100 router-core
    exit 1
  fi
  sleep 2
done

echo "ERRO: timeout aguardando Core ficar healthy."
docker compose ps
docker compose logs --tail=100 router-core
exit 1

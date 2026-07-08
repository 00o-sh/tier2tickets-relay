#!/usr/bin/env bash
# Dump the Gorelo IDs needed to fill wrangler.toml [vars]:
#   groups, ticket types, ticket statuses, and clients (id / name / domains).
#
# Usage:
#   GORELO_API_KEY=xxxx ./scripts/gorelo-ids.sh
#   GORELO_API_KEY=xxxx GORELO_BASE_URL=https://api.aue.gorelo.io ./scripts/gorelo-ids.sh
#
# Requires: curl, jq. The key needs asset/contact/client read (and ticket write for creates).
set -euo pipefail

BASE_URL="${GORELO_BASE_URL:-https://api.usw.gorelo.io}"
: "${GORELO_API_KEY:?Set GORELO_API_KEY}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required (https://jqlang.github.io/jq/)" >&2
  exit 1
fi

get() {
  curl -sS -H "X-API-Key: ${GORELO_API_KEY}" -H "Accept: application/json" "${BASE_URL}$1"
}

echo "=== Groups  (GET /v1/organization/groups)  -> DEFAULT_GROUP_ID ==="
get /v1/organization/groups | jq -r '(.items // .data // .) | .[] | "\(.id)\t\(.name)"' 2>/dev/null || echo "(inspect raw response)"

echo
echo "=== Ticket types  (GET /v1/tickets/types)  -> DEFAULT_TYPE_ID ==="
get /v1/tickets/types | jq -r '(.items // .data // .) | .[] | "\(.id)\t\(.name)"' 2>/dev/null || echo "(inspect raw response)"

echo
echo "=== Ticket statuses  (GET /v1/tickets/statuses)  (optional) ==="
get /v1/tickets/statuses | jq -r '(.items // .data // .) | .[] | "\(.id)\t\(.name)"' 2>/dev/null || echo "(inspect raw response)"

echo
echo "=== Clients  (GET /v1/clients)  -> CATCHALL_CLIENT_ID + domain mirror ==="
get /v1/clients | jq -r '(.items // .data // .) | .[] | "\(.id)\t\(.name)\tdomains=\([.domains[]? | (.domain // .name)] | join(","))"' 2>/dev/null || echo "(inspect raw response)"

echo
echo "Enums to confirm in the Gorelo UI (spec ships ints without labels):"
echo "  PublicTicketPriority = [0,1,2,3,4]  -> DEFAULT_PRIORITY"
echo "  TicketSource         = [1,2,3,4,5,6] -> DEFAULT_SOURCE (pick the integration/portal/API source)"

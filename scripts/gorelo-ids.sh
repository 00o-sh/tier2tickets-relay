#!/usr/bin/env bash
# Dump the Gorelo IDs needed to fill wrangler.toml [vars]:
#   groups, ticket types, ticket statuses, and clients (id / name / domains).
#
# Usage:
#   GORELO_API_KEY=xxxx ./scripts/gorelo-ids.sh
#   GORELO_API_KEY=xxxx GORELO_BASE_URL=https://api.aue.gorelo.io ./scripts/gorelo-ids.sh
#   RAW=1 GORELO_API_KEY=xxxx ./scripts/gorelo-ids.sh    # always print raw bodies
#
# Requires: curl, jq. The key needs asset/contact/client read (and ticket write for creates).
set -euo pipefail

BASE_URL="${GORELO_BASE_URL:-https://api.usw.gorelo.io}"
: "${GORELO_API_KEY:?Set GORELO_API_KEY}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required (https://jqlang.github.io/jq/)" >&2
  exit 1
fi

# Fetch a path; print the HTTP status, and either the extracted rows or the raw
# body (on non-2xx, non-JSON, or when the jq extraction finds nothing / RAW=1).
# $1 = path, $2 = jq extraction program
dump() {
  local path="$1" prog="$2" body code
  # Capture body + trailing HTTP code without failing the script on non-2xx.
  body="$(curl -sS -w $'\n%{http_code}' \
    -H "X-API-Key: ${GORELO_API_KEY}" -H "Accept: application/json" \
    "${BASE_URL}${path}" || true)"
  code="${body##*$'\n'}"
  body="${body%$'\n'*}"

  echo "  HTTP ${code}"
  if [[ "${code}" != 2* ]]; then
    echo "  !! request failed — raw body:"
    echo "${body}" | sed 's/^/    /'
    echo "  (403 usually means the API key lacks the required scope.)"
    return
  fi

  # Valid JSON?
  if ! echo "${body}" | jq -e . >/dev/null 2>&1; then
    echo "  !! response is not JSON — raw body:"
    echo "${body}" | sed 's/^/    /'
    return
  fi

  local rows
  rows="$(echo "${body}" | jq -r "${prog}" 2>/dev/null || true)"
  if [[ -z "${rows}" || "${RAW:-}" == "1" ]]; then
    echo "  (no rows matched the expected shape — raw JSON below; adjust the vars accordingly)"
    echo "${body}" | jq . | sed 's/^/    /'
  else
    echo "${rows}" | sed 's/^/    /'
  fi
}

# Handles a bare array or an { items | data | results | value: [...] } envelope.
ROWS='(if type=="array" then . else (.items // .data // .results // .value // []) end)
      | .[] | "\(.id)\t\(.name)"'
CLIENT_ROWS='(if type=="array" then . else (.items // .data // .results // .value // []) end)
      | .[] | "\(.id)\t\(.name)\tdomains=\([.domains[]? | (.domain // .name)] | join(","))"'

echo "=== Groups  (GET /v1/organization/groups)  -> DEFAULT_GROUP_ID ==="
dump /v1/organization/groups "${ROWS}"

echo
echo "=== Ticket types  (GET /v1/tickets/types)  -> DEFAULT_TYPE_ID ==="
dump /v1/tickets/types "${ROWS}"

echo
echo "=== Ticket statuses  (GET /v1/tickets/statuses)  (optional) ==="
dump /v1/tickets/statuses "${ROWS}"

echo
echo "=== Clients  (GET /v1/clients)  -> CATCHALL_CLIENT_ID + domain mirror ==="
dump /v1/clients "${CLIENT_ROWS}"

echo
echo "Enums to confirm in the Gorelo UI (spec ships ints without labels):"
echo "  PublicTicketPriority = [0,1,2,3,4]  -> DEFAULT_PRIORITY"
echo "  TicketSource         = [1,2,3,4,5,6] -> DEFAULT_SOURCE (pick the integration/portal/API source)"

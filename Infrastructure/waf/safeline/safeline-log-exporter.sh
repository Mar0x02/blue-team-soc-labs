#!/usr/bin/env bash
set -uo pipefail

LOG_FILE="${SAFELINE_LOG_FILE:-/var/log/safeline/events.json}"
STATE_FILE="${SAFELINE_STATE_FILE:-/var/lib/safeline-exporter/last_id}"
PG_CONTAINER="${SAFELINE_PG_CONTAINER:-safeline-pg}"
POLL_INTERVAL="${SAFELINE_POLL_INTERVAL:-10}"

mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$STATE_FILE")"

last_id=0
if [ -s "$STATE_FILE" ]; then
  last_id="$(cat "$STATE_FILE")"
fi

while true; do
  query="SELECT id, json_build_object('safeline', to_json(t))
         FROM (SELECT id, event_id, src_ip, socket_ip, host, url_path, dst_port,
                      attack_type, risk_level, action, rule_id, timestamp
               FROM mgt_detect_log_basic
               WHERE id > ${last_id}
               ORDER BY id
               LIMIT 500) t
         ORDER BY id"

  if rows="$(docker exec "$PG_CONTAINER" sh -c \
    'psql -U "$POSTGRES_USER" -d "${POSTGRES_DB:-$POSTGRES_USER}" -v ON_ERROR_STOP=1 -At -F "$(printf "\t")" -c "$1"' \
    sh "$query" 2>/dev/null)"; then
    while IFS=$'\t' read -r id json; do
      [ -n "$id" ] || continue
      printf '%s\n' "$json" >> "$LOG_FILE"
      last_id="$id"
      printf '%s\n' "$last_id" > "$STATE_FILE"
    done <<< "$rows"
  fi

  sleep "$POLL_INTERVAL"
done

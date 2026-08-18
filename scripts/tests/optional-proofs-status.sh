#!/usr/bin/env bash
#
# Report what each node of the optional-proofs devnet is doing with execution proofs.
#
# A healthy run has the gated consumers at the same head and the same finalized epoch as the
# ungated controls, with a non-zero `imported_via_proof` count: those are payload envelopes that
# became importable only once a proof arrived.
set -Eeuo pipefail

api_port() {
  docker port "$1" 4000/tcp 2>/dev/null | head -1 | sed 's/.*://'
}

beacon_get() {
  curl -s --max-time 4 "http://127.0.0.1:$1$2" 2>/dev/null
}

printf "%-6s %-9s %-6s %-11s %-10s %-9s %s\n" \
  NODE ROLE HEAD JUST/FINAL PUBLISHED VERIFIED IMPORTED_VIA_PROOF

for container in $(docker ps --format '{{.Names}}' | grep -E '^cl-[0-9]+-lighthouse' | sort); do
  node=$(echo "$container" | grep -oE '^cl-[0-9]+')
  port=$(api_port "$container")
  [ -z "$port" ] && continue

  head=$(beacon_get "$port" /eth/v1/beacon/headers/head |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["header"]["message"]["slot"])' 2>/dev/null)
  checkpoints=$(beacon_get "$port" /eth/v1/beacon/states/head/finality_checkpoints |
    python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; print(d["current_justified"]["epoch"]+"/"+d["finalized"]["epoch"])' 2>/dev/null)

  logs=$(docker logs --tail 60000 "$container" 2>&1)
  published=$(grep -c "Publishing execution proof" <<<"$logs" || true)
  verified=$(grep -c "Verified execution proof from gossip" <<<"$logs" || true)
  imported=$(grep -c "imported after execution proof" <<<"$logs" || true)

  if [ "$published" -gt 0 ]; then
    role=seeder
  elif [ "$verified" -gt 0 ]; then
    role=consumer
  else
    role=control
  fi

  printf "%-6s %-9s %-6s %-11s %-10s %-9s %s\n" \
    "$node" "$role" "${head:-?}" "${checkpoints:-?}" "$published" "$verified" "$imported"
done

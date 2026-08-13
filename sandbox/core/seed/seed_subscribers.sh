#!/bin/bash
# Provisions the sandbox's fixed set of test subscribers in Open5GS's Mongo DB.
# Re-runnable: existing IMSIs are removed and re-added, so this is safe to run
# again if the mongo volume was ever wiped. See docs/adr/0002.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Canonical Open5GS test credentials (PLMN 999/70, matches core/.env and
# ran/.env). Same K/OPC reused across UEs; only the IMSI increments.
KI="465B5CE8B199B49FAA5F0A2EE238A6BC"
OPC="E8ED289DEBA952E4283B54E88E6183CA"
IMSIS=(999700000000001 999700000000002 999700000000003)

DB_URI="mongodb://$(grep ^MONGO_IP= .env | cut -d= -f2)/open5gs"

for imsi in "${IMSIS[@]}"; do
  echo "Provisioning subscriber $imsi"
  docker compose exec -T nrf /open5gs/misc/db/open5gs-dbctl --db_uri="$DB_URI" remove "$imsi" >/dev/null 2>&1 || true
  docker compose exec -T nrf /open5gs/misc/db/open5gs-dbctl --db_uri="$DB_URI" add "$imsi" "$KI" "$OPC"
done

echo "Subscribers provisioned:"
docker compose exec -T nrf /open5gs/misc/db/open5gs-dbctl --db_uri="$DB_URI" showfiltered

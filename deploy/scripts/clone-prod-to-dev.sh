#!/usr/bin/env bash
# Replace the auth-service dev database with a copy of prod.
#
#   clone-prod-to-dev.sh [--yes]
#
# Copies all users, roles and the application registry, so dev has the same people
# and role assignments as prod. Deliberately NOT copied or kept:
#   * the RSA signing key volume — dev generates its own. If dev shared prod's key,
#     a token minted in dev (where developers can edit the database) would be
#     accepted by prod.
#   * users' stored OpenRouter keys — they are encrypted with prod's
#     SECRETS_ENCRYPTION_KEY and would be unreadable in dev anyway, so they are
#     removed from the copy. Users re-enter them in dev if they need them there.
# Prod is only ever READ. Environment: DBIS_ROOT (default /srv/dbis-universe).
set -euo pipefail

root=${DBIS_ROOT:-/srv/dbis-universe}
prod="$root/auth/prod"
dev="$root/auth/dev"
assume_yes=0
for arg in "$@"; do
  case "$arg" in
    --yes) assume_yes=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

log() { printf '%s %s\n' "$(date -Is)" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }
env_value() { sed -n "s/^$2=//p" "$1/.env" | tail -n1; }

for d in "$prod" "$dev"; do [ -f "$d/compose.yaml" ] && [ -f "$d/.env" ] || die "$d is not a stack directory"; done
[ "$(env_value "$prod" ENVIRONMENT)" = prod ] || die "$prod/.env does not say ENVIRONMENT=prod"
[ "$(env_value "$dev" ENVIRONMENT)" = dev ]  || die "$dev/.env does not say ENVIRONMENT=dev"
[ "$(env_value "$prod" SECRETS_ENCRYPTION_KEY)" != "$(env_value "$dev" SECRETS_ENCRYPTION_KEY)" ] \
  || die "dev must use its own SECRETS_ENCRYPTION_KEY, not prod's"

prod_db=$(env_value "$prod" MONGO_DB_NAME); prod_db=${prod_db:-auth_db}
dev_db=$(env_value "$dev" MONGO_DB_NAME);   dev_db=${dev_db:-auth_db}

if [ "$assume_yes" != 1 ]; then
  echo "This OVERWRITES the dev auth database ($dev_db) with a copy of prod ($prod_db)."
  read -r -p "Type 'dev' to continue: " answer
  [ "$answer" = dev ] || die "aborted"
fi

pcompose() { (cd "$prod" && docker compose "$@"); }
dcompose() { (cd "$dev" && docker compose "$@"); }
# run mongo tools inside the container so the credentials never leave it
mongo_auth='-u "$MONGO_INITDB_ROOT_USERNAME" -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin'

log "stopping dev auth-service"
dcompose stop auth-service
dcompose up -d auth-mongo --wait

log "copying database $prod_db (prod) -> $dev_db (dev)"
pcompose exec -T auth-mongo sh -c "mongodump --quiet --archive --db '$prod_db' $mongo_auth" \
  | dcompose exec -T auth-mongo sh -c "mongorestore --quiet --archive --drop --nsFrom '$prod_db.*' --nsTo '$dev_db.*' $mongo_auth"

log "removing the copied OpenRouter keys (undecryptable in dev)"
dcompose exec -T auth-mongo sh -c "mongosh --quiet $mongo_auth '$dev_db' --eval 'db.users.updateMany({}, {\$unset: {openrouter_api_key_encrypted: \"\"}}).modifiedCount'"

log "starting dev auth-service"
dcompose up -d --wait
log "done: dev holds a copy of prod's users as of $(date -Is)"

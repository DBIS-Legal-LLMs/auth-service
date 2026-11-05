#!/usr/bin/env bash
# One-time cutover: copy the auth-service dev database into the (empty) prod database, so the people
# who work on dev log in on prod with the same accounts and keep the same user ids (GRIPL's datasets
# are owned by the auth user id, so registering them again on prod would orphan their data).
#
#   clone-dev-to-prod.sh [--force] [--keep-dev-stopped] [--yes]
#
# Copied: all users (password hashes, roles, superuser flag) and the application registry.
# Deliberately NOT copied or kept:
#   * the RSA signing key volume: prod generates its own, everybody logs in once more
#   * users' stored OpenRouter keys, when the two stacks use different SECRETS_ENCRYPTION_KEYs (the
#     default): they would be unreadable in prod, so they are removed from the copy and every user enters
#     the key again under Account Settings. With the same key they are kept.
#
# Safety:
#   * dev is only ever READ (its auth-service is stopped during the copy so nothing is written, and
#     started again at the end unless --keep-dev-stopped)
#   * refuses to run when prod already has users, unless --force (which REPLACES prod's database)
# Run the GRIPL counterpart (GRIPL-v2/deploy/scripts/clone-dev-to-prod.sh) in the same maintenance window.
# Environment: DBIS_ROOT (default /srv/gripl) - the folder holding {prod,dev}/auth.
set -euo pipefail

root=${DBIS_ROOT:-/srv/gripl}
prod="$root/prod/auth"
dev="$root/dev/auth"
force=0 keep_dev_stopped=0 assume_yes=0
for arg in "$@"; do
  case "$arg" in
    --force) force=1 ;;
    --keep-dev-stopped) keep_dev_stopped=1 ;;
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

prod_db=$(env_value "$prod" MONGO_DB_NAME); prod_db=${prod_db:-auth_db}
dev_db=$(env_value "$dev" MONGO_DB_NAME);   dev_db=${dev_db:-auth_db}
prod_key=$(env_value "$prod" SECRETS_ENCRYPTION_KEY)
dev_key=$(env_value "$dev" SECRETS_ENCRYPTION_KEY)
[ -n "$prod_key" ] || die "SECRETS_ENCRYPTION_KEY is not set in $prod/.env"

pcompose() { (cd "$prod" && docker compose "$@"); }
dcompose() { (cd "$dev" && docker compose "$@"); }
# run mongo tools inside the container so the credentials never leave it
mongo_auth='-u "$MONGO_INITDB_ROOT_USERNAME" -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin'
# count_docs <prod|dev> <db> <collection>
count_docs() {
  local out
  if [ "$1" = prod ]; then
    out=$(pcompose exec -T auth-mongo sh -c "mongosh --quiet $mongo_auth '$2' --eval 'db.getCollection(\"$3\").countDocuments({})'" </dev/null)
  else
    out=$(dcompose exec -T auth-mongo sh -c "mongosh --quiet $mongo_auth '$2' --eval 'db.getCollection(\"$3\").countDocuments({})'" </dev/null)
  fi
  out=$(tail -n1 <<<"$out" | tr -d '[:space:]')
  [[ $out =~ ^[0-9]+$ ]] || die "could not count $3 in $1 (got '$out')"
  echo "$out"
}

log "starting the prod database (a fresh stack creates its volumes now)"
pcompose up -d auth-mongo --wait
prod_users=$(count_docs prod "$prod_db" users)
if [ "$prod_users" != 0 ] && [ "$force" != 1 ]; then
  die "prod already has $prod_users users; this script is for the first fill of an empty prod. Use --force only to REPLACE prod's database with dev's."
fi

if [ "$assume_yes" != 1 ]; then
  echo "This copies the users of dev ($dev_db) into prod ($prod_db)."
  [ "$prod_users" = 0 ] || echo "prod has $prod_users users now; they are REPLACED."
  [ "$dev_key" = "$prod_key" ] || echo "The stored OpenRouter keys are removed from the copy (the two stacks use different SECRETS_ENCRYPTION_KEYs)."
  read -r -p "Type 'prod' to continue: " answer || die "aborted (no answer)"
  [ "$answer" = prod ] || die "aborted"
fi

# whatever happens below, put the services back as they were (prod is started by the script itself on success)
prod_was_running=0
[ -z "$(pcompose ps --status running -q auth-service)" ] || prod_was_running=1
restore() {
  if [ "$keep_dev_stopped" != 1 ]; then log "starting dev auth-service again"; dcompose up -d --wait || true; fi
  if [ "$prod_was_running" = 1 ]; then log "starting prod auth-service again"; pcompose up -d auth-service --wait || true; fi
}
trap restore EXIT

log "stopping the auth-service of dev and prod, so nothing is written during the copy"
dcompose stop auth-service
pcompose stop auth-service
dcompose up -d auth-mongo --wait

dev_users=$(count_docs dev "$dev_db" users)
dev_apps=$(count_docs dev "$dev_db" applications)
[ "$dev_users" != 0 ] || die "dev has no users, refusing to copy an empty database"

log "copying database $dev_db (dev) -> $prod_db (prod)"
dcompose exec -T auth-mongo sh -c "mongodump --quiet --archive --db '$dev_db' $mongo_auth" </dev/null \
  | pcompose exec -T auth-mongo sh -c "mongorestore --quiet --archive --drop --nsFrom '$dev_db.*' --nsTo '$prod_db.*' $mongo_auth"

if [ "$dev_key" != "$prod_key" ]; then
  log "removing the copied OpenRouter keys (undecryptable in prod)"
  pcompose exec -T auth-mongo sh -c "mongosh --quiet $mongo_auth '$prod_db' --eval 'db.users.updateMany({}, {\$unset: {openrouter_api_key_encrypted: \"\"}}).modifiedCount'" </dev/null >/dev/null
fi

log "starting prod auth-service"
pcompose up -d --wait

new_users=$(count_docs prod "$prod_db" users)
new_apps=$(count_docs prod "$prod_db" applications)
log "check: users dev=$dev_users prod=$new_users, applications dev=$dev_apps prod=$new_apps"
[ "$new_users" = "$dev_users" ] && [ "$new_apps" = "$dev_apps" ] || die "the counts differ, do not use prod before this is understood"
log "done: prod holds the $new_users accounts of dev, as of $(date -Is). Everybody logs in again (new signing key)."

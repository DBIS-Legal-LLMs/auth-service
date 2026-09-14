#!/usr/bin/env python3
"""Bootstrap the *first* global superuser (auth-service#7).

Run inside the container:

    docker compose exec auth-service python scripts/promote_superuser.py <email-or-username>

There is deliberately no API path to create the first superuser: every
superuser-granting endpoint requires an existing superuser caller (auth-service#8),
so the very first one can only be set out-of-band. This script does that — and
nothing more.

**It refuses to run once any superuser already exists.** `docker exec` access to
the container already implies host-level control of the deployment (same trust
boundary as reading the RSA signing key off its volume), so this script grants no
new capability to whoever can reach it — but without the guard, that same person
could keep using it as a standing bypass of the real, audited, reauthenticated
controls. With the guard it can only ever be used once, for the bootstrap.
"""

import argparse
import sys

from pymongo import MongoClient

sys.path.insert(0, ".")

from app.config import get_settings  # noqa: E402
from app.services.user_service import USERS_COLLECTION  # noqa: E402

ALREADY_EXISTS_MESSAGE = (
    "A superuser already exists. Use the admin panel to promote further users "
    "— this script is bootstrap-only."
)


def _users_collection():
    settings = get_settings()
    client = MongoClient(settings.mongo_url)
    return client[settings.mongo_db_name][USERS_COLLECTION]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("identifier", help="the target user's email or username")
    args = parser.parse_args()

    users = _users_collection()

    if users.count_documents({"is_superuser": True}, limit=1) > 0:
        print(ALREADY_EXISTS_MESSAGE, file=sys.stderr)
        return 1

    user = users.find_one({"$or": [{"email": args.identifier}, {"username": args.identifier}]})
    if user is None:
        print(f"No user found with email or username {args.identifier!r}.", file=sys.stderr)
        return 1

    if user.get("is_superuser"):
        # Can't happen given the guard above (that would mean a superuser
        # exists), but keep it explicit.
        print(f"{args.identifier!r} is already a superuser.", file=sys.stderr)
        return 1

    users.update_one({"_id": user["_id"]}, {"$set": {"is_superuser": True}})
    print(
        f"Promoted {user.get('username')} <{user.get('email')}> to global superuser. "
        f"Every further promotion must go through the audited API (auth-service#8)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

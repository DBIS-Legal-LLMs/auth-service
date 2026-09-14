#!/usr/bin/env python3
"""Register (or update) a consuming app in the `applications` registry.

Registering an app is a rare, deployment-time action — closer to provisioning
than to day-to-day admin — so it is deliberately not exposed over HTTP
(auth-service#5). Run this inside the container:

    docker compose exec auth-service python scripts/register_application.py gripl \
        --name "GRIPL" \
        --role admin=Admin \
        --role dpo="Data Protection Officer" \
        --role researcher=Researcher \
        --role end-user="End User" \
        --default-role end-user

Re-registering an existing app needs --overwrite. `--list` prints the current
registry and exits.

The document shape and validation rules (must define an `admin` role, etc.) are
the model in app/models/application_models.py — this script just feeds it.
"""

import argparse
import sys

from pymongo import MongoClient

# Allow `python scripts/register_application.py` from the repo root as well as
# from inside the container (where /app is the working dir).
sys.path.insert(0, ".")

from app.config import get_settings  # noqa: E402
from app.models.application_models import ApplicationCreate  # noqa: E402
from app.services.application_service import APPLICATIONS_COLLECTION  # noqa: E402


def _parse_role(raw: str) -> dict[str, str]:
    for sep in ("=", ":"):
        if sep in raw:
            key, label = raw.split(sep, 1)
            key, label = key.strip(), label.strip()
            if key and label:
                return {"key": key, "label": label}
    raise argparse.ArgumentTypeError(
        f"--role must look like KEY=Label (got {raw!r})"
    )


def _collection():
    settings = get_settings()
    client = MongoClient(settings.mongo_url)
    return client[settings.mongo_db_name][APPLICATIONS_COLLECTION]


def _print_registry() -> None:
    col = _collection()
    docs = list(col.find({}).sort("_id", 1))
    if not docs:
        print("(no applications registered)")
        return
    for doc in docs:
        roles = ", ".join(f"{r['key']} ({r['label']})" for r in doc.get("roles", []))
        print(f"- {doc['_id']}: {doc.get('display_name')}")
        print(f"    roles: {roles}")
        print(f"    default_role: {doc.get('default_role')}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("app_key", nargs="?", help="app id, e.g. 'gripl' (lowercase, digits, hyphens)")
    parser.add_argument("--name", help="human-readable display name")
    parser.add_argument("--role", action="append", type=_parse_role, default=[], metavar="KEY=Label",
                        help="a selectable role; repeat for each. Must include 'admin=...'")
    parser.add_argument("--default-role", help="role key assigned to users with no explicit role for this app")
    parser.add_argument("--overwrite", action="store_true", help="replace an already-registered app")
    parser.add_argument("--list", action="store_true", help="print the current registry and exit")
    args = parser.parse_args()

    if args.list:
        _print_registry()
        return 0

    missing = [name for name, val in
               (("app_key", args.app_key), ("--name", args.name), ("--default-role", args.default_role))
               if not val]
    if missing or not args.role:
        parser.error(f"missing required: {', '.join(missing + (['--role'] if not args.role else []))}")

    try:
        app_in = ApplicationCreate(
            _id=args.app_key,
            display_name=args.name,
            roles=args.role,
            default_role=args.default_role,
        )
    except ValueError as exc:
        print(f"Invalid application definition: {exc}", file=sys.stderr)
        return 2

    col = _collection()
    doc = {
        "_id": app_in.id,
        "display_name": app_in.display_name,
        "roles": [r.model_dump() for r in app_in.roles],
        "default_role": app_in.default_role,
    }

    existing = col.find_one({"_id": app_in.id})
    if existing and not args.overwrite:
        print(f"'{app_in.id}' is already registered. Re-run with --overwrite to replace it.", file=sys.stderr)
        return 1

    if existing:
        col.replace_one({"_id": app_in.id}, doc)
        print(f"Updated application '{app_in.id}'.")
    else:
        col.insert_one(doc)
        print(f"Registered application '{app_in.id}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

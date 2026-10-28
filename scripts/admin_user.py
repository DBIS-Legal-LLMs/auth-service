#!/usr/bin/env python3
"""Manage the users of a running auth-service through its own, audited API.

Run inside the auth-service container, so nothing has to be reachable from outside:

    docker compose exec auth-service python scripts/admin_user.py superuser <user>
    docker compose exec auth-service python scripts/admin_user.py superuser <user> --revoke
    docker compose exec auth-service python scripts/admin_user.py role <user> <app> <role>
    docker compose exec auth-service python scripts/admin_user.py show <user>

`<user>` is a username or an e-mail address. The script logs in as YOU (it asks for your
username and password, or reads ADMIN_USER / ADMIN_PASSWORD from the environment) and calls
the same endpoints the service documents, including the password re-check for superuser
changes. `show` only reads the database and needs no login.

This is the way to promote anybody after the first superuser; promote_superuser.py refuses
to run once one exists (it is bootstrap-only).
"""
import getpass
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.getcwd())  # /app inside the container, like the other scripts
from pymongo import MongoClient  # noqa: E402

from app.config import get_settings  # noqa: E402

BASE = "http://127.0.0.1:8000"


def api(method, path, token=None, body=None, form=None):
    data, headers = None, {}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        sys.exit(f"{method} {path} -> HTTP {error.code}: {error.read().decode()[:300]}")
    except urllib.error.URLError as error:
        sys.exit(f"cannot reach auth-service on {BASE}: {error.reason}")


def find_user(name):
    settings = get_settings()
    users = MongoClient(settings.mongo_url)[settings.mongo_db_name]["users"]
    user = users.find_one({"$or": [{"username": name}, {"email": name}]})
    if user is None:
        sys.exit(f"no user '{name}' (username or e-mail)")
    return user


def login():
    username = os.environ.get("ADMIN_USER") or input("Your username or e-mail: ")
    password = os.environ.get("ADMIN_PASSWORD") or getpass.getpass("Your password: ")
    token = api("POST", "/auth/login", form={"username": username, "password": password})["access_token"]
    return token, password


def describe(user):
    return (f"{user.get('username')} <{user.get('email')}> id={user['_id']} "
            f"superuser={user.get('is_superuser', False)} app_roles={user.get('app_roles', {})}")


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    command, name = argv[0], argv[1]
    target = find_user(name)
    if command == "show":
        print(describe(target))
    elif command == "superuser":
        revoke = "--revoke" in argv[2:]
        token, password = login()
        api("PUT", f"/users/{target['_id']}/superuser", token,
            {"is_superuser": not revoke, "current_password": password})
        print(("revoked superuser from " if revoke else "granted superuser to ") + name)
        print(describe(find_user(name)))
    elif command == "role":
        if len(argv) != 4:
            sys.exit("usage: role <user> <app> <role>")
        token, _ = login()
        api("PUT", f"/users/{target['_id']}/roles/{argv[2]}", token, {"role": argv[3]})
        print(f"set {name} to '{argv[3]}' in {argv[2]}")
        print(describe(find_user(name)))
    else:
        sys.exit(f"unknown command '{command}'\n{__doc__}")


main(sys.argv[1:])

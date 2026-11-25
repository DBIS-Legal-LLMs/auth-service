"""The daily error log file (app/core/logging_setup.py) and the events that end up in it."""

import logging
import os
import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.deps import get_application_service, get_refresh_token_service, get_user_service
from app.core.logging_setup import DailyErrorFileHandler, install_error_log, remove_error_log
from app.main import app
from app.services.refresh_token_service import REUSE_GRACE, RefreshTokenService
from tests.test_refresh_tokens import PASSWORD, FakeApplicationService, FakeDb, FakeUserService, _user

TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")


@pytest.fixture
def logdir(tmp_path):
    handler = install_error_log(str(tmp_path), retention_days=30, max_file_mb=20)
    assert handler is not None
    yield tmp_path
    remove_error_log()


def read_today(logdir) -> str:
    path = logdir / f"auth-service-errors-{TODAY}.log"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def test_warning_and_error_land_in_the_daily_file_but_info_does_not(logdir):
    log = logging.getLogger("app.test")
    old_level = logging.getLogger().level
    logging.getLogger().setLevel(logging.INFO)
    try:
        log.info("an info line")
        log.warning("a warning line")
        log.error("an error line")
    finally:
        logging.getLogger().setLevel(old_level)

    text = read_today(logdir)
    assert "WARNING app.test a warning line" in text
    assert "ERROR app.test an error line" in text
    assert "an info line" not in text
    assert (logdir / f"auth-service-errors-{TODAY}.log").exists()


def test_tracebacks_are_written(logdir):
    try:
        1 / 0
    except ZeroDivisionError:
        logging.getLogger("app.test").exception("it failed")

    assert "ZeroDivisionError" in read_today(logdir)


def test_unhandled_exceptions_logged_by_uvicorn_are_written(logdir):
    logging.getLogger("uvicorn.error").error("Exception in ASGI application")

    assert "Exception in ASGI application" in read_today(logdir)


def test_the_access_log_is_not_written(logdir):
    logging.getLogger("uvicorn.access").warning("GET /x 404")

    assert "GET /x 404" not in read_today(logdir)


def test_installing_twice_does_not_duplicate_lines(logdir):
    install_error_log(str(logdir), 30, 20)
    logging.getLogger("app.test").warning("only once")

    assert read_today(logdir).count("only once") == 1


def test_a_new_day_starts_a_new_file_and_old_files_are_pruned(tmp_path):
    for age in (0, 29, 30, 45):
        day = (datetime.now(timezone.utc) - timedelta(days=age)).strftime("%Y-%m-%d")
        (tmp_path / f"auth-service-errors-{day}.log").write_text("old\n")
    (tmp_path / "keep-me.txt").write_text("not a log of ours\n")

    handler = DailyErrorFileHandler(str(tmp_path), retention_days=30)
    handler.close()

    names = sorted(p.name for p in tmp_path.iterdir())
    kept = [n for n in names if n.startswith("auth-service-errors-")]
    assert len(kept) == 2  # today and 29 days ago are the last 30 days; 30 and 45 days ago are gone
    assert "keep-me.txt" in names


def test_records_of_another_day_go_to_that_days_file(tmp_path):
    handler = DailyErrorFileHandler(str(tmp_path))
    tomorrow = datetime.now(timezone.utc) + timedelta(days=1)
    record = logging.LogRecord("app.test", logging.WARNING, __file__, 1, "next day", None, None)
    record.created = tomorrow.timestamp()

    handler.handle(record)
    handler.close()

    assert "next day" in (tmp_path / f"auth-service-errors-{tomorrow.strftime('%Y-%m-%d')}.log").read_text()


def test_a_day_stops_at_the_size_limit(tmp_path):
    handler = DailyErrorFileHandler(str(tmp_path), max_file_bytes=500)
    for i in range(100):
        handler.handle(logging.LogRecord("app.test", logging.ERROR, __file__, 1, f"line {i} " + "x" * 50, None, None))
    handler.close()

    path = tmp_path / f"auth-service-errors-{TODAY}.log"
    assert path.stat().st_size < 500 + 200
    assert "size limit" in path.read_text()


def test_an_unusable_directory_does_not_stop_the_service(tmp_path, capsys):
    blocker = tmp_path / "a-file"
    blocker.write_text("")

    assert install_error_log(str(blocker / "logs"), 30, 20) is None
    logging.getLogger("app.test").warning("still works")  # must not raise

    assert "no error log file" in capsys.readouterr().err


# ----- what the application logs, and what it must not -----

@pytest.fixture
def client(logdir):
    db = FakeDb()
    users = FakeUserService([_user("alice")])
    app.dependency_overrides[get_user_service] = lambda: users
    app.dependency_overrides[get_application_service] = lambda: FakeApplicationService()
    app.dependency_overrides[get_refresh_token_service] = lambda: RefreshTokenService(db)
    yield TestClient(app), db
    app.dependency_overrides.clear()


def test_failed_login_is_logged_without_the_password(client, logdir):
    http, _ = client

    http.post("/auth/login", data={"username": "alice\nfake line", "password": "hunter2-secret"})

    text = read_today(logdir)
    assert re.search(r"WARNING app\.api\.routes\.auth_routes event=login_failed login='alice\\nfake line'", text)
    assert "hunter2-secret" not in text
    assert len(text.splitlines()) == 1  # the line break in the login did not start a second line


def test_refresh_reuse_is_a_warning_with_user_and_family_but_no_token(client, logdir):
    http, db = client
    login = http.post("/auth/login", data={"username": "alice", "password": PASSWORD}).json()
    spent = login["refresh_token"]
    http.post("/auth/refresh", json={"refresh_token": spent})
    db.collection.docs[0]["used_at"] -= REUSE_GRACE + timedelta(seconds=1)
    family = db.collection.docs[0]["family_id"]

    assert http.post("/auth/refresh", json={"refresh_token": spent}).status_code == 401

    text = read_today(logdir)
    assert f"WARNING app.services.refresh_token_service event=refresh_token_reuse" in text
    assert "user_id=alice" in text and f"family_id={family}" in text
    for secret in (spent, login["access_token"], db.collection.docs[0]["token_hash"]):
        assert secret not in text


def test_invalid_refresh_tokens_are_warnings_with_a_reason(client, logdir):
    http, db = client
    http.post("/auth/refresh", json={"refresh_token": "made-up-token"})
    login = http.post("/auth/login", data={"username": "alice", "password": PASSWORD}).json()
    db.collection.docs[0]["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=1)
    http.post("/auth/refresh", json={"refresh_token": login["refresh_token"]})
    http.post("/auth/logout", json={"refresh_token": login["refresh_token"]})
    http.post("/auth/refresh", json={"refresh_token": login["refresh_token"]})

    text = read_today(logdir)
    assert "event=refresh_rejected reason=unknown_token" in text
    assert re.search(r"reason=expired user_id=alice family_id=\w+", text)
    assert "made-up-token" not in text and login["refresh_token"] not in text


def test_the_grace_window_is_not_a_warning(client, logdir):
    http, _ = client
    login = http.post("/auth/login", data={"username": "alice", "password": PASSWORD}).json()
    http.post("/auth/refresh", json={"refresh_token": login["refresh_token"]})

    assert http.post("/auth/refresh", json={"refresh_token": login["refresh_token"]}).status_code == 200
    assert read_today(logdir) == ""

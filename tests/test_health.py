from fastapi.testclient import TestClient

from app.main import app


def test_health_reports_status_and_version():
    body = TestClient(app).get("/health").json()
    assert body["status"] == "ok"
    assert body["version"]

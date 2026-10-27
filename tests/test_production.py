"""Settings, auth and merchant scoping, limits, headers, metrics, health, persistence, key rotation and migrations."""
import base64
import hashlib
import importlib
import json
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from pqcpayment import db, ops
from pqcpayment.fpe import generate_luhn_pan
from pqcpayment.hsm import QuantumSafeHSMVault

M32 = base64.b64encode(b"m" * 32).decode()
A32 = base64.b64encode(b"a" * 32).decode()
KEY = "pqcpayment_" + "x" * 40
HASHED = {f"sha256:{hashlib.sha256(KEY.encode()).hexdigest()}": {"user": "MERCH-A", "role": "merchant"}}
KEYS = {"k-a": {"user": "MERCH-A", "role": "merchant"}, "k-ops": {"user": "ops", "role": "payments_ops"},
        "k-kc": {"user": "kc", "role": "key_custodian"}, "k-aud": {"user": "asha", "role": "auditor"},
        "k-mon": {"user": "prom", "role": "monitor"}, "k-admin": {"user": "root", "role": "admin"}}
PAN = generate_luhn_pan("453201", 31337)


def prod_env(**over):
    env = {"PQCPAYMENT_ENV": "production", "PQCPAYMENT_API_KEYS": json.dumps(HASHED), "PQCPAYMENT_MASTER_KEY": M32,
           "PQCPAYMENT_AUDIT_KEY": A32, "PQCPAYMENT_DATABASE_URL": "sqlite://"}
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


def boot(monkeypatch, **env):
    for k in [k for k in os.environ if k.startswith("PQCPAYMENT_")]:
        monkeypatch.delenv(k)
    for k, v in env.items():
        monkeypatch.setenv(f"PQCPAYMENT_{k}", v)
    import pqcpayment.api as api

    return importlib.reload(api)


def test_production_settings_accepted():
    s = ops.load_settings(prod_env())
    assert s.production and not s.demo and s.secret["MASTER_KEY"] == b"m" * 32 and not s.ephemeral


@pytest.mark.parametrize("change, message", [
    ({"PQCPAYMENT_API_KEYS": None}, "API keys"),
    ({"PQCPAYMENT_MASTER_KEY": None}, "MASTER_KEY"),
    ({"PQCPAYMENT_AUDIT_KEY": None}, "AUDIT_KEY"),
    ({"PQCPAYMENT_DATABASE_URL": None}, "DATABASE_URL"),
    ({"PQCPAYMENT_API_KEYS": json.dumps({KEY: {"user": "MERCH-A", "role": "merchant"}})}, "sha256"),
    ({"PQCPAYMENT_API_KEYS": json.dumps({"sha256:" + "0" * 64: {"user": "x", "role": "root"}})}, "roles"),
    ({"PQCPAYMENT_MASTER_KEY": base64.b64encode(b"short").decode()}, "32 bytes"),
    ({"PQCPAYMENT_MASTER_KEY_PREVIOUS": base64.b64encode(b"p" * 40).decode()}, "32 bytes"),
    ({"PQCPAYMENT_AUDIT_KEY": base64.b64encode(b"short").decode()}, "at least 32"),
    ({"PQCPAYMENT_MASTER_KEY": "not base64!"}, "base64"),
    ({"PQCPAYMENT_CORS_ORIGINS": "*"}, "CORS"),
    ({"PQCPAYMENT_ENV": "prod"}, "development or production"),
    ({"PQCPAYMENT_DATABASE_URL": "mysql://x"}, "postgresql"),
])
def test_production_refuses_to_start(change, message):
    with pytest.raises(ops.ConfigError, match=message):
        ops.load_settings(prod_env(**change))


def test_no_public_bind_without_keys():
    with pytest.raises(ops.ConfigError, match="without API keys"):
        ops.load_settings({"PQCPAYMENT_HOST": "0.0.0.0"})
    assert ops.load_settings({"PQCPAYMENT_HOST": "0.0.0.0", "PQCPAYMENT_API_KEYS": json.dumps(HASHED)}).host == "0.0.0.0"
    dev = ops.load_settings({})
    assert dev.demo and set(dev.ephemeral) == {"MASTER_KEY", "AUDIT_KEY"} and dev.port == 8020


def test_serve_exits_with_a_readable_error():
    env = {k: v for k, v in os.environ.items() if not k.startswith("PQCPAYMENT_")}
    r = subprocess.run([sys.executable, "-m", "pqcpayment", "serve", "--host", "0.0.0.0"], env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and "configuration error" in r.stderr and "without API keys" in r.stderr


def test_roles_and_merchant_scoping(monkeypatch):
    c = TestClient(boot(monkeypatch, API_KEYS=json.dumps(KEYS)).app)
    assert c.post("/tokenize", json={"pan": PAN, "merchant_id": "MERCH-A"}).status_code == 401
    assert c.post("/tokenize", json={"pan": PAN, "merchant_id": "MERCH-A"}, headers={"x-api-key": "wrong"}).status_code == 401
    tok = c.post("/tokenize", json={"pan": PAN, "merchant_id": "MERCH-A"}, headers={"x-api-key": "k-a"})
    assert tok.status_code == 200
    token = tok.json()["token"]
    # a merchant key acts only for its own merchant, so it can't read another merchant's cards
    assert c.post("/tokenize", json={"pan": PAN, "merchant_id": "MERCH-B"}, headers={"x-api-key": "k-a"}).status_code == 403
    assert c.post("/detokenize", json={"token": token, "merchant_id": "MERCH-B"}, headers={"x-api-key": "k-a"}).status_code == 403
    assert c.post("/detokenize", json={"token": token, "merchant_id": "MERCH-A"}, headers={"x-api-key": "k-a"}).json()["pan"] == PAN
    assert c.post("/detokenize", json={"token": token, "merchant_id": "MERCH-A"}, headers={"authorization": "Bearer k-ops"}).status_code == 200
    assert c.post("/hsm/rotate", json={}, headers={"x-api-key": "k-ops"}).status_code == 403
    assert c.get("/hsm/status", headers={"x-api-key": "k-aud"}).status_code == 200
    assert c.post("/detokenize", json={"token": token, "merchant_id": "MERCH-A"}, headers={"x-api-key": "k-aud"}).status_code == 403
    assert c.post("/kem/handshake", json={}, headers={"x-api-key": "k-kc"}).status_code == 200
    assert c.post("/tokenize", json={"pan": PAN, "merchant_id": "MERCH-A"}, headers={"x-api-key": "k-kc"}).status_code == 403
    assert c.get("/bench", headers={"x-api-key": "k-kc"}).status_code == 403
    assert c.get("/metrics", headers={"x-api-key": "k-a"}).status_code == 403
    m = c.get("/metrics", headers={"x-api-key": "k-mon"})
    assert m.status_code == 200 and 'http_requests_total{method="POST",route="/tokenize",status="200"}' in m.text
    assert 'pqcpayment_decisions_total{decision="detokenized"}' in m.text and "errors_total" in m.text
    assert PAN not in m.text


def test_rate_limit(monkeypatch):
    c = TestClient(boot(monkeypatch, RATE_LIMIT="3").app)
    codes = [c.post("/kem/handshake", json={}).status_code for _ in range(5)]
    assert codes[:3] == [200] * 3 and codes[3:] == [429, 429]
    assert int(c.post("/kem/handshake", json={}).headers["retry-after"]) >= 1
    assert c.get("/healthz").status_code == 200  # probes are never limited


def test_body_size_cap(monkeypatch):
    c = TestClient(boot(monkeypatch, MAX_BODY_BYTES="200").app)
    assert c.post("/tokenize", json={"pan": PAN, "merchant_id": "M" * 64, "pad": "x" * 300}).status_code == 413

    def chunks():  # no content-length: the cap still holds
        for _ in range(20):
            yield b"a" * 100

    assert c.post("/tokenize", content=chunks(), headers={"content-type": "application/json"}).status_code == 413
    assert c.post("/tokenize", json={"pan": PAN}).status_code == 200


def test_headers_and_request_ids(monkeypatch):
    c = TestClient(boot(monkeypatch).app)
    r = c.post("/kem/handshake", json={}, headers={"x-request-id": "abc-123"})
    assert r.headers["x-request-id"] == "abc-123"
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert r.headers["content-security-policy"] == ops.API_CSP and r.headers["cache-control"] == "no-store"
    assert "unsafe-inline" in c.get("/").headers["content-security-policy"]
    assert len(c.get("/healthz", headers={"x-request-id": "bad id\n"}).headers["x-request-id"]) == 32
    assert "access-control-allow-origin" not in c.get("/healthz", headers={"origin": "https://evil.example"}).headers


def test_cors_only_for_listed_origins(monkeypatch):
    c = TestClient(boot(monkeypatch, CORS_ORIGINS="https://console.bank.example").app)
    ok = c.get("/healthz", headers={"origin": "https://console.bank.example"})
    assert ok.headers["access-control-allow-origin"] == "https://console.bank.example"
    assert "access-control-allow-origin" not in c.get("/healthz", headers={"origin": "https://evil.example"}).headers


def test_errors_do_not_leak(monkeypatch, capsys):
    api = boot(monkeypatch)

    @api.app.get("/boom")
    def boom():
        raise RuntimeError(f"secret detail: card {PAN}")

    c = TestClient(api.app)
    r = c.get("/boom")
    assert r.status_code == 500 and PAN not in r.text and r.json()["request_id"] == r.headers["x-request-id"]
    bad = c.post("/tokenize", json={"pan": PAN + "x"})
    assert bad.status_code == 422 and PAN not in bad.text
    bad = c.post("/tokenize", json={"pan": PAN + "0"})  # fits the pattern, fails Luhn
    assert bad.status_code == 400 and PAN not in bad.text
    assert c.post("/tokenize", content=b"{not json", headers={"content-type": "application/json"}).status_code == 422
    c.post("/tokenize", json={"pan": PAN})
    assert PAN not in "".join(line for line in capsys.readouterr().out.splitlines() if '"msg": "request"' in line)


def test_health_and_readiness(monkeypatch, tmp_path):
    url = f"sqlite:///{tmp_path / 'ready.db'}"
    api = boot(monkeypatch, DATABASE_URL=url, MASTER_KEY=M32)
    c = TestClient(api.app)
    assert c.get("/healthz").json() == {"status": "ok"}
    r = c.get("/readyz")
    assert r.status_code == 200 and r.json()["checks"] == {"database": True, "keys": True}
    wrong = TestClient(boot(monkeypatch, DATABASE_URL=url, MASTER_KEY=base64.b64encode(b"w" * 32).decode()).app)
    r = wrong.get("/readyz")  # epoch keys sealed under another master key: not ready
    assert r.status_code == 503 and r.json()["checks"]["keys"] is False
    api.store.dispose()
    monkeypatch.setattr(api.store, "connect", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    r = c.get("/readyz")
    assert r.status_code == 503 and r.json()["checks"]["database"] is False and "db down" not in r.text


def test_json_logs_carry_request_ids(capsys):
    ops.setup_logging("INFO")
    token = ops.request_id.set("rid-1")
    ops.log.info("hello", extra={"fields": {"n": 1}})
    ops.request_id.reset(token)
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["msg"] == "hello" and line["request_id"] == "rid-1" and line["n"] == 1 and line["level"] == "INFO"


def test_production_warns_about_unreviewed_crypto(monkeypatch, tmp_path, capsys):
    env = {k.removeprefix("PQCPAYMENT_"): v for k, v in prod_env(PQCPAYMENT_DATABASE_URL=f"sqlite:///{tmp_path / 'p.db'}").items()}
    boot(monkeypatch, **env)
    warnings = [json.loads(line) for line in capsys.readouterr().out.splitlines() if "UNREVIEWED" in line]
    assert warnings and warnings[0]["level"] == "WARNING" and "PCI" in warnings[0]["msg"]


def _url(tmp_path):
    """A fresh vault database: tmp SQLite, or TEST_DATABASE_URL emptied (a database for these tests only)."""
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        return f"sqlite:///{tmp_path / 'vault.db'}"
    with db.connect(url).begin() as c:
        for t in ("tokens", "records", "epochs", "audit_log"):
            c.execute(text("DELETE FROM " + t))
    return url


def test_vault_survives_a_restart_with_sealed_keys(tmp_path):
    url = _url(tmp_path)
    m, a = b"m" * 32, b"a" * 32
    v = QuantumSafeHSMVault(engine=db.connect(url), master_key=m, audit_key=a)
    merchant = f"M-RESTART-{os.urandom(3).hex()}"
    t1 = v.tokenize(PAN, merchant_id=merchant)["token"]
    v2 = QuantumSafeHSMVault(engine=db.connect(url), master_key=m, audit_key=a)  # a new process, same database
    assert v2.detokenize(t1, merchant_id=merchant)["pan"] == PAN
    v2.rotate_epoch(reason="restart test")
    v3 = QuantumSafeHSMVault(engine=db.connect(url), master_key=m, audit_key=a)
    assert v3.detokenize(t1, merchant_id=merchant)["legacy_token"] is True
    assert v3.verify_audit_log()["valid"]
    with v3.db.connect() as c:  # nothing in the database is a PAN or a raw key
        dump = " ".join(str(x) for t in ("epochs", "records", "tokens", "audit_log") for r in c.execute(text("SELECT * FROM " + t)) for x in r)
    assert PAN not in dump and base64.b64encode(v3.epochs[1].bdk).decode() not in dump

    # Master and audit key rotation: new keys seal and sign, previous keys still read and verify
    m2, a2 = b"n" * 32, b"b" * 32
    with pytest.raises(ValueError, match="unseal"):
        QuantumSafeHSMVault(engine=db.connect(url), master_key=m2, audit_key=a2).detokenize(t1, merchant_id=merchant)
    v4 = QuantumSafeHSMVault(engine=db.connect(url), master_key=m2, audit_key=a2, previous_master_keys=(m,), previous_audit_keys=(a,))
    assert v4.detokenize(t1, merchant_id=merchant)["pan"] == PAN
    v4.rotate_epoch(reason="sealed under the new master key")
    assert QuantumSafeHSMVault(engine=db.connect(url), master_key=m2, audit_key=a2, previous_master_keys=(m,)).epochs
    assert v4.verify_audit_log()["valid"]
    assert not QuantumSafeHSMVault(engine=db.connect(url), master_key=m2, audit_key=a2,
                                   previous_master_keys=(m,)).verify_audit_log()["valid"]  # old entries need the old audit key


def test_replicas_share_one_vault(tmp_path):
    url = _url(tmp_path)
    keys = {"master_key": b"m" * 32, "audit_key": b"a" * 32}
    a = QuantumSafeHSMVault(engine=db.connect(url), **keys)
    b = QuantumSafeHSMVault(engine=db.connect(url), **keys)
    merchant = f"M-REPL-{os.urandom(3).hex()}"
    t = a.tokenize(PAN, merchant_id=merchant)
    assert b.detokenize(t["token"], merchant_id=merchant)["pan"] == PAN
    b.rotate_epoch(reason="replica b rotates")
    t2 = a.tokenize(PAN, merchant_id=merchant)  # replica a picks up the new epoch
    assert t2["epoch"] == b.active_epoch and t2["dukpt"]["counter"] == 1
    assert a.detokenize(t["token"], merchant_id=merchant)["legacy_token"] is True
    assert a.verify_audit_log()["valid"]


def test_migrations_apply_once(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    eng = db.engine(url)
    assert db.migrate(eng) == ["001_init.sql"]
    assert db.migrate(eng) == []
    with eng.connect() as c:
        assert [r[0] for r in c.execute(text("SELECT version FROM schema_migrations"))] == [1]
        tables = {r[0] for r in c.execute(text("SELECT name FROM sqlite_master WHERE type = 'table'"))}
    assert {"epochs", "records", "tokens", "audit_log"} <= tables
    env = {**{k: v for k, v in os.environ.items() if not k.startswith("PQCPAYMENT_")}, "PQCPAYMENT_DATABASE_URL": url}
    out = subprocess.run([sys.executable, "-m", "pqcpayment", "migrate"], env=env, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and "up to date" in out.stdout

import pytest
from fastapi.testclient import TestClient
from api.app import app, MAX_INPUT_BYTES

client = TestClient(app)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# POST /sanitize — basic behaviour
# ---------------------------------------------------------------------------

def test_sanitize_clean_text():
    r = client.post("/sanitize", json={"text": "Hello, world!"})
    assert r.status_code == 200
    body = r.json()
    assert body["text"] == "Hello, world!"
    assert body["findings"]["total"] == 0

def test_sanitize_strips_by_default():
    r = client.post("/sanitize", json={"text": "hello​world"})
    assert r.status_code == 200
    body = r.json()
    assert body["text"] == "helloworld"
    assert body["findings"]["removed_format"] == 1
    assert 0x200B in body["findings"]["codepoints"]

def test_sanitize_mark_mode():
    r = client.post("/sanitize", json={"text": "hello​world", "mode": "mark"})
    assert r.status_code == 200
    assert r.json()["text"] == "hello[U+200B]world"

def test_sanitize_control_char():
    r = client.post("/sanitize", json={"text": "a\x1bb"})
    assert r.status_code == 200
    body = r.json()
    assert body["text"] == "ab"
    assert body["findings"]["removed_control"] == 1

def test_sanitize_bidi_char():
    r = client.post("/sanitize", json={"text": "a‮b"})
    assert r.status_code == 200
    body = r.json()
    assert body["text"] == "ab"
    assert body["findings"]["removed_bidi"] == 1

def test_sanitize_findings_total_field():
    r = client.post("/sanitize", json={"text": "\x00​‮"})
    assert r.status_code == 200
    assert r.json()["findings"]["total"] == 3


# ---------------------------------------------------------------------------
# POST /sanitize — input validation
# ---------------------------------------------------------------------------

def test_sanitize_missing_text_field():
    r = client.post("/sanitize", json={})
    assert r.status_code == 422

def test_sanitize_invalid_mode():
    r = client.post("/sanitize", json={"text": "hello", "mode": "unknown"})
    assert r.status_code == 422

def test_sanitize_oversized_input():
    big = "a" * (MAX_INPUT_BYTES + 1)
    r = client.post("/sanitize", json={"text": big})
    assert r.status_code == 422

def test_sanitize_exactly_at_limit():
    ok = "a" * MAX_INPUT_BYTES
    r = client.post("/sanitize", json={"text": ok})
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# POST /sanitize/debug — always mark mode
# ---------------------------------------------------------------------------

def test_debug_forces_mark_mode():
    r = client.post("/sanitize/debug", json={"text": "hello​world"})
    assert r.status_code == 200
    assert r.json()["text"] == "hello[U+200B]world"

def test_debug_ignores_strip_mode_field():
    # Even if caller sends mode=strip, debug endpoint overrides to mark
    r = client.post("/sanitize/debug", json={"text": "a\x00b", "mode": "strip"})
    assert r.status_code == 200
    assert r.json()["text"] == "a[U+0000]b"

def test_debug_clean_text():
    r = client.post("/sanitize/debug", json={"text": "clean"})
    assert r.status_code == 200
    assert r.json()["text"] == "clean"
    assert r.json()["findings"]["total"] == 0

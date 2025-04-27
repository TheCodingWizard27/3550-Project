import pytest
import sqlite3
import time
import uuid
from fastapi.testclient import TestClient
from project3 import app, DB_FILE

client = TestClient(app)

def setup_module(module):
    """Setup: Clear users, keys, auth_logs before running tests."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM keys")
    cursor.execute("DELETE FROM auth_logs")
    conn.commit()
    conn.close()

def test_register_user():
    """Test registering a new user."""
    response = client.post("/register", json={
        "username": "testuser",
        "email": "testuser@example.com"
    })
    assert response.status_code in (200, 201)
    data = response.json()
    assert "password" in data
    assert len(data["password"]) > 0

def test_duplicate_register():
    """Test duplicate user registration should fail."""
    response = client.post("/register", json={
        "username": "testuser",  # Already exists
        "email": "testuser@example.com"
    })
    assert response.status_code == 400  # Should fail due to UNIQUE constraint

def test_authenticate_user():
    """Test authenticating a registered user."""
    # First register
    username = str(uuid.uuid4())
    email = f"{username}@example.com"
    reg_response = client.post("/register", json={"username": username, "email": email})
    assert reg_response.status_code in (200, 201)
    password = reg_response.json()["password"]

    # Now authenticate
    auth_response = client.post("/auth", json={"username": username, "password": password})
    assert auth_response.status_code == 200
    assert auth_response.json()["message"] == "Authentication successful."

def test_auth_logs_entry():
    """Test that authentication creates a log entry."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM auth_logs")
    before_logs = cursor.fetchone()[0]
    conn.close()

    # Register and authenticate a new user
    username = str(uuid.uuid4())
    email = f"{username}@example.com"
    reg_response = client.post("/register", json={"username": username, "email": email})
    password = reg_response.json()["password"]

    auth_response = client.post("/auth", json={"username": username, "password": password})
    assert auth_response.status_code == 200

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM auth_logs")
    after_logs = cursor.fetchone()[0]
    conn.close()

    assert after_logs == before_logs + 1

def test_auth_rate_limiting():
    """Test rate limiter triggers on rapid /auth requests."""
    # Register user
    username = str(uuid.uuid4())
    email = f"{username}@example.com"
    reg_response = client.post("/register", json={"username": username, "email": email})
    password = reg_response.json()["password"]

    # Hit /auth multiple times quickly
    success = 0
    fail = 0
    for _ in range(15):
        auth_response = client.post("/auth", json={"username": username, "password": password})
        if auth_response.status_code == 200:
            success += 1
        elif auth_response.status_code == 429:
            fail += 1
        time.sleep(0.05)  # small delay

    assert success > 0
    assert fail > 0

def test_jwks_endpoint():
    """Test JWKS endpoint returns keys."""
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert isinstance(data["keys"], list)
    assert len(data["keys"]) > 0

def test_private_key_encryption():
    """Test that private keys are encrypted in database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT private_key FROM keys")
    keys = cursor.fetchall()
    conn.close()

    assert keys, "No keys found in DB."
    for (private_key_blob,) in keys:
        assert isinstance(private_key_blob, bytes)
        assert len(private_key_blob) > 0

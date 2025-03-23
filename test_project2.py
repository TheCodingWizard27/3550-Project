import pytest
import sqlite3
import time
from fastapi.testclient import TestClient
from project2 import app, DB_FILE, generate_rsa_key

# Creating the test client
client = TestClient(app)

def setup_module(module):
    """Setting up the test database before tests run."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM keys")  # Clearing previous test data
    conn.commit()
    conn.close()
    # Adding test keys
    generate_rsa_key(int(time.time()) - 10)  # Expired keys
    generate_rsa_key(int(time.time()) + 3600)  # Valid keys

def test_auth_valid():
    """Testing the /auth endpoint with a valid key."""
    response = client.post("/auth")
    assert response.status_code == 200
    assert "token" in response.json()

def test_auth_expired():
    """Testing the /auth endpoint with an expired key."""
    response = client.post("/auth?expired=true")
    assert response.status_code == 404  # No valid expired keys should be returned

def test_jwks():
    """Testing the JWKS endpoint for fetching public keys."""
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert isinstance(data["keys"], list)
    assert len(data["keys"]) > 0  # It should have at least one valid key

def test_auth_invalid_method():
    """Testing invalid HTTP method on /auth endpoint."""
    response = client.get("/auth")
    assert response.status_code == 405  # This method should not be allowed

def test_jwks_invalid_method():
    """Testing invalid HTTP method on JWKS endpoint."""
    response = client.post("/.well-known/jwks.json")
    assert response.status_code == 405  # This method should not be allowed
# To run tests: pytest --cov=project2 --cov-report=term-missing
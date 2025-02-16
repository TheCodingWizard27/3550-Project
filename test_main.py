import jwt
import json
import time
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from project1 import app, key_store, generate_and_store_key, KEY_EXPIRY_TIME

client = TestClient(app)

def test_generate_and_store_key():
    kid = generate_and_store_key()
    assert kid in key_store
    assert "private_key" in key_store[kid]
    assert "public_key" in key_store[kid]
    assert "expiry" in key_store[kid]
    assert key_store[kid]["expiry"] > time.time()

def test_get_jwks():
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert isinstance(data["keys"], list)
    for key in data["keys"]:
        assert "kty" in key
        assert "n" in key
        assert "e" in key
        assert "alg" in key
        assert "use" in key
        assert "kid" in key

def test_authenticate_valid_key():
    response = client.post("/auth")
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    token = data["token"]
    
    # Verify JWT structure
    header = jwt.get_unverified_header(token)
    assert "kid" in header
    assert header["alg"] == "RS256"

    payload = jwt.decode(token, options={"verify_signature": False})
    assert "sub" in payload
    assert "exp" in payload
    assert payload["sub"] == "user123"

def test_authenticate_expired_key():
    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    token = data["token"]
    
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["exp"] < time.time()  # Ensure the token is expired

def test_no_valid_keys():
    with patch("time.time", return_value=9999999999):  # Fast forward time
        response = client.post("/auth")
        assert response.status_code == 500
        assert response.json()["detail"] == "No valid keys available"

def test_expired_keys_cleanup():
    kid = generate_and_store_key()
    key_store[kid]["expiry"] = time.time() - 1  # Expire the key
    
    time.sleep(1.5)  # Wait for the cleanup thread to run
    assert kid not in key_store

if __name__ == "__main__":
    pytest.main()

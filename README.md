# JWT Auth Server with SQLite Key Management

## Overview

This FastAPI project implements a secure JWT issuance server using dynamically generated RSA key pairs stored in a local SQLite database. The server supports issuing tokens with both valid and expired keys, and exposes a JWKS (JSON Web Key Set) endpoint for token verification.

## Features

- 🔐 RSA key pair generation
- 🗂️ SQLite-based key storage with expiration tracking
- 🔁 Issuance of JWTs using valid or expired private keys
- 🌐 JWKS endpoint exposing public keys in JSON Web Key Set format
- ⚡ FastAPI-powered asynchronous API

## Technologies Used

- **FastAPI** – API framework
- **SQLite** – Key database storage
- **Cryptography** – RSA key generation and serialization
- **PyJWT** – JWT encoding
- **Base64 / JSON / Time** – Token metadata utilities

## You can run the server using:
```
uvicorn project2:app --host 127.0.0.1 --port 8000 --reload
```

## JWT Auth Server

Once the server is running, you can access the following endpoints:

- **JWKS Endpoint:**  
  `http://127.0.0.1:8000/.well-known/jwks.json`

- **Authentication Endpoint:**  
  `POST /auth`

## API Endpoints

1. **Get JSON Web Key Set (JWKS)**  
   **Endpoint:** `GET /.well-known/jwks.json`  
   → Returns all non-expired public keys in JWKS format, which can be used to verify JWTs issued by this server.

2. **Authenticate & Get a JWT Token**  
   **Endpoint:** `POST /auth`  
   → Issues a JWT token signed with an RSA private key from the database.  
   → Supports the optional query parameter `expired=true` to test expired key behavior.


## Running Tests:

This project includes a test suite using pytest. 
To run the tests, execute:
```
pytest --cov=project2 --cov-report=term-missing
```

This ensures 90%+ test coverage, validating key functionality such as:
- RSA key generation and rotation
- JWT issuance with valid and expired keys
- JWKS endpoint response
- Expired key cleanup

# 🔐 JWT Auth Server with Encrypted Key Storage and User Management

## Overview

This FastAPI project implements a secure JWT authentication server with dynamic RSA key management and encrypted private key storage using AES.  
The server supports user registration with secure password hashing, authentication logging, and rate limiting to enhance security and resilience.

---

## ✨ Features

- 🔐 RSA key pair generation and AES-encrypted private key storage
- 🧑‍💻 Secure user registration with Argon2 password hashing
- 🔐 JWT issuance using valid private keys
- 🐂️ SQLite-based storage for keys, users, and authentication logs
- 🌐 JWKS (JSON Web Key Set) endpoint for public key retrieval
- 🛡️ Rate limiting to prevent abuse (10 requests per second on `/auth`)
- 📜 Authentication request logging (IP, timestamp, user ID)
- ⚡ Built with FastAPI for high performance

---

## 🚀 Technologies Used

- **FastAPI** – Web framework
- **SQLite** – Local database for keys, users, logs
- **Cryptography** – RSA and AES encryption
- **PyJWT** – JWT token encoding
- **Passlib (Argon2)** – Secure password hashing
- **UUID** – Secure password generation
- **Time / JSON / Base64** – Utilities
- **pytest** – Automated testing with coverage reports

---

## 📦 Running the Server

1. Set your AES encryption key as an environment variable:

   ```bash
   export NOT_MY_KEY="your-256-bit-secret-key-here"
   ```

   > (The `NOT_MY_KEY` must be a secure 32-byte (256-bit) key.)

2. Start the server locally:

   ```bash
   uvicorn project3:app --host 127.0.0.1 --port 8080 --reload
   ```

---

## 🌐 Available API Endpoints

### 1. Register a New User

**Endpoint:** `POST /register`

**Request JSON:**
```json
{
  "username": "myusername",
  "email": "myemail@example.com"
}
```

**Response JSON:**
```json
{
  "password": "generated-uuid-password"
}
```

- The server generates a secure UUIDv4 password and stores a hashed version (Argon2) in the database.

---

### 2. Authenticate User

**Endpoint:** `POST /auth`

**Request JSON:**
```json
{
  "username": "myusername",
  "password": "your-password-here"
}
```

**Response JSON:**
```json
{
  "message": "Authentication successful."
}
```

- Upon successful login, the authentication event is logged with IP address, timestamp, and user ID.
- ⚠️ **Rate Limiting:** Only 10 requests per second are allowed. Exceeding the limit returns HTTP 429.

---

### 3. Fetch JSON Web Key Set (JWKS)

**Endpoint:** `GET /.well-known/jwks.json`

- Retrieves the public keys used for verifying JWTs issued by this server.

---

## 🧪 Running Tests

This project includes a comprehensive test suite using `pytest`.

To run all tests with coverage report:

```bash
pytest test_project3.py --cov=project3 --cov-report=term-missing
```

The test suite verifies:
- User registration and password generation
- Password hashing and authentication
- JWT issuance and public key exposure
- Rate limiter behavior
- Private key encryption storage
- Authentication request logging

---


## 🔥 Notes

- Private keys are AES-encrypted using the `NOT_MY_KEY` environment variable.
- Authentication rate limiting protects against potential DoS attacks.
- Passwords are **never** stored in plain text (only Argon2 hashes are saved).

---
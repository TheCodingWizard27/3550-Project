import sqlite3
import base64
import uuid
import time
import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from collections import defaultdict


DB_FILE = "totally_not_my_privateKeys.db"
AES_KEY = base64.urlsafe_b64decode(os.getenv("NOT_MY_KEY", "MISSING_KEY" * 4))[:32]
RATE_LIMIT = 10
RATE_PERIOD = 1


app = FastAPI()
ph = PasswordHasher()
rate_limit_tracker = defaultdict(list)


def encrypt_data(data: bytes):
   iv = os.urandom(16)
   cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())
   encryptor = cipher.encryptor()
   encrypted_data = encryptor.update(data) + encryptor.finalize()
   return encrypted_data, iv


class RegisterRequest(BaseModel):
   username: str
   email: str


class AuthRequest(BaseModel):
   username: str
   password: str


def init_db():
   conn = sqlite3.connect(DB_FILE)
   cursor = conn.cursor()
   cursor.execute("DROP TABLE IF EXISTS keys")
   cursor.execute("""
       CREATE TABLE keys (
           kid INTEGER PRIMARY KEY AUTOINCREMENT,
           private_key BLOB NOT NULL,
           iv BLOB NOT NULL,
           public_key TEXT NOT NULL
       )
   """)
   cursor.execute("""
       CREATE TABLE IF NOT EXISTS users(
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           username TEXT NOT NULL UNIQUE,
           password_hash TEXT NOT NULL,
           email TEXT UNIQUE,
           date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
           last_login TIMESTAMP
       )
   """)
   cursor.execute("""
       CREATE TABLE IF NOT EXISTS auth_logs(
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           request_ip TEXT NOT NULL,
           request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
           user_id INTEGER,
           FOREIGN KEY(user_id) REFERENCES users(id)
       )
   """)
   conn.commit()
   conn.close()


init_db()


@app.middleware("http")
async def rate_limiter(request: Request, call_next):
   if request.url.path == "/auth":
       ip = request.client.host
       now = time.time()
       rate_limit_tracker[ip] = [ts for ts in rate_limit_tracker[ip] if now - ts < RATE_PERIOD]
       if len(rate_limit_tracker[ip]) >= RATE_LIMIT:
           return JSONResponse(status_code=429, content={"detail": "Too Many Requests"})
       rate_limit_tracker[ip].append(now)


   response = await call_next(request)
   return response


@app.post("/register")
async def register_user(data: RegisterRequest):
   password = str(uuid.uuid4())
   hashed_password = ph.hash(password)
   conn = sqlite3.connect(DB_FILE)
   try:
       cursor = conn.cursor()
       cursor.execute(
           """
           INSERT INTO users (username, email, password_hash)
           VALUES (?, ?, ?)
           """,
           (data.username, data.email, hashed_password)
       )
       conn.commit()
   except sqlite3.IntegrityError:
       raise HTTPException(status_code=400, detail="Username or Email already exists.")
   finally:
       conn.close()


   return {"password": password}


@app.post("/auth")
async def authenticate_user(request: Request, data: AuthRequest):
   conn = sqlite3.connect(DB_FILE)
   try:
       cursor = conn.cursor()
       cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (data.username,))
       user = cursor.fetchone()


       if not user:
           raise HTTPException(status_code=401, detail="Invalid username or password.")


       user_id, password_hash = user


       try:
           ph.verify(password_hash, data.password)
       except VerifyMismatchError:
           raise HTTPException(status_code=401, detail="Invalid username or password.")


       cursor.execute(
           """
           INSERT INTO auth_logs (request_ip, user_id)
           VALUES (?, ?)
           """,
           (request.client.host, user_id)
       )
       conn.commit()
   finally:
       conn.close()


   return {"message": "Authentication successful."}


@app.post("/generate-key")
async def generate_key():
   key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


   private_bytes = key.private_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PrivateFormat.PKCS8,
       encryption_algorithm=serialization.NoEncryption()
   )


   public_bytes = key.public_key().public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
   )


   encrypted_key, iv = encrypt_data(private_bytes)


   conn = sqlite3.connect(DB_FILE)
   try:
       cursor = conn.cursor()
       cursor.execute(
           """
           INSERT INTO keys (private_key, iv, public_key)
           VALUES (?, ?, ?)
           """,
           (encrypted_key, iv, public_bytes.decode('utf-8'))
       )
       conn.commit()
   finally:
       conn.close()


   return {"message": "Key generated and stored securely."}


import sqlite3
import jwt
import json
import time
import base64
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

DB_FILE = "totally_not_my_privateKeys.db"
app = FastAPI()

# Initializing Database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
                        kid INTEGER PRIMARY KEY AUTOINCREMENT,
                        key TEXT NOT NULL,
                        exp INTEGER NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

# Generating and Storing the Private Key
def generate_rsa_key(expiration):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (private_pem, expiration))
    conn.commit()
    conn.close()

# Ensuring we have at least one valid and one expired key
generate_rsa_key(int(time.time()) - 10)  # Expired Key
generate_rsa_key(int(time.time()) + 3600)  # Valid Key


# Fetching the Private Key from the DB
def get_private_key(expired=False):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    current_time = int(time.time())
    query = "SELECT kid, key FROM keys WHERE exp {} ? ORDER BY exp DESC LIMIT 1".format("<" if expired else ">")
    cursor.execute(query, (current_time,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="No appropriate key found")
    return row

# POST: /auth - Generate JWT
def create_jwt(private_key_pem, kid):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(), password=None
    )
    now = int(time.time())
    payload = {"sub": "user123", "exp": now + 600, "iat": now}
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": str(kid)})
    return token

@app.post("/auth")
def auth(expired: bool = Query(False)):
    kid, private_key_pem = get_private_key(expired)
    token = create_jwt(private_key_pem, kid)
    return {"token": token}
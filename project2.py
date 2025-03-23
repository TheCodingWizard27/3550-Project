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

# Initialize Database
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
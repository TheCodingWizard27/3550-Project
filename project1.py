# Importing the required Libraries
import jwt
import json
import threading
import time
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from typing import Dict, List

app = FastAPI() # Creating an instance of FastAPI() object and storing it in app

key_store = {} # Dictionary used for storing keys

KEY_EXPIRY_TIME = 600 # Key expiry time set for 10 minutes


# Function for generating a RSA Key pair (Private and Public)
def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    public_key = private_key.public_key()
    
    # Converting the private key to a PEM format
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    
    # Converting the public key to a PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    
    return private_pem, public_pem
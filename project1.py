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


# Function for generating a RSA Key
def generate_rsa_key():
    
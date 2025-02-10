import time
import uuid
import jwt
import base64
import logging
from fastapi import FastAPI, Query
from cryptography.hazmat.primitives.asymmetric import rsa

# Init FastAPI app
app = FastAPI()

# Basic logging 
logging.basicConfig(level=logging.INFO)


# Generate RSA key pair 
def generate_rsa_key():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


# Converts public key to JSON  
def convert_pubkey_to_jwk(pub_key, key_id):
    pub_nums = pub_key.public_numbers()
    return {
        "kid": key_id,
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": base64.urlsafe_b64encode(
            pub_nums.n.to_bytes((pub_nums.n.bit_length() + 7) // 8, "big")
        )
        .decode("utf-8")
        .rstrip("="),
        "e": base64.urlsafe_b64encode(
            pub_nums.e.to_bytes((pub_nums.e.bit_length() + 7) // 8, "big")
        )
        .decode("utf-8")
        .rstrip("="),
    }


# Generate RSA key with expiration
def create_key_pair(expire_in_sec=1200):
    priv, pub = generate_rsa_key()
    return {
        "kid": str(uuid.uuid4()),  # Random key ID
        "private": priv,
        "public": pub,
        "expires_at": int(time.time()) + expire_in_sec,
    }


# Store active and expired keys 
keys = {
    "active_key": create_key_pair(),
    "old_key": create_key_pair(-100),  # Expired key
}


# Generates JWT using active or expired keys
def make_jwt(use_expired=False):
    selected_key = keys["old_key"] if use_expired else keys["active_key"]

    # Show log info
    logging.info(f"Creating JWT with key ID: {selected_key['kid']}")

    payload = {
        "sub": "test_user",
        "iat": int(time.time()),
        "exp": int(
            time.time() + (1200 if not use_expired else -1200)
        ),  # Set expired 
    }

    # JWT token
    token = jwt.encode(
        payload,
        selected_key["private"],
        algorithm="RS256",
        headers={"kid": selected_key["kid"]},
    )

    return token


# JWKS return valid keys
@app.get("/.well-known/jwks.json")
def jwks():
    now = int(time.time())
    jwks_keys = []

    # Convert valid public keys
    for k in keys.values():
        if k["expires_at"] > now:
            jwks_keys.append(convert_pubkey_to_jwk(k["public"], k["kid"]))

    logging.info("JWKS requested, serving keys")
    return {"keys": jwks_keys}


# Get JWT auth
@app.post("/auth")
def auth(expired: bool = Query(False)):
    return {"token": make_jwt(expired)}


# Testing
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8080, reload=True)

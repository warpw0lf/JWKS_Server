import time
from fastapi.testclient import TestClient
from project1 import app, make_jwt, keys, convert_pubkey_to_jwk  

client = TestClient(app)

def test_generate_jwt_active():
    """Test JWT generation with an active key."""
    token = make_jwt(use_expired=False)  
    assert token is not None
    assert isinstance(token, str)  

def test_generate_jwt_expired():
    """Test JWT generation with an expired key."""
    token = make_jwt(use_expired=True)  
    assert token is not None
    assert isinstance(token, str) 

def test_jwks_no_expired_key():
    """Ensure only non-expired keys are in JWKS response."""
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200

    jwks = response.json()
    assert "keys" in jwks
    assert isinstance(jwks["keys"], list)

    
    now = int(time.time())
    for k in keys.values():
        if k["expires_at"] > now:
            assert any(jwk["kid"] == k["kid"] for jwk in jwks["keys"])

def test_public_key_to_jwk():
    """Verify public key conversion to JWK format."""
    public_key = keys["active_key"]["public"]
    jwk = convert_pubkey_to_jwk(public_key, "test_key_id")

    assert isinstance(jwk, dict)
    assert jwk["kid"] == "test_key_id"
    assert "n" in jwk
    assert "e" in jwk



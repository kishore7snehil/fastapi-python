import os
import time
from typing import Dict, Any, Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from authlib.jose import jwt
from authlib.jose.errors import JoseError


def derive_encryption_secret(secret: str, salt: str) -> bytes:
    """Derive an encryption key using HKDF."""
    encoder = lambda s: s.encode("utf-8")
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=encoder(salt),
        info=encoder("derived cookie encryption secret"),
    ).derive(encoder(secret))
    
    return key


def encrypt(payload: Dict[str, Any], secret: str, salt: str) -> str:
    """Encrypt payload using JWE."""
    encryption_secret = derive_encryption_secret(secret, salt)
    
    # Use authlib to encrypt
    header = {"alg": "A256KW", "enc": "A256GCM"}
    jwe = jwt.encode(header, payload, encryption_secret)
    return jwe.decode("utf-8")


def decrypt(value: str, secret: str, salt: str) -> Dict[str, Any]:
    """Decrypt JWE payload."""
    encryption_secret =  derive_encryption_secret(secret, salt)
    
    try:
        # Use authlib to decrypt with 10s clock tolerance
        claims = jwt.decode(
            value,
            encryption_secret,
            claims_options={"exp": {"essential": True}},
            clock_skew=10
        )
        return claims
    except JoseError as e:
        raise ValueError(f"Failed to decrypt: {str(e)}")
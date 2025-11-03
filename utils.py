# utils.py
import json
import time
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

__all__ = [
    "derive_fernet_key",
    "make_fernet_from_password",
    "fernet_from_base64",
    "make_packet",
    "parse_packet",
]

def derive_fernet_key(password: str, salt: bytes) -> bytes:
    """Derive a URL-safe base64 Fernet key from (password, salt) using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

def make_fernet_from_password(password: str, salt: bytes) -> Fernet:
    """Return a Fernet object derived from a password and salt."""
    key = derive_fernet_key(password, salt)
    return Fernet(key)

def fernet_from_base64(key_b64: str) -> Fernet:
    """Return a Fernet object from a base64-encoded key (as printed by keygen.py)."""
    return Fernet(key_b64.encode())

def make_packet(src: str, dst: str, ptype: str, data: bytes) -> bytes:
    """
    Create a JSON tunnel packet and return the bytes.
    - data is stored using latin1 so raw bytes round-trip safely through JSON (OK for demo).
    - 'len' contains the byte-length of the data payload.
    """
    pkt = {
        "header": "VPNv1",
        "src": src,
        "dst": dst,
        "type": ptype,
        "timestamp": time.time(),
        "len": len(data),
        "data": data.decode("latin1"),
    }
    return json.dumps(pkt).encode()

def parse_packet(packet_bytes: bytes):
    """
    Parse a packet created by make_packet.
    Returns: (src, dst, type, data_bytes)
    Raises ValueError on malformed packet.
    """
    try:
        obj = json.loads(packet_bytes.decode())
    except Exception as e:
        raise ValueError(f"Invalid packet JSON: {e}")

    if not all(k in obj for k in ("src", "dst", "type", "data")):
        raise ValueError("Packet missing required fields")

    data = obj["data"].encode("latin1")
    return obj["src"], obj["dst"], obj["type"], data

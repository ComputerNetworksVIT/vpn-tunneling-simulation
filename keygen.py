# keygen.py
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import argparse

DEFAULT_ITERATIONS = 390_000

def derive_key_from_password(password: str, salt: bytes = None, iterations: int = DEFAULT_ITERATIONS):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def main():
    parser = argparse.ArgumentParser(description="Derive a Fernet key from a password.")
    parser.add_argument("--salt", help="Provide salt as hex to derive reproducibly (optional).")
    parser.add_argument("--out", help="Save key+salt to file (optional).")
    parser.add_argument("--iter", type=int, default=DEFAULT_ITERATIONS, help="PBKDF2 iterations (default 390000).")
    args = parser.parse_args()

    pwd = input("Enter a password to derive key: ").strip()
    if args.salt:
        try:
            salt = bytes.fromhex(args.salt)
        except Exception as e:
            print("Invalid salt hex:", e)
            return
    else:
        salt = None

    key, salt = derive_key_from_password(pwd, salt=salt, iterations=args.iter)

    print("\nFernet key (save & share securely):", key.decode())
    print("Salt (hex) — save this too:", salt.hex())
    print("PBKDF2 iterations:", args.iter)

    if args.out:
        try:
            with open(args.out, "w") as f:
                f.write(f"FernetKey={key.decode()}\n")
                f.write(f"Salt={salt.hex()}\n")
                f.write(f"Iterations={args.iter}\n")
            print("Saved key+salt to", args.out)
        except Exception as e:
            print("Failed to save file:", e)

if __name__ == "__main__":
    main()

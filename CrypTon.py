#!/usr/bin/env python3
"""
crypto_tool.py

Simple cross-platform Encryption / Decryption Tool (CLI)
Features:
 - AES-256-GCM symmetric encrypt/decrypt (text & file)
 - PBKDF2-HMAC-SHA256 password-derived key encryption
 - RSA-4096 keygen + RSA-OAEP encrypt/decrypt (small payloads)
 - Hybrid: encrypt file with AES, wrap AES key with RSA public key

Usage examples:
  python crypto_tool.py genrsa --priv private.pem --pub public.pem
  python crypto_tool.py aes-encrypt --out secret.json --text "hello"
  python crypto_tool.py aes-decrypt --in secret.json
  python crypto_tool.py pbe-encrypt --pass "mypw" --in file.txt --out file.enc
  python crypto_tool.py pbe-decrypt --pass "mypw" --in file.enc --out file.dec
  python crypto_tool.py rsa-encrypt --pub public.pem --in small.txt --out small.enc
  python crypto_tool.py rsa-decrypt --priv private.pem --in small.enc --out small.dec
  python crypto_tool.py hybrid-encrypt --pub public.pem --in bigfile.bin --out big.enc
  python crypto_tool.py hybrid-decrypt --priv private.pem --in big.enc --out big.dec

Note: This is a utility for learning/ops. Review & audit before using for critical production data.
"""
import argparse
import json
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

import secrets

# ---- Utils -----------------------------------------------------------------

def b64enc(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

def b64dec(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

def write_json_b64(obj, path):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def read_json_b64(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

# ---- AES-GCM symmetric -----------------------------------------------------

def aes_gcm_encrypt_bytes(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> dict:
    # key: 32 bytes (AES-256)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96-bit nonce recommended
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    # AESGCM returns ciphertext||tag; keep as single blob
    return {"nonce": b64enc(nonce), "ciphertext": b64enc(ct)}

def aes_gcm_decrypt_bytes(key: bytes, payload: dict, associated_data: bytes | None = None) -> bytes:
    aesgcm = AESGCM(key)
    nonce = b64dec(payload['nonce'])
    ct = b64dec(payload['ciphertext'])
    return aesgcm.decrypt(nonce, ct, associated_data)

def generate_aes_key() -> bytes:
    return secrets.token_bytes(32)  # 256-bit

# ---- Password-based key derivation (PBKDF2) -------------------------------

def derive_key_from_password(password: str, salt: bytes = None, iterations: int = 200_000) -> (bytes, bytes, int):
    if salt is None:
        salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key, salt, iterations

# ---- RSA operations --------------------------------------------------------

def rsa_generate_keypair(bits: int = 4096):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    pub = priv.public_key()
    return priv, pub

def rsa_serialize_private(priv, path: str, passphrase: str | None = None):
    enc = serialization.NoEncryption()
    if passphrase:
        enc = serialization.BestAvailableEncryption(passphrase.encode('utf-8'))
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )
    with open(path, 'wb') as f:
        f.write(pem)

def rsa_serialize_public(pub, path: str):
    pem = pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(path, 'wb') as f:
        f.write(pem)

def rsa_load_private(path: str, passphrase: str | None = None):
    with open(path, 'rb') as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=passphrase.encode('utf-8') if passphrase else None, backend=default_backend())

def rsa_load_public(path: str):
    with open(path, 'rb') as f:
        data = f.read()
    return serialization.load_pem_public_key(data, backend=default_backend())

def rsa_encrypt_with_public(pub, plaintext: bytes) -> bytes:
    ct = pub.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return ct

def rsa_decrypt_with_private(priv, ciphertext: bytes) -> bytes:
    pt = priv.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return pt

# ---- Hybrid file encrypt (AES key wrapped by RSA) -------------------------

def hybrid_encrypt_file(pubkey_path: str, infile: str, outfile: str):
    pub = rsa_load_public(pubkey_path)
    # read file
    with open(infile, 'rb') as f:
        data = f.read()
    # generate symmetric key and encrypt data with AES-GCM
    key = generate_aes_key()
    aes_payload = aes_gcm_encrypt_bytes(key, data)
    # wrap AES key using RSA
    wrapped_key = rsa_encrypt_with_public(pub, key)
    out = {
        "mode": "hybrid-rsa-aes-gcm",
        "wrapped_key": b64enc(wrapped_key),
        "aes": aes_payload,
        "meta": {"orig_filename": os.path.basename(infile)}
    }
    write_json_b64(out, outfile)
    print(f"[+] Hybrid-encrypted {infile} -> {outfile}")

def hybrid_decrypt_file(privkey_path: str, infile: str, outfile: str, priv_pass: str | None = None):
    priv = rsa_load_private(privkey_path, priv_pass)
    j = read_json_b64(infile)
    if j.get("mode") != "hybrid-rsa-aes-gcm":
        raise ValueError("Not a hybrid-rsa-aes-gcm file")
    wrapped_key = b64dec(j["wrapped_key"])
    key = rsa_decrypt_with_private(priv, wrapped_key)
    plaintext = aes_gcm_decrypt_bytes(key, j["aes"])
    with open(outfile, 'wb') as f:
        f.write(plaintext)
    print(f"[+] Hybrid-decrypted {infile} -> {outfile}")

# ---- CLI handlers ---------------------------------------------------------

def cmd_genrsa(args):
    priv, pub = rsa_generate_keypair(bits=args.bits if args.bits else 4096)
    rsa_serialize_private(priv, args.priv, passphrase=args.passphrase)
    rsa_serialize_public(pub, args.pub)
    print(f"[+] Generated RSA keypair: priv={args.priv} pub={args.pub}")

def cmd_aes_encrypt(args):
    key = generate_aes_key()
    if args.keyfile:
        with open(args.keyfile, 'rb') as f:
            key = f.read()
    if args.text is not None:
        plaintext = args.text.encode('utf-8')
        payload = aes_gcm_encrypt_bytes(key, plaintext)
        out = {"mode":"aes-gcm", "key_used": b64enc(key) if args.dump_key else None, "payload": payload}
        write_json_b64(out, args.out)
        print(f"[+] Encrypted text -> {args.out}")
    else:
        with open(args.infile, 'rb') as f:
            plaintext = f.read()
        payload = aes_gcm_encrypt_bytes(key, plaintext)
        out = {"mode":"aes-gcm", "key_used": b64enc(key) if args.dump_key else None, "payload": payload, "meta":{"orig_filename": os.path.basename(args.infile)}}
        write_json_b64(out, args.out)
        print(f"[+] Encrypted file {args.infile} -> {args.out}")

def cmd_aes_decrypt(args):
    j = read_json_b64(args.infile)
    if j.get("mode") != "aes-gcm":
        raise ValueError("Input not aes-gcm mode")
    key = None
    if args.keyfile:
        with open(args.keyfile, 'rb') as f:
            key = f.read()
    elif j.get("key_used"):
        key = b64dec(j["key_used"])
    else:
        raise ValueError("No key provided (use --keyfile or ensure the file contains key_used)")
    try:
        pt = aes_gcm_decrypt_bytes(key, j["payload"])
    except InvalidTag:
        print("[!] Decryption failed: Invalid authentication tag (tampered or wrong key)")
        return
    if args.out:
        with open(args.out, 'wb') as f:
            f.write(pt)
        print(f"[+] Decrypted -> {args.out}")
    else:
        print(pt.decode('utf-8', errors='replace'))

def cmd_pbe_encrypt(args):
    # derive key from password
    key, salt, iterations = derive_key_from_password(args.password, None)
    # read input
    with open(args.infile, 'rb') as f:
        data = f.read()
    payload = aes_gcm_encrypt_bytes(key, data)
    out = {"mode":"pbe-aes-gcm", "kdf":{"salt":b64enc(salt), "iterations":iterations}, "payload": payload, "meta":{"orig_filename": os.path.basename(args.infile)}}
    write_json_b64(out, args.out)
    print(f"[+] PBE-encrypted {args.infile} -> {args.out}")

def cmd_pbe_decrypt(args):
    j = read_json_b64(args.infile)
    if j.get("mode") != "pbe-aes-gcm":
        raise ValueError("Input not pbe-aes-gcm mode")
    salt = b64dec(j["kdf"]["salt"])
    iterations = int(j["kdf"]["iterations"])
    # derive key with given salt and iterations
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations, backend=default_backend())
    key = kdf.derive(args.password.encode('utf-8'))
    try:
        pt = aes_gcm_decrypt_bytes(key, j["payload"])
    except InvalidTag:
        print("[!] Decryption failed: invalid tag (wrong password or corrupted file)")
        return
    with open(args.out, 'wb') as f:
        f.write(pt)
    print(f"[+] PBE-decrypted {args.infile} -> {args.out}")

def cmd_rsa_encrypt(args):
    pub = rsa_load_public(args.pub)
    # small payload mode: read as bytes
    with open(args.infile, 'rb') as f:
        data = f.read()
    # RSA-OAEP can only encrypt up to k-2*hLen-2 bytes -> usually small (few hundred bytes)
    ct = rsa_encrypt_with_public(pub, data)
    out = {"mode":"rsa-oaep", "ciphertext": b64enc(ct), "meta":{"orig_filename": os.path.basename(args.infile)}}
    write_json_b64(out, args.out)
    print(f"[+] RSA-encrypted {args.infile} -> {args.out}")

def cmd_rsa_decrypt(args):
    priv = rsa_load_private(args.priv, passphrase=args.passphrase)
    j = read_json_b64(args.infile)
    if j.get("mode") != "rsa-oaep":
        raise ValueError("Input not rsa-oaep mode")
    ct = b64dec(j["ciphertext"])
    pt = rsa_decrypt_with_private(priv, ct)
    with open(args.out, 'wb') as f:
        f.write(pt)
    print(f"[+] RSA-decrypted {args.infile} -> {args.out}")

# ---- Argparse --------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(description="Encryption/Decryption Tools (AES-GCM, PBE, RSA, Hybrid)")
    sub = p.add_subparsers(dest='cmd')

    # genrsa
    a = sub.add_parser("genrsa", help="Generate RSA keypair (private + public)")
    a.add_argument("--bits", type=int, default=4096)
    a.add_argument("--priv", required=True, help="private key path (PEM)")
    a.add_argument("--pub", required=True, help="public key path (PEM)")
    a.add_argument("--passphrase", default=None, help="optional passphrase for private key")
    a.set_defaults(func=cmd_genrsa)

    # aes-encrypt
    a = sub.add_parser("aes-encrypt", help="Encrypt text or file with AES-256-GCM (random key)")
    a.add_argument("--text", help="text to encrypt (if provided)")
    a.add_argument("--infile", help="input file to encrypt")
    a.add_argument("--out", required=True, help="output JSON file")
    a.add_argument("--keyfile", help="provide 32-byte key file (raw bytes) to use instead of random")
    a.add_argument("--dump-key", action='store_true', help="include base64 key_used in output (insecure!)")
    a.set_defaults(func=cmd_aes_encrypt)

    # aes-decrypt
    a = sub.add_parser("aes-decrypt", help="Decrypt AES-GCM JSON file")
    a.add_argument("--infile", required=True, help="input JSON file")
    a.add_argument("--keyfile", help="raw key file (32 bytes) or omit if key embedded")
    a.add_argument("--out", help="output file path (if omitted will print text)")
    a.set_defaults(func=cmd_aes_decrypt)

    # pbe-encrypt
    a = sub.add_parser("pbe-encrypt", help="Encrypt file with password (PBKDF2 + AES-GCM)")
    a.add_argument("--infile", required=True)
    a.add_argument("--out", required=True)
    a.add_argument("--password", required=True)
    a.set_defaults(func=cmd_pbe_encrypt)

    # pbe-decrypt
    a = sub.add_parser("pbe-decrypt", help="Decrypt PBE file with password")
    a.add_argument("--infile", required=True)
    a.add_argument("--out", required=True)
    a.add_argument("--password", required=True)
    a.set_defaults(func=cmd_pbe_decrypt)

    # rsa-encrypt
    a = sub.add_parser("rsa-encrypt", help="Encrypt small payload using RSA-OAEP (use hybrid for big files)")
    a.add_argument("--pub", required=True, help="public key PEM")
    a.add_argument("--infile", required=True)
    a.add_argument("--out", required=True)
    a.set_defaults(func=cmd_rsa_encrypt)

    # rsa-decrypt
    a = sub.add_parser("rsa-decrypt", help="Decrypt RSA-OAEP file")
    a.add_argument("--priv", required=True, help="private key PEM")
    a.add_argument("--infile", required=True)
    a.add_argument("--out", required=True)
    a.add_argument("--passphrase", default=None, help="private key passphrase (if any)")
    a.set_defaults(func=cmd_rsa_decrypt)

    # hybrid
    a = sub.add_parser("hybrid-encrypt", help="Encrypt file using AES & wrap key with RSA public key")
    a.add_argument("--pub", required=True)
    a.add_argument("--in", dest='infile', required=True)
    a.add_argument("--out", required=True)
    a.set_defaults(func=lambda args: hybrid_encrypt_file(args.pub, args.infile, args.out))

    a = sub.add_parser("hybrid-decrypt", help="Decrypt hybrid file using RSA private key")
    a.add_argument("--priv", required=True)
    a.add_argument("--in", dest='infile', required=True)
    a.add_argument("--out", required=True)
    a.add_argument("--passphrase", default=None)
    a.set_defaults(func=lambda args: hybrid_decrypt_file(args.priv, args.infile, args.out, args.passphrase))

    return p

def main():
    p = build_parser()
    args = p.parse_args()
    if not hasattr(args, 'func'):
        p.print_help()
        return
    try:
        args.func(args)
    except Exception as e:
        print("[!] Error:", e)

if __name__ == "__main__":
    main()

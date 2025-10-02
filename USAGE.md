# 📖 CLI Usage & Commands

## Main Help
```
python crypto_tool.py --help
```

Commands:
- `genrsa`         → Generate RSA keypair  
- `aes-encrypt`    → Encrypt text/file with AES-256-GCM  
- `aes-decrypt`    → Decrypt AES-GCM JSON  
- `pbe-encrypt`    → Encrypt file with password (PBKDF2 + AES-GCM)  
- `pbe-decrypt`    → Decrypt password-based encrypted file  
- `rsa-encrypt`    → Encrypt small payload using RSA-OAEP  
- `rsa-decrypt`    → Decrypt RSA-OAEP encrypted file  
- `hybrid-encrypt` → Encrypt large file (AES + RSA)  
- `hybrid-decrypt` → Decrypt hybrid file  

---

## genrsa
```
python crypto_tool.py genrsa --priv private.pem --pub public.pem [--bits 4096] [--passphrase PASS]
```

Generate RSA keypair.

---

## aes-encrypt
```
python crypto_tool.py aes-encrypt [--text TEXT] [--infile FILE] --out OUT.json [--keyfile KEYFILE] [--dump-key]
```

Encrypt text or file with AES-256-GCM.

---

## aes-decrypt
```
python crypto_tool.py aes-decrypt --infile INPUT.json [--keyfile KEYFILE] [--out OUTPUT]
```

Decrypt AES JSON file.

---

## pbe-encrypt
```
python crypto_tool.py pbe-encrypt --infile FILE --out OUT.json --password PASS
```

Encrypt file with password-derived AES key.

---

## pbe-decrypt
```
python crypto_tool.py pbe-decrypt --infile FILE.enc --out FILE --password PASS
```

Decrypt PBE file.

---

## rsa-encrypt
```
python crypto_tool.py rsa-encrypt --pub public.pem --infile FILE --out OUT.json
```

Encrypt small file/data with RSA-OAEP.

---

## rsa-decrypt
```
python crypto_tool.py rsa-decrypt --priv private.pem --infile FILE.enc --out FILE [--passphrase PASS]
```

Decrypt RSA-OAEP file.

---

## hybrid-encrypt
```
python crypto_tool.py hybrid-encrypt --pub public.pem --in FILE --out OUT.json
```

Encrypt big file using AES + wrap key with RSA.

---

## hybrid-decrypt
```
python crypto_tool.py hybrid-decrypt --priv private.pem --in FILE.enc --out FILE [--passphrase PASS]
```

Decrypt hybrid-encrypted file.

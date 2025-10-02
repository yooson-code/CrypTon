# 🔐 Encryption / Decryption Tools

## 📌 Overview
Cross-platform **Encryption/Decryption CLI Tool** written in Python.  
Supports:

- AES-256-GCM (symmetric encrypt/decrypt text & files)
- Password-Based Encryption (PBKDF2 + AES-GCM)
- RSA-4096 (keypair generation + small payload encryption/decryption)
- Hybrid Encryption (AES for data, RSA for wrapping the key)

Runs on **Windows / Linux / macOS** with Python 3.10+.

---

## 📦 Installation
Clone repo & install requirements:

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## ⚙️ Usage

### Show all commands
```bash
python crypto_tool.py --help
```

### Generate RSA keys
```bash
python crypto_tool.py genrsa --priv private.pem --pub public.pem --passphrase "mypassword"
```

### AES (text or file)
```bash
python crypto_tool.py aes-encrypt --text "rahasia" --out secret.json --dump-key
python crypto_tool.py aes-decrypt --infile secret.json
```

### Password-based (PBE)
```bash
python crypto_tool.py pbe-encrypt --infile notes.txt --out notes.enc --password "MyStrongPass!"
python crypto_tool.py pbe-decrypt --infile notes.enc --out notes.txt --password "MyStrongPass!"
```

### RSA small payload
```bash
python crypto_tool.py rsa-encrypt --pub public.pem --infile token.txt --out token.enc
python crypto_tool.py rsa-decrypt --priv private.pem --infile token.enc --out token.txt --passphrase "mypassword"
```

### Hybrid (AES + RSA)
```bash
python crypto_tool.py hybrid-encrypt --pub public.pem --in bigfile.bin --out bigfile.enc
python crypto_tool.py hybrid-decrypt --priv private.pem --in bigfile.enc --out bigfile.bin --passphrase "mypassword"
```

---

## 📖 Full Help
See [USAGE.md](USAGE.md) for detailed `--help` output of each command.

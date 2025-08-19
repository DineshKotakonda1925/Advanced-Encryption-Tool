# 🔐 Advanced Encryption Tool (AES-256-GCM)

A robust, user-friendly **file encryption/decryption** application built with **Python + Tkinter**.  
It uses **AES-256 in GCM mode** (authenticated encryption) and **PBKDF2-HMAC-SHA256** for key derivation with a per-file random salt.

## ✨ Features
- AES-256-GCM (secure, authenticated)
- PBKDF2-HMAC-SHA256 (200k iterations)
- Streaming I/O (handles large files)
- Clean GUI (Encrypt / Decrypt, progress bar, logs)
- Safe file container: `AET1 | salt(16) | nonce(12) | ciphertext | tag(16)`

## 🚀 Quick Start
```bash
git clone https://github.com/<your-username>/Advanced-Encryption-Tool.git
cd Advanced-Encryption-Tool
pip install -r requirements.txt
python aet_gui.py
```

## 🛡️ Security Notes
- Never lose your password—**decryption is impossible** without it.
- GCM tag is verified at decrypt time: wrong password or tampering ⇒ failure.
- Each file uses a unique random **salt** and **nonce**.

## 📦 File Format
```
MAGIC=AET1 | SALT=16B | NONCE=12B | CIPHERTEXT | TAG=16B
```
Output files use the `.aet` extension.

## 🤝 Contributing
Issues and PRs are welcome! Consider tests for edge cases (huge files, I/O errors, wrong tag).

## ⚠️ Legal
For **educational and authorized** use only. You are responsible for compliance with laws/policies.

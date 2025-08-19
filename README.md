# 🔐 Advanced Encryption Tool

A **GUI-based file encryption & decryption application** built with **Python (Tkinter)**.  
It uses **AES-256-GCM** for secure authenticated encryption and **PBKDF2-HMAC-SHA256** for password-based key derivation.

---

## ✨ Features

- 🔑 **AES-256-GCM** encryption with authentication tag  
- 🧂 **Per-file random salt** & nonce for strong security  
- 📡 **PBKDF2-HMAC-SHA256** (200k iterations) for password-based key derivation  
- ⚡ **Streaming I/O** (supports large files without memory issues)  
- 🖥️ **Simple GUI** with file selector, password field, and log output  
- 📂 **Custom File Format**  
```

MAGIC=AET1 | SALT(16B) | NONCE(12B) | CIPHERTEXT | TAG(16B)

````

---

## 📸 Screenshots

*(Add screenshots of the GUI here e.g. `docs/screenshot.png`)*  

---

## 🚀 Installation & Usage

### 1️⃣ Clone the repository
```bash
git clone https://github.com/<your-username>/Advanced-Encryption-Tool.git
cd Advanced-Encryption-Tool
````

### 2️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ Run the application

```bash
python aet_gui.py
```

---

## 🛠️ Tech Stack

* **Python 3.7+**
* **Tkinter** (GUI)
* **cryptography** (AES, PBKDF2, GCM)

---

## 🧪 Testing

A sample file `sample_test.txt` is included for quick testing.

1. Encrypt with a password of your choice → produces `.aet` file
2. Decrypt `.aet` with the same password → restores original file

---

## ⚠️ Disclaimer

This project is intended **for educational and authorized use only**.
Do **not** use on systems/files you do not own or have explicit permission to test.

---

## 🤝 Contributing

Contributions are welcome!

* Open an issue for feature requests/bugs
* Fork → Branch → PR 🚀

---


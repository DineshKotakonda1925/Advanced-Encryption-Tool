"""
Advanced Encryption Tool – AES‑256‑GCM
Author: Dinesh Kotakonda
License: MIT

A robust, user‑friendly file encryption/decryption GUI using:
- AES‑256 in GCM mode (authenticated encryption)
- PBKDF2‑HMAC(SHA‑256) key derivation with per‑file random salt
- Streaming (chunked) I/O to handle large files without loading in memory
- Simple custom file container format with a magic header

File format (container):
    0..3   : magic bytes b"AET1"
    4..19  : 16‑byte salt
    20..31 : 12‑byte nonce (IV)
    32..N-17: ciphertext (same size as plaintext)
    N-16..N-1: 16‑byte GCM tag

Dependencies:
    cryptography

Run:
    python aet_gui.py
"""
from __future__ import annotations
import os
from pathlib import Path
from typing import Callable, Optional

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

# -------------------------
# Crypto configuration
# -------------------------
MAGIC = b"AET1"  # Advanced Encryption Tool v1
SALT_LEN = 16
NONCE_LEN = 12  # recommended for GCM
TAG_LEN = 16
KEY_LEN = 32  # 256‑bit key
PBKDF2_ITERS = 200_000
CHUNK_SIZE = 1024 * 1024  # 1 MiB

backend = default_backend()


def derive_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non‑empty string")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERS,
        backend=backend,
    )
    return kdf.derive(password.encode("utf-8"))


def _progress_wrapper(callback: Optional[Callable[[int, int], None]], done: int, total: int):
    if callback:
        try:
            callback(done, total)
        except Exception:
            pass


class AETFormatError(Exception):
    pass


def encrypt_file(src: Path, dst: Path, password: str, progress: Optional[Callable[[int, int], None]] = None):
    total = src.stat().st_size
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend)
    encryptor = cipher.encryptor()

    with src.open("rb") as f_in, dst.open("wb") as f_out:
        # Write header (magic + salt + nonce)
        f_out.write(MAGIC)
        f_out.write(salt)
        f_out.write(nonce)

        processed = 0
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break
            ct = encryptor.update(chunk)
            if ct:
                f_out.write(ct)
            processed += len(chunk)
            _progress_wrapper(progress, processed, total)

        encryptor.finalize()
        # Append tag at the end
        tag = encryptor.tag
        if len(tag) != TAG_LEN:
            # The library produces 16‑byte tags by default; ensure invariant
            raise RuntimeError("Unexpected GCM tag length")
        f_out.write(tag)


def decrypt_file(src: Path, dst: Path, password: str, progress: Optional[Callable[[int, int], None]] = None):
    size = src.stat().st_size
    if size < len(MAGIC) + SALT_LEN + NONCE_LEN + TAG_LEN:
        raise AETFormatError("File too small or not AET format")

    with src.open("rb") as f_in:
        header = f_in.read(len(MAGIC))
        if header != MAGIC:
            raise AETFormatError("Invalid magic header – not an AET file")
        salt = f_in.read(SALT_LEN)
        nonce = f_in.read(NONCE_LEN)

        # Determine positions
        header_len = len(MAGIC) + SALT_LEN + NONCE_LEN
        ct_len = size - header_len - TAG_LEN
        if ct_len < 0:
            raise AETFormatError("Corrupted file – negative ciphertext length")

        # Read tag from end
        f_in.seek(header_len + ct_len)
        tag = f_in.read(TAG_LEN)

        # Prepare decryptor
        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=backend)
        decryptor = cipher.decryptor()

        # Stream decrypt
        f_in.seek(header_len)
        processed = 0
        with dst.open("wb") as f_out:
            remaining = ct_len
            total = ct_len
            while remaining > 0:
                to_read = CHUNK_SIZE if remaining >= CHUNK_SIZE else remaining
                chunk = f_in.read(to_read)
                if not chunk:
                    break
                pt = decryptor.update(chunk)
                if pt:
                    f_out.write(pt)
                remaining -= len(chunk)
                processed += len(chunk)
                _progress_wrapper(progress, processed, total)

            # finalize() will verify tag; raises InvalidTag on failure
            decryptor.finalize()


# -------------------------
# GUI Application
# -------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Encryption Tool By Dinesh – AES‑256‑GCM")
        self.geometry("720x420")
        self.minsize(660, 380)

        self._build_ui()

    # UI layout
    def _build_ui(self):
        pad = 10

        container = ttk.Frame(self)
        container.pack(fill=tk.BOTH, expand=True, padx=pad, pady=pad)

        # File row
        file_row = ttk.Frame(container)
        file_row.pack(fill=tk.X, pady=(0, pad))
        ttk.Label(file_row, text="File:").pack(side=tk.LEFT)
        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(file_row, textvariable=self.path_var)
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 8))
        ttk.Button(file_row, text="Browse", command=self._browse).pack(side=tk.LEFT)

        # Password row
        pw_row = ttk.Frame(container)
        pw_row.pack(fill=tk.X, pady=(0, pad))
        ttk.Label(pw_row, text="Password:").pack(side=tk.LEFT)
        self.pw_var = tk.StringVar()
        self.pw_entry = ttk.Entry(pw_row, textvariable=self.pw_var, show="•")
        self.pw_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 8))

        self.show_var = tk.BooleanVar(value=False)
        show_cb = ttk.Checkbutton(pw_row, text="Show", variable=self.show_var, command=self._toggle_pw)
        show_cb.pack(side=tk.LEFT)

        # Confirm password row (used in encrypt for typo safety)
        cpw_row = ttk.Frame(container)
        cpw_row.pack(fill=tk.X, pady=(0, pad))
        ttk.Label(cpw_row, text="Confirm:").pack(side=tk.LEFT)
        self.cpw_var = tk.StringVar()
        self.cpw_entry = ttk.Entry(cpw_row, textvariable=self.cpw_var, show="•")
        self.cpw_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(16, 8))

        # Buttons
        btn_row = ttk.Frame(container)
        btn_row.pack(fill=tk.X, pady=(0, pad))
        self.encrypt_btn = ttk.Button(btn_row, text="Encrypt", command=self._encrypt_clicked)
        self.decrypt_btn = ttk.Button(btn_row, text="Decrypt", command=self._decrypt_clicked)
        self.encrypt_btn.pack(side=tk.LEFT)
        self.decrypt_btn.pack(side=tk.LEFT, padx=(8, 0))

        # Progress
        self.progress = ttk.Progressbar(container, mode="determinate")
        self.progress.pack(fill=tk.X, pady=(0, pad))

        # Log area
        self.log = tk.Text(container, height=10, state=tk.DISABLED)
        self.log.pack(fill=tk.BOTH, expand=True)

        # Style tweaks
        try:
            self.style = ttk.Style(self)
            self.style.configure("TButton", padding=6)
        except Exception:
            pass

    def _toggle_pw(self):
        self.pw_entry.configure(show="" if self.show_var.get() else "•")
        self.cpw_entry.configure(show="" if self.show_var.get() else "•")

    def _browse(self):
        path = filedialog.askopenfilename(title="Select file")
        if path:
            self.path_var.set(path)

    def _set_progress(self, done: int, total: int):
        self.progress.configure(maximum=max(total, 1), value=done)
        self.update_idletasks()

    def _log(self, text: str):
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, text + "\n")
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    def _validate_common(self) -> Optional[Path]:
        p = Path(self.path_var.get().strip())
        if not p.exists() or not p.is_file():
            messagebox.showerror("Error", "Please select a valid file")
            return None
        pw = self.pw_var.get()
        if not pw:
            messagebox.showerror("Error", "Password cannot be empty")
            return None
        return p

    def _encrypt_clicked(self):
        p = self._validate_common()
        if not p:
            return
        if self.pw_var.get() != self.cpw_var.get():
            messagebox.showerror("Error", "Passwords do not match")
            return
        out = Path(str(p) + ".aet")
        if out.exists():
            if not messagebox.askyesno("Overwrite?", f"Output file exists:\n{out}\nOverwrite?"):
                return
        self._run_bg(lambda: self._encrypt(p, out))

    def _decrypt_clicked(self):
        p = self._validate_common()
        if not p:
            return
        # Infer output name
        if p.suffix == ".aet":
            out = p.with_suffix("")
            if out == p:
                out = Path(str(p) + ".dec")
        else:
            out = Path(str(p) + ".dec")
        if out.exists():
            if not messagebox.askyesno("Overwrite?", f"Output file exists:\n{out}\nOverwrite?"):
                return
        self._run_bg(lambda: self._decrypt(p, out))

    def _run_bg(self, fn: Callable[[], None]):
        # Disable buttons during work
        self.encrypt_btn.configure(state=tk.DISABLED)
        self.decrypt_btn.configure(state=tk.DISABLED)
        self.progress.configure(value=0)
        def runner():
            try:
                fn()
            except Exception as e:
                self._log(f"[!] Error: {e}")
                messagebox.showerror("Error", str(e))
            finally:
                self.encrypt_btn.configure(state=tk.NORMAL)
                self.decrypt_btn.configure(state=tk.NORMAL)
        import threading
        threading.Thread(target=runner, daemon=True).start()

    def _encrypt(self, src: Path, dst: Path):
        self._log(f"[+] Encrypting: {src}")
        encrypt_file(src, dst, self.pw_var.get(), self._set_progress)
        self._log(f"[*] Done. Output: {dst}")

    def _decrypt(self, src: Path, dst: Path):
        self._log(f"[+] Decrypting: {src}")
        decrypt_file(src, dst, self.pw_var.get(), self._set_progress)
        self._log(f"[*] Done. Output: {dst}")


if __name__ == "__main__":
    app = App()
    app.mainloop()

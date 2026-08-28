"""Browser cookie extraction, so the MCP server can reuse an existing Grafana session.

Reads the session cookie straight out of the local Firefox/Chromium cookie store. Chromium
cookies are encrypted with a key kept in the OS keyring (GNOME Keyring via secretstorage, or
KDE Wallet via kwallet-query); the key is cached on disk after the first successful read so it
does not have to be pulled from the keyring again.
"""

from __future__ import annotations

import glob
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "grafana-mcp"
KEY_FILE = CACHE_DIR / "chrome-safe-storage-key"


class AuthError(RuntimeError):
    pass


def load_env(path: Path | None = None) -> None:
    """Read grafana-mcp/.env without overriding what the MCP host already set."""
    path = path or HERE / ".env"
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


# --- browser cookies -------------------------------------------------------

def _query_sqlite(db: str, sql: str, args: tuple) -> list[tuple]:
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "db"
        shutil.copy2(db, copy)
        for suffix in ("-wal", "-shm"):
            if Path(db + suffix).exists():
                shutil.copy2(db + suffix, str(copy) + suffix)
        con = sqlite3.connect(str(copy))
        try:
            return con.execute(sql, args).fetchall()
        finally:
            con.close()


def _firefox_dbs() -> list[str]:
    return glob.glob(str(Path.home() / ".mozilla/firefox/*/cookies.sqlite")) + glob.glob(
        str(Path.home() / "snap/firefox/common/.mozilla/firefox/*/cookies.sqlite")
    )


def _chromium_dbs() -> list[str]:
    roots = [
        ".config/google-chrome",
        ".config/google-chrome-beta",
        ".config/chromium",
        ".config/microsoft-edge",
        ".config/BraveSoftware/Brave-Browser",
        ".config/vivaldi",
    ]
    paths: list[str] = []
    for root in roots:
        paths += glob.glob(str(Path.home() / root / "*/Cookies"))
        paths += glob.glob(str(Path.home() / root / "*/Network/Cookies"))
    return paths


def _kwallet_passwords() -> list[bytes]:
    """KDE stores the Chrome safe-storage key in kdewallet, reachable only through kwallet-query."""
    import subprocess

    found = []
    for folder, entry in (
        ("Chrome Keys", "Chrome Safe Storage"),
        ("Chromium Keys", "Chromium Safe Storage"),
        ("Chrome Keys", "Chromium Safe Storage"),
    ):
        try:
            proc = subprocess.run(
                ["kwallet-query", "-f", folder, "-r", entry, "kdewallet"],
                capture_output=True,
                timeout=15,
            )
        except Exception:
            continue
        secret = proc.stdout.decode("utf-8", "ignore").strip()
        if proc.returncode == 0 and secret and "not found" not in secret.lower():
            found.append(secret.encode())
    return found


def _cached_password() -> list[bytes]:
    """The OS keyring can be slow or unreachable from the MCP process, so a found key is kept on disk."""
    try:
        data = KEY_FILE.read_bytes().strip()
    except Exception:
        return []
    return [data] if data else []


def _store_password(password: bytes) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        KEY_FILE.write_bytes(password)
        KEY_FILE.chmod(0o600)
    except Exception:
        pass


def _chromium_keys() -> list[bytes]:
    from cryptography.hazmat.primitives.hashes import SHA1
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    passwords: list[bytes] = _cached_password()
    discovered: list[bytes] = []
    try:
        import secretstorage

        conn = secretstorage.dbus_init()
        for coll in secretstorage.get_all_collections(conn):
            if coll.is_locked():
                continue
            for item in coll.get_all_items():
                if "Safe Storage" in (item.get_label() or ""):
                    discovered.append(item.get_secret())
    except Exception:
        pass
    discovered += _kwallet_passwords()
    if discovered:
        _store_password(discovered[0])
    passwords += discovered
    passwords.append(b"peanuts")  # Chromium's documented fallback when no OS keyring is present

    keys = []
    for pw in passwords:
        kdf = PBKDF2HMAC(algorithm=SHA1(), length=16, salt=b"saltysalt", iterations=1)
        keys.append(kdf.derive(pw))
    return keys


def _unpad(data: bytes) -> bytes:
    return data[: -data[-1]] if data and 0 < data[-1] <= 16 else data


def _clean_cookie_bytes(plain: bytes) -> str | None:
    """Chrome 130+ prefixes the plaintext with a 32 byte domain hash, so strip before decoding."""
    for candidate in (plain, plain[32:]):
        if not candidate:
            continue
        text = candidate.decode("utf-8", "ignore").strip()
        if text and text.isascii() and text.isprintable():
            return text
    return None


def _chromium_decrypt(blob: bytes, keys: list[bytes]) -> str | None:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not blob:
        return None
    prefix, body = blob[:3], blob[3:]
    for key in keys:
        try:
            if prefix in (b"v10", b"v11"):
                plain = _unpad(Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).decryptor().update(body))
            elif prefix == b"v20":
                plain = AESGCM(key).decrypt(body[:12], body[12:], None)
            else:
                plain = blob
        except Exception:
            continue
        text = _clean_cookie_bytes(plain)
        if text:
            return text
    return None


def _header_safe(name: str, value: str) -> bool:
    """Cookies ride in an HTTP header, so anything non-ascii or with control chars is dropped."""
    if not name or not value:
        return False
    if not name.isascii() or not value.isascii():
        return False
    return not any(ord(c) < 32 or ord(c) == 127 for c in name + value)


def cookies_for_host(host: str) -> dict[str, str]:
    """Every cookie the local browsers hold for this host, SSO proxy cookies included."""
    found: dict[str, str] = {}

    for db in _firefox_dbs():
        try:
            for name, value in _query_sqlite(
                db, "SELECT name, value FROM moz_cookies WHERE host LIKE ?", (f"%{host}%",)
            ):
                if _header_safe(name, value or ""):
                    found.setdefault(name, value)
        except Exception:
            continue

    dbs = _chromium_dbs()
    if dbs:
        keys = _chromium_keys()
        for db in dbs:
            try:
                rows = _query_sqlite(
                    db,
                    "SELECT name, value, encrypted_value FROM cookies WHERE host_key LIKE ?",
                    (f"%{host}%",),
                )
            except Exception:
                continue
            for name, value, enc in rows:
                token = value or _chromium_decrypt(enc, keys) or ""
                if _header_safe(name, token):
                    found.setdefault(name, token)
    return found

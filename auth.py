"""Browser cookie extraction, so the MCP server can reuse an existing Grafana session.

Reads the session cookie straight out of the local browser's cookie store. Linux, macOS and
Windows each protect Chromium's cookie encryption key differently, so the password/key lookup
branches by platform; parsing the cookie database itself (SQLite for Firefox and Chromium,
Apple's binary format for Safari) is otherwise the same everywhere.
"""

from __future__ import annotations

import base64
import glob
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "grafana-mcp"
KEY_FILE = CACHE_DIR / "chrome-safe-storage-key"

IS_MAC = sys.platform == "darwin"
IS_WINDOWS = sys.platform == "win32"


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


# --- cookie database discovery ----------------------------------------------

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
    if IS_WINDOWS:
        appdata = os.environ.get("APPDATA", str(Path.home() / "AppData/Roaming"))
        return glob.glob(str(Path(appdata) / "Mozilla/Firefox/Profiles/*/cookies.sqlite"))
    if IS_MAC:
        return glob.glob(str(Path.home() / "Library/Application Support/Firefox/Profiles/*/cookies.sqlite"))
    return glob.glob(str(Path.home() / ".mozilla/firefox/*/cookies.sqlite")) + glob.glob(
        str(Path.home() / "snap/firefox/common/.mozilla/firefox/*/cookies.sqlite")
    )


def _chromium_roots() -> list[str]:
    """Each browser's own profile root -- 'User Data' on Windows, its config dir elsewhere.

    Windows decryption needs this because the AES key lives in each root's own 'Local State'
    file; Linux/macOS derive the key from a password instead, so the root barely matters there.
    """
    if IS_WINDOWS:
        local = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local")))
        return [
            str(local / "Google/Chrome/User Data"),
            str(local / "Google/Chrome Beta/User Data"),
            str(local / "Chromium/User Data"),
            str(local / "Microsoft/Edge/User Data"),
            str(local / "BraveSoftware/Brave-Browser/User Data"),
            str(local / "Vivaldi/User Data"),
        ]
    if IS_MAC:
        support = Path.home() / "Library/Application Support"
        return [
            str(support / "Google/Chrome"),
            str(support / "Google/Chrome Beta"),
            str(support / "Chromium"),
            str(support / "Microsoft Edge"),
            str(support / "BraveSoftware/Brave-Browser"),
            str(support / "Vivaldi"),
        ]
    return [
        str(Path.home() / d)
        for d in (
            ".config/google-chrome",
            ".config/google-chrome-beta",
            ".config/chromium",
            ".config/microsoft-edge",
            ".config/BraveSoftware/Brave-Browser",
            ".config/vivaldi",
        )
    ]


def _chromium_dbs() -> list[tuple[str, str]]:
    """(browser root, cookie file) pairs."""
    pairs = []
    for root in _chromium_roots():
        for pattern in ("*/Cookies", "*/Network/Cookies"):
            for path in glob.glob(str(Path(root) / pattern)):
                pairs.append((root, path))
    return pairs


# --- Linux: GNOME Keyring / KDE Wallet --------------------------------------

def _kwallet_passwords() -> list[bytes]:
    """KDE stores the Chrome safe-storage key in kdewallet, reachable only through kwallet-query."""
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
    """The Linux keyring can be slow or unreachable from the MCP process, so a found key is cached."""
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


# --- macOS: Keychain ---------------------------------------------------------

def _macos_keychain_passwords() -> list[bytes]:
    found = []
    for service in (
        "Chrome Safe Storage",
        "Chromium Safe Storage",
        "Brave Safe Storage",
        "Microsoft Edge Safe Storage",
        "Vivaldi Safe Storage",
    ):
        try:
            proc = subprocess.run(
                ["security", "find-generic-password", "-w", "-s", service],
                capture_output=True,
                timeout=15,
            )
        except Exception:
            continue
        secret = proc.stdout.decode("utf-8", "ignore").strip()
        if proc.returncode == 0 and secret:
            found.append(secret.encode())
    return found


def _posix_chromium_keys() -> list[bytes]:
    """Linux and macOS both derive an AES-128 key via PBKDF2 from a password, just with a
    different password source (keyring vs. Keychain) and a different iteration count."""
    from cryptography.hazmat.primitives.hashes import SHA1
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    candidates: list[tuple[bytes, int]] = []
    if IS_MAC:
        candidates += [(pw, 1003) for pw in _macos_keychain_passwords()]
    else:
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
        candidates += [(pw, 1) for pw in passwords]

    return [
        PBKDF2HMAC(algorithm=SHA1(), length=16, salt=b"saltysalt", iterations=iterations).derive(pw)
        for pw, iterations in candidates
    ]


# --- Windows: DPAPI -----------------------------------------------------------

def _dpapi_unprotect(blob: bytes) -> bytes | None:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(blob, len(blob))
    blob_in = DATA_BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(  # type: ignore[attr-defined]
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    )
    if not ok:
        return None
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)  # type: ignore[attr-defined]


def _windows_chromium_key(root: str) -> bytes | None:
    """Each browser install keeps its AES key DPAPI-wrapped in its own 'Local State' file."""
    try:
        data = json.loads((Path(root) / "Local State").read_text(encoding="utf-8"))
        encrypted = base64.b64decode(data["os_crypt"]["encrypted_key"])
    except Exception:
        return None
    if not encrypted.startswith(b"DPAPI"):
        return None
    return _dpapi_unprotect(encrypted[5:])


# --- decryption ---------------------------------------------------------------

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


def _chromium_decrypt_posix(blob: bytes, keys: list[bytes]) -> str | None:
    """Linux/macOS: v10/v11 is AES-128-CBC with a fixed IV, v20 is AES-256-GCM."""
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


def _chromium_decrypt_windows(blob: bytes, key: bytes | None) -> str | None:
    """Windows: v10/v11 is AES-256-GCM with a DPAPI-unwrapped key. v20 (Chrome 127+'s App-Bound
    Encryption) additionally wraps that key through Chrome's elevation service, which isn't
    implemented here -- those cookies are simply skipped, not raised as an error."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not blob or not key:
        return None
    prefix, body = blob[:3], blob[3:]
    if prefix not in (b"v10", b"v11"):
        return None
    try:
        plain = AESGCM(key).decrypt(body[:12], body[12:], None)
    except Exception:
        return None
    return _clean_cookie_bytes(plain)


def _header_safe(name: str, value: str) -> bool:
    """Cookies ride in an HTTP header, so anything non-ascii or with control chars is dropped."""
    if not name or not value:
        return False
    if not name.isascii() or not value.isascii():
        return False
    return not any(ord(c) < 32 or ord(c) == 127 for c in name + value)


# --- Safari (macOS only) -------------------------------------------------------

def _safari_cookie_files() -> list[str]:
    home = Path.home()
    return glob.glob(
        str(home / "Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies")
    ) + glob.glob(str(home / "Library/Cookies/Cookies.binarycookies"))


def _parse_safari_page(page: bytes, host: str, found: dict[str, str]) -> None:
    num_cookies = struct.unpack("<I", page[4:8])[0]
    cookie_offsets = struct.unpack(f"<{num_cookies}I", page[8 : 8 + 4 * num_cookies])
    for rel in cookie_offsets:
        record_all = page[rel:]
        size = struct.unpack("<I", record_all[0:4])[0]
        record = record_all[:size]
        url_off, name_off, _path_off, value_off = struct.unpack("<4I", record[16:32])

        def cstr(off: int) -> str:
            end = record.index(b"\x00", off)
            return record[off:end].decode("utf-8", "ignore")

        domain = cstr(url_off)
        if host not in domain and domain.lstrip(".") not in host:
            continue
        name, value = cstr(name_off), cstr(value_off)
        if _header_safe(name, value):
            found.setdefault(name, value)


def _safari_cookies(host: str) -> dict[str, str]:
    """Safari only writes cookies with an explicit expiry to disk -- a pure session cookie (no
    Expires attribute) lives in memory only and will not show up here. Reading the sandboxed
    Container path also requires the terminal/process to have Full Disk Access on modern macOS.
    """
    found: dict[str, str] = {}
    for path in _safari_cookie_files():
        try:
            data = Path(path).read_bytes()
        except Exception:
            continue
        if data[:4] != b"cook":
            continue
        try:
            num_pages = struct.unpack(">I", data[4:8])[0]
            page_sizes = struct.unpack(f">{num_pages}I", data[8 : 8 + 4 * num_pages])
            offset = 8 + 4 * num_pages
            for size in page_sizes:
                page = data[offset : offset + size]
                offset += size
                try:
                    _parse_safari_page(page, host, found)
                except Exception:
                    continue
        except Exception:
            continue
    return found


# --- public entry point --------------------------------------------------------

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

    pairs = _chromium_dbs()
    if pairs:
        if IS_WINDOWS:
            key_cache: dict[str, bytes | None] = {}
            for root, db in pairs:
                if root not in key_cache:
                    key_cache[root] = _windows_chromium_key(root)
                try:
                    rows = _query_sqlite(
                        db,
                        "SELECT name, value, encrypted_value FROM cookies WHERE host_key LIKE ?",
                        (f"%{host}%",),
                    )
                except Exception:
                    continue
                for name, value, enc in rows:
                    token = value or _chromium_decrypt_windows(enc, key_cache[root]) or ""
                    if _header_safe(name, token):
                        found.setdefault(name, token)
        else:
            keys = _posix_chromium_keys()
            for _root, db in pairs:
                try:
                    rows = _query_sqlite(
                        db,
                        "SELECT name, value, encrypted_value FROM cookies WHERE host_key LIKE ?",
                        (f"%{host}%",),
                    )
                except Exception:
                    continue
                for name, value, enc in rows:
                    token = value or _chromium_decrypt_posix(enc, keys) or ""
                    if _header_safe(name, token):
                        found.setdefault(name, token)

    if IS_MAC:
        try:
            for name, value in _safari_cookies(host).items():
                found.setdefault(name, value)
        except Exception:
            pass

    return found

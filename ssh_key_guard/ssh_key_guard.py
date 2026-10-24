#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ServerGuard SSH Key Guard 2.2

Cross-platform monitor for SSH authorized_keys changes.

Supported platforms (Python 3.7+, standard library only):
  Linux            full: polling + auditd attribution (who/what changed the file)
  macOS, FreeBSD   polling + OpenBSM attribution (EXPERIMENTAL, untested in CI)
  OpenBSD, NetBSD  polling only (no audit backend: attribution is "unavailable")
  Windows          polling + Security log (event 4663) attribution via SACL
                   (EXPERIMENTAL until integration-tested)

Design (three independent layers):
  1. Detection    state based (baseline vs. current snapshot); never depends on
                  audit or notifications.
  2. Evidence     OS audit records; best effort. When the evidence is missing or
                  ambiguous the event says so ("attribution") instead of guessing.
  3. Notification syslog / webhook; a failure here never affects layers 1-2.

Local snapshots and logs cannot protect against a fully compromised root. Events
are therefore hash-chained (tamper evident) and should be shipped to a remote
log server (--syslog with remote forwarding, or --webhook).
"""

import argparse
import base64
import glob
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as xml_escape
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import pwd
except ImportError:  # Windows
    pwd = None

try:
    import grp
except ImportError:  # Windows
    grp = None

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None

try:
    import msvcrt
except ImportError:  # POSIX
    msvcrt = None

VERSION = "2.2.0"

SYSTEM = platform.system().lower()
IS_WINDOWS = SYSTEM == "windows"
IS_LINUX = SYSTEM == "linux"
IS_MAC = SYSTEM == "darwin"
IS_BSD = SYSTEM in ("freebsd", "openbsd", "netbsd", "dragonfly")
IS_POSIX = os.name == "posix"

DEFAULT_INTERVAL = 5
MAX_EVENTS_BYTES = 20 * 1024 * 1024
EVENTS_KEEP = 5                    # rotated generations: .1 ... .5
AUDIT_REFRESH_SECONDS = 60
AUDIT_CONTEXT_WINDOW = 120
AUDIT_LOOKBACK_SECONDS = 600       # how far back 'ausearch -ts recent' / BSM look
ATTRIBUTION_TOLERANCE = 15         # max seconds between file change and audit record
MAX_KEY_FILE_BYTES = 32 * 1024 * 1024
STABLE_READ_ATTEMPTS = 3
SSHD_RETRY_SECONDS = 300

AUDIT_RULE_FILE = "/etc/audit/rules.d/serverguard-ssh-key.rules"
AUDIT_KEY = "serverguard_ssh_keys"
SERVICE_NAME = "serverguard-ssh-key-guard"
LAUNCHD_LABEL = "com.serverguard.sshkeyguard"
WIN_TASK_NAME = "ServerGuardSSHKeyGuard"

DEFAULT_KEY_PATTERNS = [".ssh/authorized_keys", ".ssh/authorized_keys2"]

KEY_TYPES = (
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "sk-ssh-ed25519@openssh.com",
    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-rsa-cert-v01@openssh.com",
    "ssh-dss-cert-v01@openssh.com",
    "ssh-ed25519-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
)

CFG = {
    "geoip": False,
    "webhook": os.environ.get("SERVERGUARD_WEBHOOK", ""),
    "syslog": False,
    "json": False,
}

_GEO_CACHE = {}


# ----------------------------------------------------------------------------
# Generic helpers
# ----------------------------------------------------------------------------

def warn(message):
    print(message, file=sys.stderr, flush=True)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def local_now():
    return datetime.now().astimezone().isoformat()


def is_admin():
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def which(name):
    return shutil.which(name)


def run_command(command, timeout=5):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as exc:
        return -1, "", str(exc)


def parse_iso(value):
    """ISO timestamp -> epoch seconds (None on failure). Accepts trailing Z."""
    if not value:
        return None
    try:
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        # Trim fractional seconds to 6 digits (Windows gives 7+)
        text = re.sub(r"(\.\d{6})\d+", r"\1", text)
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        return parsed.timestamp()
    except Exception:
        return None


def same_path(a, b):
    try:
        return (
            os.path.normcase(os.path.realpath(a))
            == os.path.normcase(os.path.realpath(b))
        )
    except Exception:
        return False


# ----------------------------------------------------------------------------
# Storage (platform aware)
# ----------------------------------------------------------------------------

def default_data_dir():
    env = os.environ.get("SERVERGUARD_DATA_DIR")

    if env:
        return Path(env)

    if IS_WINDOWS:
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(base) / "ServerGuard" / "data"

    if not is_admin():
        return Path.home() / ".local" / "share" / "serverguard"

    legacy = Path("/opt/serverguard/data")

    if legacy.exists():
        return legacy

    if IS_MAC:
        return Path("/Library/Application Support/ServerGuard/data")

    if IS_BSD:
        return Path("/var/db/serverguard")

    return legacy


DATA_DIR = default_data_dir()
EVENTS_FILE = DATA_DIR / "ssh_key_events.jsonl"
LEGACY_EVENTS_FILE = DATA_DIR / "ssh_key_events.json"
STATE_FILE = DATA_DIR / "ssh_key_state.json"
CHAIN_FILE = DATA_DIR / "ssh_key_events.chain"
EVENTS_LOCK_FILE = DATA_DIR / "events.lock"
STATE_LOCK_FILE = DATA_DIR / "state.lock"
MONITOR_LOCK_FILE = DATA_DIR / "monitor.lock"


def ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if IS_POSIX:
        try:
            os.chmod(str(DATA_DIR), 0o700)
        except OSError:
            pass


class FileLock(object):
    """Cross-process lock (flock on POSIX, msvcrt on Windows).

    The OS releases it automatically when the process dies, so a crashed
    instance can never leave a stale lock behind.
    """

    def __init__(self, path, blocking=True, timeout=10.0):
        self.path = Path(path)
        self.blocking = blocking
        self.timeout = timeout
        self.handle = None
        self.locked = False

    def acquire(self):
        try:
            ensure_data_dir()
            self.handle = open(str(self.path), "a+")
        except OSError:
            self.handle = None
            return False

        deadline = time.time() + (self.timeout if self.blocking else 0)

        while True:
            try:
                if fcntl is not None:
                    fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                elif msvcrt is not None:
                    self.handle.seek(0)
                    msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
                self.locked = True
                return True
            except (OSError, IOError):
                if time.time() >= deadline:
                    self.handle.close()
                    self.handle = None
                    return False

                time.sleep(0.05)

    def release(self):
        if self.handle is None:
            return

        try:
            if self.locked:
                if fcntl is not None:
                    fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
                elif msvcrt is not None:
                    self.handle.seek(0)
                    msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
        except (OSError, IOError):
            pass

        try:
            self.handle.close()
        except OSError:
            pass

        self.handle = None
        self.locked = False

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc_info):
        self.release()
        return False


def load_json(path, default):
    try:
        path = Path(path)

        if not path.exists():
            return default

        with path.open("r", encoding="utf-8") as file:
            return json.load(file)

    except Exception:
        return default


def save_json(path, data):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")

    try:
        path.parent.mkdir(parents=True, exist_ok=True)

        with temporary.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=2, ensure_ascii=False)
            file.flush()
            os.fsync(file.fileno())

        if IS_POSIX:
            os.chmod(str(temporary), 0o600)

        os.replace(str(temporary), str(path))
        return True

    except Exception as exc:
        warn("Failed to save {}: {}".format(path, exc))

        try:
            if temporary.exists():
                temporary.unlink()
        except Exception:
            pass

        return False


def _rotated(index):
    return EVENTS_FILE.with_name("{}.{}".format(EVENTS_FILE.name, index))


def rotate_events():
    """current -> .1 -> .2 ... -> .EVENTS_KEEP (oldest dropped). Caller holds the lock."""
    for index in range(EVENTS_KEEP - 1, 0, -1):
        source = _rotated(index)

        if source.exists():
            os.replace(str(source), str(_rotated(index + 1)))

    os.replace(str(EVENTS_FILE), str(_rotated(1)))


def chain_digest(prev, record):
    body = {k: v for k, v in record.items() if k != "chain"}
    raw = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256((prev + "|" + raw).encode("utf-8")).hexdigest()


def append_event(event):
    """Events are stored as hash-chained JSON Lines.

    Appends and rotation happen under a cross-process lock so several
    instances (monitor + manual scan) cannot corrupt the log or the chain.
    """
    try:
        ensure_data_dir()

        with FileLock(EVENTS_LOCK_FILE, timeout=15) as lock:
            if (lock.locked and EVENTS_FILE.exists()
                    and EVENTS_FILE.stat().st_size > MAX_EVENTS_BYTES):
                rotate_events()

            record = dict(event)
            prev = ""

            if lock.locked:
                try:
                    prev = CHAIN_FILE.read_text(encoding="utf-8").strip()
                except OSError:
                    prev = ""

            record["prev_chain"] = prev
            record["chain"] = chain_digest(prev, record) if lock.locked else ""

            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
            fd = os.open(str(EVENTS_FILE), flags, 0o600)

            with os.fdopen(fd, "a", encoding="utf-8") as file:
                file.write(json.dumps(record, ensure_ascii=False) + "\n")
                file.flush()
                os.fsync(file.fileno())

            if lock.locked:
                tmp = CHAIN_FILE.with_name(CHAIN_FILE.name + ".tmp")
                tmp.write_text(record["chain"], encoding="utf-8")
                os.replace(str(tmp), str(CHAIN_FILE))

        return True

    except Exception as exc:
        warn("Failed to store event: {}".format(exc))
        return False


def _event_files():
    """Oldest first: .N ... .1, current."""
    files = [_rotated(i) for i in range(EVENTS_KEEP, 0, -1)]
    files.append(EVENTS_FILE)
    return [f for f in files if f.exists()]


def load_events():
    events = []

    legacy = load_json(LEGACY_EVENTS_FILE, [])

    if isinstance(legacy, list):
        events.extend(item for item in legacy if isinstance(item, dict))

    for path in _event_files():
        try:
            with path.open("r", encoding="utf-8", errors="replace") as file:
                for line in file:
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        item = json.loads(line)
                    except ValueError:
                        continue

                    if isinstance(item, dict):
                        events.append(item)
        except Exception:
            pass

    return events


def verify_event_log():
    """Check the hash chain of the stored events. Returns True when intact."""
    previous = None
    checked = unchained = 0
    problems = []

    for path in _event_files():
        try:
            with path.open("r", encoding="utf-8", errors="replace") as file:
                for number, line in enumerate(file, start=1):
                    line = line.strip()

                    if not line:
                        continue

                    where = "{}:{}".format(path.name, number)

                    try:
                        record = json.loads(line)
                    except ValueError:
                        problems.append("{}: unparsable line".format(where))
                        previous = None
                        continue

                    chain = record.get("chain", "")

                    if not chain:
                        unchained += 1
                        previous = None
                        continue

                    if chain_digest(record.get("prev_chain", ""), record) != chain:
                        problems.append("{}: record was modified".format(where))
                    elif previous is not None and record.get("prev_chain", "") != previous:
                        problems.append("{}: records missing or reordered before this line".format(where))

                    previous = chain
                    checked += 1
        except OSError as exc:
            problems.append("{}: {}".format(path.name, exc))

    print("Chained records verified: {}".format(checked))

    if unchained:
        print("Records without a chain (older version / lock unavailable): {}".format(unchained))

    try:
        stored = CHAIN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        stored = ""

    if previous is not None and stored and stored != previous:
        problems.append("tail of the log does not match {} (records removed?)".format(CHAIN_FILE.name))

    for problem in problems:
        print("PROBLEM: " + problem)

    print("Log integrity: {}".format("OK" if not problems else "FAILED"))
    print("Note: a root attacker can rewrite the whole chain; ship events to a remote server.")
    return not problems


def load_state():
    data = load_json(STATE_FILE, {})
    return data if isinstance(data, dict) else {}


def save_state(state):
    return save_json(STATE_FILE, state)


def state_lock():
    ensure_data_dir()
    return FileLock(STATE_LOCK_FILE, timeout=30)


# ----------------------------------------------------------------------------
# Users, file metadata
# ----------------------------------------------------------------------------

def sha256_file(path):
    """Hex digest, or None when the file cannot be read (NOT '' - an empty
    file has a real digest)."""
    try:
        digest = hashlib.sha256()

        with open(str(path), "rb") as file:
            while True:
                chunk = file.read(1024 * 1024)

                if not chunk:
                    break

                digest.update(chunk)

        return digest.hexdigest()

    except Exception:
        return None


def uid_to_username(uid):
    try:
        uid = int(uid)

        if uid in (4294967295, 4294967294, -1):
            return ""

        if pwd is None:
            return str(uid)

        return pwd.getpwuid(uid).pw_name

    except Exception:
        return str(uid)


def get_file_owner(path, stat=None):
    empty = {"uid": "", "gid": "", "username": "", "group": ""}

    if IS_WINDOWS:
        return empty  # POSIX uid/gid are meaningless on Windows

    if stat is None:
        if not path:
            return empty  # Path("").stat() would silently stat the cwd

        try:
            stat = Path(path).stat()
        except Exception:
            return empty

    group_name = str(stat.st_gid)

    if grp is not None:
        try:
            group_name = grp.getgrgid(stat.st_gid).gr_name
        except Exception:
            pass

    return {
        "uid": stat.st_uid,
        "gid": stat.st_gid,
        "username": uid_to_username(stat.st_uid),
        "group": group_name,
    }


def _ts_iso(value):
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).astimezone().isoformat()
    except Exception:
        return ""


def probe_stat(path):
    """Three-state stat: ('ok', st) / ('missing', None) / ('error', None).

    'error' (permissions, I/O failure) must never be confused with 'missing'.
    """
    try:
        return "ok", os.stat(str(path))
    except (FileNotFoundError, NotADirectoryError):
        return "missing", None
    except OSError:
        return "error", None


def _stat_signature(st):
    return (
        st.st_ino,
        st.st_size,
        getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)),
        getattr(st, "st_ctime_ns", int(st.st_ctime * 1e9)),
    )


def read_file_stable(path):
    """Read a file ONCE and prove it did not change while reading.

    Returns (status, stat, data, reason) with status ok | missing | error.
    'error' covers unreadable AND unstable files: the caller must not treat
    that as "empty" or "deleted", and must not record it as a baseline.
    An empty file is a normal 'ok' result with data == b"".
    """
    reason = "unstable_read"

    for attempt in range(STABLE_READ_ATTEMPTS):
        status, before = probe_stat(path)

        if status != "ok":
            return status, None, b"", "stat_failed" if status == "error" else ""

        if before.st_size > MAX_KEY_FILE_BYTES:
            return "error", before, b"", "file_too_large"

        try:
            with open(str(path), "rb") as handle:
                opened = os.fstat(handle.fileno())
                data = handle.read(MAX_KEY_FILE_BYTES + 1)
                closed = os.fstat(handle.fileno())
        except (FileNotFoundError, NotADirectoryError):
            reason = "vanished_during_read"
            time.sleep(0.05 * (attempt + 1))
            continue
        except OSError as exc:
            return "error", before, b"", "read_failed: {}".format(exc)

        after_status, after = probe_stat(path)

        stable = (
            after_status == "ok"
            and _stat_signature(opened) == _stat_signature(closed)
            and _stat_signature(closed) == _stat_signature(after)
            and len(data) == closed.st_size
        )

        if stable:
            return "ok", closed, data, ""

        reason = "unstable_read"
        time.sleep(0.05 * (attempt + 1))

    return "error", None, b"", reason


def metadata_from_read(status, stat, data, reason=""):
    metadata = {
        "status": status, "exists": status == "ok", "size": 0, "inode": 0,
        "mode": "", "mtime": "", "ctime": "", "changed_ts": 0,
        "insecure": False, "sha256": "", "error": reason,
    }

    if status != "ok" or stat is None:
        return metadata

    mode = ""
    insecure = False

    if IS_POSIX:
        mode = oct(stat.st_mode & 0o7777)
        insecure = bool(stat.st_mode & 0o022)  # group/world writable

    metadata.update({
        "size": stat.st_size,
        "inode": stat.st_ino,
        "mode": mode,
        "mtime": _ts_iso(stat.st_mtime),
        "ctime": _ts_iso(stat.st_ctime),
        "changed_ts": max(stat.st_mtime, stat.st_ctime),
        "insecure": insecure,
        "sha256": hashlib.sha256(data).hexdigest(),
    })

    return metadata


def get_file_metadata(path):
    status, stat, data, reason = read_file_stable(path)
    return metadata_from_read(status, stat, data, reason)


# ----------------------------------------------------------------------------
# sshd_config handling
# ----------------------------------------------------------------------------

def sshd_config_paths():
    if IS_WINDOWS:
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return [Path(base) / "ssh" / "sshd_config"]

    return [
        Path("/etc/ssh/sshd_config"),
        Path("/usr/local/etc/ssh/sshd_config"),
        Path("/etc/sshd_config"),
    ]


_SSHD_CACHE = {"sig": None, "parsed": None, "effective": {}}


def _sshd_signature(files):
    signature = []

    for item in files:
        try:
            signature.append((item, os.stat(item).st_mtime_ns))
        except OSError:
            signature.append((item, None))

    return tuple(signature)


def _parse_sshd_config_uncached():
    """Parse sshd_config with correct scoping.

    - Directives before the first Match form the global block; every Match
      starts a new block that ends at the next Match (or end of file).
    - Within one block the FIRST AuthorizedKeysFile wins (sshd semantics).
    - Include is processed inline and starts in the block active at that
      point; a Match inside an included file does not leak back out of it.
    - Because Match criteria depend on the connecting user/host, the result
      is the UNION of all blocks' patterns (a safe superset). Exact per-user
      values come from sshd_effective_patterns() when 'sshd -T' is usable.
    """
    result = {
        "path": "", "files": [str(p) for p in sshd_config_paths()],
        "patterns": None, "ports": [], "authorizedkeyscommand": "",
        "match_blocks": 0,
    }

    main = next((p for p in sshd_config_paths() if p.exists()), None)

    if main is None:
        result["patterns"] = list(DEFAULT_KEY_PATTERNS)
        return result

    result["path"] = str(main)
    global_block = {"patterns": None}
    blocks = [global_block]

    def read(path, depth, block):
        if depth > 8:
            return

        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        current = block

        for raw in text.splitlines():
            line = raw.strip()

            if not line or line.startswith("#"):
                continue

            match = re.match(r"(\S+?)(?:\s*=\s*|\s+)(.*)$", line)

            if not match:
                continue

            keyword = match.group(1).lower()
            value = match.group(2).strip()

            if keyword == "match":
                current = {"patterns": None}
                blocks.append(current)
                result["match_blocks"] += 1

            elif keyword == "include":
                for pattern in value.split():
                    if not os.path.isabs(pattern):
                        pattern = os.path.join(str(main.parent), pattern)

                    result["files"].append(os.path.dirname(pattern) or ".")

                    for item in sorted(glob.glob(pattern)):
                        result["files"].append(item)
                        read(item, depth + 1, current)

            elif keyword == "port":
                try:
                    result["ports"].append(int(value.split()[0]))
                except Exception:
                    pass

            elif keyword == "authorizedkeysfile":
                if current["patterns"] is None:
                    current["patterns"] = value.replace('"', "").split()

            elif keyword == "authorizedkeyscommand":
                if not result["authorizedkeyscommand"]:
                    result["authorizedkeyscommand"] = value

    read(main, 0, global_block)

    patterns = []

    for index, block in enumerate(blocks):
        values = block["patterns"]

        if values is None:
            if index != 0:
                continue  # inherits the global value, already counted

            values = DEFAULT_KEY_PATTERNS

        if len(values) == 1 and values[0].lower() == "none":
            continue

        for value in values:
            if value not in patterns:
                patterns.append(value)

    result["patterns"] = patterns
    return result


def parse_sshd_config():
    cached = _SSHD_CACHE["parsed"]

    if cached is not None and _sshd_signature(cached["files"]) == _SSHD_CACHE["sig"]:
        return cached

    parsed = _parse_sshd_config_uncached()
    _SSHD_CACHE.update({
        "parsed": parsed, "sig": _sshd_signature(parsed["files"]), "effective": {},
    })
    return parsed


def find_sshd_binary():
    found = which("sshd")

    if found:
        return found

    for candidate in ("/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd"):
        if os.path.exists(candidate):
            return candidate

    return None


def sshd_effective_patterns(account):
    """Effective AuthorizedKeysFile for one user via 'sshd -T -f <cfg> -C ...'.

    Honours Match blocks. Returns None when unavailable (not root, Windows,
    sshd missing/failing); callers then fall back to the safe union from
    parse_sshd_config(). A failure disables the mechanism only for
    SSHD_RETRY_SECONDS (or until the config changes), not forever.
    """
    if IS_WINDOWS or not is_admin():
        return None

    parsed = parse_sshd_config()  # refreshes/invalidates the cache when files change
    cache = _SSHD_CACHE["effective"]
    name = account.get("username", "")

    if time.time() < cache.get("__unavailable_until__", 0):
        return None

    if name in cache:
        return cache[name]

    binary = find_sshd_binary()

    if not binary or not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        return None

    command = [binary, "-T"]

    if parsed.get("path"):
        command += ["-f", parsed["path"]]  # the file we actually parsed

    command += ["-C", "user={},host=localhost,addr=127.0.0.1".format(name)]
    code, out, err = run_command(command, timeout=10)

    if code != 0:
        cache["__unavailable_until__"] = time.time() + SSHD_RETRY_SECONDS
        warn("sshd -T failed ({}); using the union of all Match blocks for {}s".format(
            (err or "exit {}".format(code)).strip()[:200], SSHD_RETRY_SECONDS))
        return None

    result = None

    for line in out.splitlines():
        parts = line.split()

        if parts and parts[0].lower() == "authorizedkeysfile":
            values = parts[1:]
            result = [] if (len(values) == 1 and values[0].lower() == "none") else values
            break

    cache[name] = result
    return result


def get_ssh_ports():
    return sorted(set(parse_sshd_config().get("ports") or [])) or [22]


def get_key_patterns(account=None):
    if account is not None:
        effective = sshd_effective_patterns(account)

        if effective is not None:
            return effective

    return parse_sshd_config()["patterns"]


def expand_key_pattern(pattern, account):
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")

    expanded = (
        pattern.replace("%%", "\0")
        .replace("%h", account.get("home", ""))
        .replace("%u", account.get("username", ""))
        .replace("%U", str(account.get("uid", "")))
        .replace("__PROGRAMDATA__", program_data)
        .replace("\0", "%")
    )

    if not os.path.isabs(expanded):
        expanded = os.path.join(account.get("home", ""), expanded)

    return os.path.normpath(expanded)


def get_accounts():
    accounts = []
    seen_homes = set()

    if IS_WINDOWS:
        users_dir = Path(os.environ.get("SystemDrive", "C:") + "\\") / "Users"
        skip = {"public", "default", "default user", "all users", "defaultapppool"}

        try:
            entries = sorted(users_dir.iterdir())
        except Exception:
            entries = []

        for entry in entries:
            if entry.is_dir() and entry.name.lower() not in skip:
                accounts.append({
                    "username": entry.name, "uid": "", "home": str(entry), "shell": "",
                })

        return accounts

    if pwd is None:
        return accounts

    try:
        entries = pwd.getpwall()
    except Exception:
        return accounts

    ignored_homes = {"/", "/nonexistent", "/var/empty", "/dev/null", "/usr/empty"}

    for entry in entries:
        home = entry.pw_dir

        if not home or home in ignored_homes or home in seen_homes:
            continue

        if not os.path.isdir(home):
            continue

        seen_homes.add(home)
        accounts.append({
            "username": entry.pw_name,
            "uid": entry.pw_uid,
            "home": home,
            "shell": entry.pw_shell,
        })

    accounts.sort(key=lambda item: item["uid"])
    return accounts


def collect_key_files():
    """Returns [{'path': ..., 'account': {...}}] for every authorized_keys file."""
    files = []
    seen = set()

    for account in get_accounts():
        for pattern in get_key_patterns(account):
            path = expand_key_pattern(pattern, account)
            marker = os.path.normcase(path)

            if marker in seen:
                continue

            seen.add(marker)
            files.append({"path": path, "account": account})

    if IS_WINDOWS:
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        path = os.path.normpath(
            os.path.join(base, "ssh", "administrators_authorized_keys")
        )

        if os.path.normcase(path) not in seen:
            files.append({
                "path": path,
                "account": {
                    "username": "Administrators", "uid": "", "home": "", "shell": "",
                },
            })

    return files


# ----------------------------------------------------------------------------
# authorized_keys parsing
# ----------------------------------------------------------------------------

def tokenize_spans(line):
    """Split on whitespace, but not inside double quotes (key options)."""
    spans = []
    start = None
    in_quotes = False
    escaped = False

    for index, char in enumerate(line):
        if start is None:
            if char.isspace():
                continue

            start = index

        if in_quotes:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_quotes = False

            continue

        if char == '"':
            in_quotes = True

        elif char.isspace():
            spans.append((start, index))
            start = None

    if start is not None:
        spans.append((start, len(line)))

    return spans


def decode_key_blob(key_type, key_data):
    """Return the decoded public key blob, or None when it is not a real key.

    An SSH public key blob starts with a length-prefixed string equal to the
    key type. Checking that stops arbitrary text (a comment, a garbage line
    that merely contains 'ssh-rsa') from being accepted as a key - sshd
    would not accept it either.
    """
    try:
        decoded = base64.b64decode(key_data.encode("ascii"), validate=True)
    except Exception:
        return None

    if len(decoded) < 4:
        return None

    length = int.from_bytes(decoded[:4], "big")
    type_bytes = key_type.encode("ascii")

    if length != len(type_bytes) or len(decoded) < 4 + length + 1:
        return None

    if decoded[4:4 + length] != type_bytes:
        return None

    return decoded


def parse_authorized_key_line(line, line_number):
    original = line.rstrip("\r\n")
    stripped = original.strip()

    if not stripped or stripped.startswith("#"):
        return None

    spans = tokenize_spans(stripped)
    tokens = [stripped[a:b] for a, b in spans]
    type_index = -1
    decoded = None

    for index, token in enumerate(tokens):
        if token in KEY_TYPES and index + 1 < len(tokens):
            decoded = decode_key_blob(token, tokens[index + 1])

            if decoded is not None:
                type_index = index
                break

    if type_index < 0:
        return None

    key_type = tokens[type_index]
    key_data = tokens[type_index + 1]
    options = stripped[spans[0][0]:spans[type_index - 1][1]] if type_index > 0 else ""
    comment = (
        stripped[spans[type_index + 2][0]:] if type_index + 2 < len(tokens) else ""
    )

    digest = hashlib.sha256(decoded).digest()
    fingerprint = "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")

    return {
        "type": key_type,
        "data": key_data,
        "fingerprint": fingerprint,
        "sha256": digest.hex(),
        "comment": comment,
        "options": options,
        "line": line_number,
        "raw": original,
    }


def parse_authorized_keys_text(text):
    keys = []

    for number, line in enumerate(text.split("\n"), start=1):
        key = parse_authorized_key_line(line, number)

        if key is not None:
            keys.append(key)

    return keys


def read_authorized_keys(path):
    """Returns (keys, ok).

    ok=False means the file could not be read reliably. Callers must NOT
    interpret that as 'the file has no keys'.
    """
    status, _, data, _ = read_file_stable(path)

    if status != "ok":
        return [], False

    return parse_authorized_keys_text(data.decode("utf-8", errors="replace")), True


def key_identity(key):
    if not key:
        return ""

    return (
        key.get("fingerprint")
        or key.get("sha256")
        or key.get("type", "") + ":" + key.get("data", "")
    )


def compare_keys(old_keys, new_keys):
    """Returns (added, removed, modified[(old, new)]).

    A key whose options changed (e.g. a restriction was dropped) is reported
    as modified instead of an unrelated remove + add.
    """
    def signature(key):
        return key_identity(key), key.get("options", "")

    remaining = list(old_keys)
    added = []

    for key in new_keys:
        sig = signature(key)
        index = next((i for i, o in enumerate(remaining) if signature(o) == sig), None)

        if index is None:
            added.append(key)
        else:
            remaining.pop(index)

    removed = remaining
    modified = []

    for key in list(added):
        index = next(
            (i for i, o in enumerate(removed) if key_identity(o) == key_identity(key)),
            None,
        )

        if index is not None:
            modified.append((removed.pop(index), key))
            added.remove(key)

    return added, removed, modified


def build_snapshot():
    """One consistent read per file: hash, metadata and keys all come from the
    SAME bytes, and a file that changes while being read is reported as
    'error' (retried next scan) instead of being recorded as a baseline."""
    snapshot = {}

    for item in collect_key_files():
        path = Path(item["path"])
        account = item["account"]
        status, stat, data, reason = read_file_stable(path)
        metadata = metadata_from_read(status, stat, data, reason)
        keys = []

        if status == "ok":
            keys = parse_authorized_keys_text(data.decode("utf-8", errors="replace"))

        snapshot[str(path)] = {
            "username": account.get("username", ""),
            "uid": account.get("uid", ""),
            "home": account.get("home", ""),
            "shell": account.get("shell", ""),
            "status": status,
            "exists": status == "ok",
            "sha256": metadata.get("sha256", ""),
            "metadata": metadata,
            "owner": get_file_owner(path, stat) if status == "ok" else get_file_owner("", None),
            "keys": keys,
        }

    return snapshot


# ----------------------------------------------------------------------------
# Process / network context
# ----------------------------------------------------------------------------

def _read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _process_info_proc(pid, result, with_parent):
    proc = Path("/proc/{}".format(pid))

    if not proc.exists():
        return

    result["process"] = _read_text(proc / "comm").strip()

    try:
        raw = (proc / "cmdline").read_bytes()
        result["command"] = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except Exception:
        pass

    try:
        result["exe"] = os.readlink(str(proc / "exe"))
    except Exception:
        pass

    for line in _read_text(proc / "status").splitlines():
        try:
            if line.startswith("PPid:"):
                result["ppid"] = int(line.split(":", 1)[1].strip())
            elif line.startswith("Uid:"):
                result["uid"] = int(line.split(":", 1)[1].split()[0])
        except Exception:
            pass

    if result["uid"] != "":
        result["username"] = uid_to_username(result["uid"])

    if with_parent and result["ppid"]:
        result["parent_process"] = process_info(result["ppid"], False).get("process", "")


def _process_info_ps(pid, result, with_parent):
    code, out, _ = run_command(["ps", "-o", "ppid=,user=,args=", "-p", str(pid)])

    if code != 0 or not out.strip():
        return

    parts = out.strip().split(None, 2)

    if len(parts) < 3:
        return

    try:
        result["ppid"] = int(parts[0])
    except ValueError:
        pass

    result["username"] = parts[1]
    result["command"] = parts[2]
    first = parts[2].split()[0] if parts[2].split() else ""
    result["process"] = os.path.basename(first)
    result["exe"] = first if os.path.isabs(first) else ""

    if with_parent and result["ppid"]:
        code, out, _ = run_command(["ps", "-o", "comm=", "-p", str(result["ppid"])])

        if code == 0:
            result["parent_process"] = os.path.basename(out.strip())


def process_info(pid, with_parent=True):
    result = {
        "pid": "", "ppid": "", "process": "", "parent_process": "",
        "exe": "", "command": "", "uid": "", "username": "",
    }

    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return result

    if pid <= 0:
        return result

    result["pid"] = pid

    if IS_LINUX:
        _process_info_proc(pid, result, with_parent)
    elif IS_POSIX:
        _process_info_ps(pid, result, with_parent)

    return result


def split_address(address):
    """Parse 'host:port', '[v6]:port' and BSD style 'host.port'."""
    address = address.strip()

    if "]:" in address:
        host, _, port = address.rpartition("]:")
        return host.lstrip("["), port

    if address.count(":") == 1:
        host, _, port = address.partition(":")
        return host, port

    if ":" in address and "." in address.rsplit(":", 1)[-1]:  # BSD IPv6: ::1.22
        host, _, port = address.rpartition(".")
        return host, port

    if address.count(".") == 4:  # BSD IPv4: 10.0.0.1.22
        host, _, port = address.rpartition(".")
        return host, port

    return address, ""


def get_ssh_sessions(ports=None):
    """Established TCP connections to the sshd port(s). Heuristic only."""
    ports = set(str(p) for p in (ports or get_ssh_ports()))

    if IS_WINDOWS:
        command = ["netstat", "-ano", "-p", "tcp"]
    elif IS_LINUX and which("ss"):
        command = ["ss", "-tn"]
    elif which("netstat"):
        command = ["netstat", "-an", "-p", "tcp"] if (IS_MAC or IS_BSD) else ["netstat", "-an"]
    else:
        return []

    code, out, _ = run_command(command, timeout=8)

    if code != 0:
        return []

    sessions = []

    for line in out.splitlines():
        if "ESTAB" not in line.upper():
            continue

        addresses = []

        for token in line.split():
            host, port = split_address(token)

            if port.isdigit():
                addresses.append((host, port))

        if len(addresses) < 2:
            continue

        (local_host, local_port), (remote_host, remote_port) = addresses[0], addresses[1]

        if local_port not in ports:
            continue

        if remote_host.lower().startswith("::ffff:"):
            remote_host = remote_host[7:]

        sessions.append({
            "local": "{}:{}".format(local_host, local_port),
            "remote": "{}:{}".format(remote_host, remote_port),
            "remote_ip": remote_host,
        })

    return sessions


def session_hint_ips():
    """Remote IPs of currently established SSH sessions.

    This is only a HINT: a connected client is not proof that it made a given
    change, so it is never reported as the source IP.
    """
    hints = []

    for session in get_ssh_sessions():
        ip = session.get("remote_ip", "")

        if ip and ip not in hints:
            hints.append(ip)

    return hints


def geoip(ip):
    if not CFG["geoip"] or not ip:
        return {}

    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]

    try:
        address = ipaddress.ip_address(ip.split("%")[0])

        if (address.is_private or address.is_loopback or address.is_link_local
                or address.is_reserved or address.is_multicast):
            return {}

        request = urllib.request.Request(
            "https://ipinfo.io/{}/json".format(ip),
            headers={"User-Agent": "serverguard-ssh-key-guard/" + VERSION},
        )

        with urllib.request.urlopen(request, timeout=4) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))

    except Exception:
        return {}

    result = {key: data.get(key, "") for key in ("country", "region", "city", "org", "hostname")}
    _GEO_CACHE[ip] = result
    return result


# ----------------------------------------------------------------------------
# Audit backends (who changed the file?)
# ----------------------------------------------------------------------------

def blank_audit_event():
    return {
        "audit_id": "", "timestamp": "", "serial": "", "uid": "", "username": "",
        "auid": "", "auid_username": "", "pid": "", "ppid": "", "process": "",
        "parent_process": "", "exe": "", "command": "", "cwd": "",
        "source_ip": "", "terminal": "", "success": "", "syscall": "",
        "exit": "", "names": [], "name_types": {},
    }


class AuditBackend(object):
    name = "none"
    hint = ("No OS audit backend for this platform; only change detection is "
            "available and events are reported with attribution 'unavailable'.")
    last_error = ""  # non-empty when the last recent_events() could not read the audit log

    def available(self):
        return False

    def setup(self, paths, quiet=False):
        return False

    def teardown(self, paths=None):
        return True

    def recent_events(self):
        return []

    def status(self):
        print("Backend: {}".format(self.name))
        print(self.hint)


# ---- Linux: auditd ----------------------------------------------------------

AUDIT_FIELDS = (
    "pid", "ppid", "uid", "auid", "ses", "comm", "exe", "name", "cwd",
    "syscall", "success", "exit", "addr", "terminal", "proctitle",
)
AUDIT_HEX_FIELDS = ("name", "cwd", "exe", "comm", "proctitle")


def parse_audit_timestamp(line):
    match = re.search(r"msg=audit\((\d+)(?:\.(\d+))?:(\d+)\)", line)

    if not match:
        return "", ""

    seconds = int(match.group(1))
    fraction = match.group(2) or ""
    serial = match.group(3)

    try:
        value = seconds + (int(fraction) / (10 ** len(fraction)) if fraction else 0)
        timestamp = datetime.fromtimestamp(value, tz=timezone.utc).astimezone().isoformat()
    except Exception:
        timestamp = ""

    return timestamp, serial


def extract_audit_field(line, name):
    match = re.search(r'(?:^|\s)' + re.escape(name) + r'=(?:"([^"]*)"|(\S+))', line)

    if not match:
        return "", False

    if match.group(1) is not None:
        return match.group(1), True

    return match.group(2), False


def decode_audit_value(field, value, quoted):
    # auditd hex-encodes values containing spaces/special characters (unquoted)
    if (not quoted and field in AUDIT_HEX_FIELDS and len(value) % 2 == 0
            and "/" not in value and re.fullmatch(r"[0-9A-Fa-f]+", value)):
        try:
            return bytes.fromhex(value).replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except ValueError:
            pass

    return value


def audit_group_key(line):
    """Records of one audit event share 'msg=audit(<time>:<serial>)'.

    Serials restart after reboot, so the key is time AND serial.
    """
    match = re.search(r"msg=audit\(([\d.]+:\d+)\)", line)
    return match.group(1) if match else ""


def parse_audit_events(text):
    groups = {}

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        group_key = audit_group_key(line)

        if not group_key:
            continue

        timestamp, serial = parse_audit_timestamp(line)
        group = groups.setdefault(
            group_key, {"timestamp": timestamp, "serial": serial, "raw": []})
        group["raw"].append(line)

    events = []

    for group_key, group in groups.items():
        event = {
            "audit_id": group_key, "serial": group["serial"],
            "timestamp": group["timestamp"], "names": [], "name_types": {},
        }

        for line in group["raw"]:
            record_match = re.search(r"(?:^|\s)type=(\S+)", line)
            record_type = record_match.group(1) if record_match else ""

            for field in AUDIT_FIELDS:
                value, quoted = extract_audit_field(line, field)

                if not value:
                    continue

                value = decode_audit_value(field, value, quoted)

                if field == "name":
                    event["names"].append(value)

                    if record_type == "PATH":
                        # nametype tells WHAT happened to the path:
                        # CREATE / DELETE / NORMAL / PARENT / UNKNOWN
                        nametype, _ = extract_audit_field(line, "nametype")
                        types = event["name_types"].setdefault(value, [])

                        if nametype and nametype not in types:
                            types.append(nametype)

                elif not event.get(field) or record_type == "SYSCALL":
                    event[field] = value

        events.append(event)

    return events


def _resolve_audit_name(name, cwd):
    """Relative PATH names are relative to the audited process' cwd."""
    if name and not os.path.isabs(name) and cwd and os.path.isabs(cwd):
        return os.path.normpath(os.path.join(cwd, name))

    return name


def normalize_linux_audit_event(raw):
    event = blank_audit_event()
    process = process_info(raw.get("pid", ""))

    def as_int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return value

    uid = as_int(raw.get("uid", ""))
    auid = as_int(raw.get("auid", ""))
    username = uid_to_username(uid) if isinstance(uid, int) else ""
    auid_username = uid_to_username(auid) if isinstance(auid, int) else ""

    command = raw.get("proctitle", "") or process.get("command", "") or raw.get("comm", "")
    source_ip = raw.get("addr", "")

    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        source_ip = ""

    success = raw.get("success", "")
    success = "yes" if success in ("yes", "1") else "no" if success in ("no", "0") else success

    parent = process.get("parent_process", "")

    if not parent and raw.get("ppid"):
        parent = process_info(raw["ppid"], False).get("process", "")

    cwd = raw.get("cwd", "")
    names = []
    name_types = {}

    for name in raw.get("names", []):
        resolved = _resolve_audit_name(name, cwd)
        names.append(resolved)
        name_types.setdefault(resolved, [])

        for item in (raw.get("name_types") or {}).get(name, []):
            if item not in name_types[resolved]:
                name_types[resolved].append(item)

    event.update({
        "timestamp": raw.get("timestamp", ""),
        "serial": raw.get("serial", ""),
        "audit_id": raw.get("audit_id", ""),
        "uid": uid,
        "username": username or process.get("username", ""),
        "auid": auid,
        "auid_username": auid_username,
        "pid": as_int(raw.get("pid", "")),
        "ppid": as_int(raw.get("ppid", "")),
        "process": raw.get("comm", "") or process.get("process", ""),
        "parent_process": parent,
        "exe": raw.get("exe", "") or process.get("exe", ""),
        "command": command,
        "cwd": cwd,
        "source_ip": source_ip,
        "terminal": raw.get("terminal", ""),
        "success": success,
        "syscall": raw.get("syscall", ""),
        "exit": raw.get("exit", ""),
        "names": names,
        "name_types": name_types,
    })

    return event


AUDIT_MARKER = "# Managed by ServerGuard SSH Key Guard"
AUDIT_LEGACY_MARKER = "# ServerGuard SSH Key Guard (generated)"  # v2.0.0 files


class LinuxAuditBackend(AuditBackend):
    """auditd integration.

    Ownership rules: this module only ever deletes rules/files that it can
    prove it created itself - the rules file must carry our marker header and
    a live rule must both carry our key AND watch a directory listed in that
    file. Anything else is left untouched.

    Update strategy (never leaves auditing worse than before):
      1. remember the previous rules file,
      2. write the new file atomically,
      3. ADD the missing live rules first, then remove only our stale ones
         (no unaudited gap, no duplicate rules),
      4. verify the live rule set,
      5. on any failure roll back: delete what was added, re-add what was
         removed, restore the previous file.
    """

    name = "auditd"
    hint = "Install auditd (apt install auditd / dnf install audit) and run as root."

    def __init__(self):
        self.applied = None
        self.last_error = ""

    def available(self):
        return bool(which("auditctl") and which("ausearch"))

    @staticmethod
    def _targets(paths):
        # Watch directories, not files: editors/sed -i replace the inode,
        # which silently kills a file watch.
        targets = set()

        for path in paths:
            directory = os.path.dirname(path)

            if not os.path.isdir(directory):
                continue

            real = os.path.realpath(directory)

            if re.search(r"\s", real):
                warn("Audit rules cannot watch a path with whitespace, skipping: {}".format(real))
                continue

            targets.add(real)

        return sorted(targets)

    @staticmethod
    def _read_owned():
        """Directories in OUR rules file; empty set if no file; None if the
        file exists but is not ours (never touch it)."""
        path = Path(AUDIT_RULE_FILE)

        if not path.exists():
            return set()

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

        head = "\n".join(text.splitlines()[:3])

        if AUDIT_MARKER not in head and AUDIT_LEGACY_MARKER not in head:
            return None

        return set(re.findall(r"dir=(\S+)", text)) | set(re.findall(r"^-w\s+(\S+)", text, re.M))

    @staticmethod
    def _render_rules(targets):
        lines = [AUDIT_MARKER, "# Generated automatically; audit key: {}".format(AUDIT_KEY), ""]

        for target in targets:
            lines.append("-a always,exit -F dir={} -F perm=wa -F key={}".format(target, AUDIT_KEY))

        return "\n".join(lines) + "\n"

    @staticmethod
    def _write_atomic(path, text):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name("." + path.name + ".tmp")

        with temporary.open("w", encoding="utf-8") as file:
            file.write(text)
            file.flush()
            os.fsync(file.fileno())

        os.chmod(str(temporary), 0o640)
        os.replace(str(temporary), str(path))

    @staticmethod
    def _live_rules():
        """[(kind, directory)] of live rules carrying OUR key; None if unreadable.

        kind is 'dir' (-a always,exit -F dir=...) or 'watch' (legacy -w rule)."""
        code, out, _ = run_command(["auditctl", "-l"], timeout=10)

        if code != 0:
            return None

        rules = []
        key_pattern = r"(?:key=|-k\s+)" + re.escape(AUDIT_KEY) + r"(?:\s|$)"

        for line in out.splitlines():
            if not re.search(key_pattern, line):
                continue

            match = re.search(r"-F\s+dir=(\S+)", line)

            if match:
                rules.append(("dir", match.group(1)))
                continue

            match = re.match(r"-w\s+(\S+)", line)

            if match:
                rules.append(("watch", match.group(1)))

        return rules

    @staticmethod
    def _rule_command(kind, directory, add):
        if kind == "dir":
            flag = "-a" if add else "-d"
            return ["auditctl", flag, "always,exit", "-F", "dir=" + directory,
                    "-F", "perm=wa", "-F", "key=" + AUDIT_KEY]

        flag = "-w" if add else "-W"
        return ["auditctl", flag, directory, "-p", "wa", "-k", AUDIT_KEY]

    def _apply_rule(self, kind, directory, add):
        code, _, err = run_command(self._rule_command(kind, directory, add), timeout=10)

        if code != 0:
            warn("auditctl {} {} failed: {}".format("add" if add else "delete", directory, err.strip()))

        return code == 0

    def _rollback(self, added, removed, old_text, wrote):
        warn("Audit rule update failed; restoring the previous configuration.")

        for directory in added:
            self._apply_rule("dir", directory, False)

        for kind, directory in removed:
            self._apply_rule(kind, directory, True)

        if wrote:
            try:
                if old_text is None:
                    Path(AUDIT_RULE_FILE).unlink()
                else:
                    self._write_atomic(AUDIT_RULE_FILE, old_text)
            except OSError as exc:
                warn("Could not restore {}: {}".format(AUDIT_RULE_FILE, exc))

        live = self._live_rules()
        self.applied = frozenset(d for k, d in live if k == "dir") if live is not None else None

    def setup(self, paths, quiet=False):
        if not is_admin():
            if not quiet:
                print("Audit configuration requires root.")
            return False

        if not self.available():
            if not quiet:
                print("auditctl/ausearch not found.")
            return False

        owned = self._read_owned()

        if owned is None:
            warn("{} exists but is not managed by ServerGuard; refusing to modify it.".format(AUDIT_RULE_FILE))
            return False

        targets = self._targets(paths)

        if not targets:
            if not quiet:
                print("No .ssh directories found to watch.")
            return False

        live = self._live_rules()

        if live is None:
            warn("Cannot read live audit rules (auditctl -l failed); not changing anything.")
            return False

        rule_path = Path(AUDIT_RULE_FILE)
        old_text = None

        if rule_path.exists():
            try:
                old_text = rule_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                warn("Cannot read {}: {}".format(AUDIT_RULE_FILE, exc))
                return False

        new_text = self._render_rules(targets)
        live_dirs = {d for k, d in live if k == "dir"}
        # only OUR rules: our key AND a directory from our own rules file
        stale = [("dir", d) for d in sorted(live_dirs) if d in owned and d not in targets]
        legacy = [("watch", d) for k, d in live if k == "watch" and d in owned]
        to_add = [t for t in targets if t not in live_dirs]

        if old_text == new_text and not to_add and not stale and not legacy:
            self.applied = frozenset(targets)
            return True  # already in the desired state

        wrote = False

        if old_text != new_text:
            try:
                self._write_atomic(rule_path, new_text)
                wrote = True
            except Exception as exc:
                warn("Failed to write audit rules (old file untouched): {}".format(exc))
                return False

        added = []

        for directory in to_add:
            if not self._apply_rule("dir", directory, True):
                self._rollback(added, [], old_text, wrote)
                return False

            added.append(directory)

        removed = []

        for kind, directory in stale + legacy:
            if self._apply_rule(kind, directory, False):
                removed.append((kind, directory))
            # a stale watch that cannot be removed is harmless: warned above

        verify = self._live_rules()
        active = {d for k, d in verify if k == "dir"} if verify is not None else set()
        missing = [t for t in targets if t not in active]

        if verify is None or missing:
            warn("Audit rules not active for: {}".format(", ".join(missing) or "(unreadable)"))
            self._rollback(added, removed, old_text, wrote)
            return False

        self.applied = frozenset(targets)

        if not quiet:
            print("Audit rules loaded: {} directories".format(len(targets)))

        return True

    def teardown(self, paths=None):
        if not is_admin():
            print("Root privileges are required.")
            return False

        owned = self._read_owned()

        if owned is None:
            print("{} is not managed by ServerGuard; leaving it untouched.".format(AUDIT_RULE_FILE))
            return False

        ok = True

        if which("auditctl"):
            live = self._live_rules()

            if live is None:
                warn("Cannot read live audit rules; file removal skipped so nothing is orphaned.")
                return False

            for kind, directory in live:
                if directory in owned and not self._apply_rule(kind, directory, False):
                    ok = False

        try:
            if Path(AUDIT_RULE_FILE).exists():
                Path(AUDIT_RULE_FILE).unlink()
        except OSError as exc:
            warn("Could not remove {}: {}".format(AUDIT_RULE_FILE, exc))
            return False

        self.applied = None
        return ok

    def recent_events(self):
        self.last_error = ""

        if not self.available():
            self.last_error = "auditctl/ausearch not found"
            return []

        code, out, err = run_command(
            ["ausearch", "-k", AUDIT_KEY, "-ts", "recent", "--raw"], timeout=15
        )

        if code != 0:
            # ausearch exits 1 with "<no matches>" when there is simply nothing to report
            if code == 1 and "no matches" in (out + err).lower():
                return []

            self.last_error = (err or out or "ausearch exit code {}".format(code)).strip()[:300]
            return []

        events = [normalize_linux_audit_event(e) for e in parse_audit_events(out)]
        events.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
        return events

    def status(self):
        owned = self._read_owned()
        print("Backend: auditd")
        print("auditctl: {}".format("available" if which("auditctl") else "unavailable"))
        print("ausearch: {}".format("available" if which("ausearch") else "unavailable"))

        if owned is None:
            print("Rules file: {} (NOT managed by ServerGuard)".format(AUDIT_RULE_FILE))
        else:
            print("Rules file: {}".format(AUDIT_RULE_FILE if Path(AUDIT_RULE_FILE).exists() else "not found"))

        print("-" * 40)
        print("Loaded rules:")
        live = self._live_rules()

        if live is None:
            print("Unable to read audit rules (root required?).")
        else:
            lines = ["{} {}".format(k, d) for k, d in live]
            print("\n".join(lines) if lines else "No ServerGuard audit rules loaded.")

        print("-" * 40)
        print("Recent events:")
        events = self.recent_events()

        if self.last_error:
            print("  audit log unreadable: {}".format(self.last_error))

        for event in events[:10]:
            print("  {} pid={} user={} auid={} exe={} ok={} path={}".format(
                event["timestamp"], event["pid"], event["username"], event["auid"],
                event["exe"], event["success"], (event["names"] or [""])[-1]))


# ---- macOS / FreeBSD: OpenBSM (EXPERIMENTAL) ---------------------------------

class BsmAuditBackend(AuditBackend):
    name = "openbsm"
    hint = ("EXPERIMENTAL, not integration-tested. Add 'fw,fm,fc,fd' (file write/modify/"
            "create/delete) to the 'flags:' line of /etc/security/audit_control and run "
            "'audit -s'.")

    def __init__(self):
        self.last_error = ""

    def available(self):
        return bool(which("auditreduce") and which("praudit") and os.path.isdir("/var/audit"))

    def _flags_enabled(self):
        text = _read_text("/etc/security/audit_control")

        for line in text.splitlines():
            if line.startswith("flags:") or line.startswith("naflags:"):
                flags = line.split(":", 1)[1]

                if re.search(r"\b(fw|fm|fc|fd|all)\b", flags.replace(",", " ")):
                    return True

        return False

    def setup(self, paths, quiet=False):
        if not self.available():
            if not quiet:
                print("OpenBSM tools not found.")
            return False

        if not self._flags_enabled():
            if not quiet:
                print("OpenBSM file audit flags are not enabled.")
                print(self.hint)
            return False

        return True

    @staticmethod
    def _record_to_event(record_xml):
        """Parse one <record> from 'praudit -x'. Every access is defensive:
        a token we do not understand yields an empty field, never an exception."""
        try:
            node = ET.fromstring(record_xml)
        except ET.ParseError:
            return None

        event = blank_audit_event()
        event["syscall"] = node.get("event", "")

        try:
            parsed = datetime.strptime(node.get("time", "").strip(), "%a %b %d %H:%M:%S %Y")
            event["timestamp"] = parsed.astimezone().isoformat()
        except ValueError:
            pass

        for path_node in node.iter("path"):
            if path_node.text:
                event["names"].append(path_node.text.strip())

        subject = node.find("subject")

        if subject is None:
            subject = node.find("subject_ex")

        if subject is not None:
            event["auid_username"] = subject.get("audit-uid", "")
            event["username"] = subject.get("uid", "")
            event["pid"] = subject.get("pid", "")
            terminal = subject.get("tid", "").split()

            if terminal:
                try:
                    ipaddress.ip_address(terminal[-1])
                    event["source_ip"] = terminal[-1]
                except ValueError:
                    pass

        result = node.find("return")

        if result is not None:
            event["success"] = "yes" if result.get("errval", "") == "success" else "no"

        if event["pid"]:
            info = process_info(event["pid"])
            event["process"] = info.get("process", "")
            event["exe"] = info.get("exe", "")
            event["command"] = info.get("command", "")
            event["parent_process"] = info.get("parent_process", "")

        event["serial"] = hashlib.sha1(record_xml.encode("utf-8", "replace")).hexdigest()[:12]
        event["audit_id"] = event["serial"]
        return event

    def recent_events(self):
        self.last_error = ""

        if not self.available():
            self.last_error = "OpenBSM tools not found"
            return []

        since = (datetime.now() - timedelta(seconds=AUDIT_LOOKBACK_SECONDS)).strftime("%Y%m%d%H%M%S")

        try:
            reduced = subprocess.run(
                ["auditreduce", "-a", since], capture_output=True, timeout=20)
            shown = subprocess.run(
                ["praudit", "-x"], input=reduced.stdout, capture_output=True, timeout=20)
        except Exception as exc:
            self.last_error = str(exc)
            return []

        if reduced.returncode != 0 or shown.returncode != 0:
            self.last_error = "auditreduce/praudit failed (exit {}/{})".format(
                reduced.returncode, shown.returncode)
            return []

        text = shown.stdout.decode("utf-8", "replace")
        events = []

        for record_xml in re.findall(r"<record\b.*?</record>", text, re.S):
            if "authorized_keys" not in record_xml:
                continue

            event = self._record_to_event(record_xml)

            if event is not None:
                events.append(event)

        events.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
        return events

    def status(self):
        print("Backend: openbsm (experimental)")
        print("Tools available: {}".format(self.available()))
        print("File audit flags enabled: {}".format(self._flags_enabled()))
        print(self.hint)


# ---- Windows: Security log, event 4663 ---------------------------------------

FILE_SYSTEM_AUDIT_GUID = "{0CCE921D-69AE-11D9-BED3-505054503030}"
WIN_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class WindowsAuditBackend(AuditBackend):
    name = "windows-security-log"
    hint = ("EXPERIMENTAL until integration-tested. Run as Administrator. The guard enables "
            "'File System' auditing and adds a SACL to the .ssh directories; changes then "
            "appear as Security event 4663.")

    def __init__(self):
        self.applied = None
        self.last_error = ""

    def _powershell(self):
        return which("powershell") or which("pwsh")

    def available(self):
        return IS_WINDOWS and bool(which("wevtutil") and self._powershell())

    @staticmethod
    def _dirs(paths):
        return sorted({os.path.dirname(p) for p in paths if os.path.isdir(os.path.dirname(p))})

    @staticmethod
    def _acl_script(directory, remove):
        """PowerShell that FAILS LOUDLY (non-zero exit) and verifies the result.

        Uses the Everyone SID (S-1-1-0), so it works on localized Windows.
        exit 2 = exception, exit 3 = the rule is not present after adding.
        """
        escaped = directory.replace("'", "''")
        script = (
            "$ErrorActionPreference='Stop'; "
            "try { "
            "$p='__DIR__'; "
            "$sid=New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0'); "
            "$acl=Get-Acl -Path $p -Audit; "
            "$r=New-Object System.Security.AccessControl.FileSystemAuditRule("
            "$sid,'WriteData,AppendData,Delete,ChangePermissions,TakeOwnership',"
            "'ContainerInherit,ObjectInherit','None','Success'); "
            "[void]$acl.__ACTION__($r); Set-Acl -Path $p -AclObject $acl; "
            "$check=(Get-Acl -Path $p -Audit).GetAuditRules($true,$false,"
            "[System.Security.Principal.SecurityIdentifier]) | "
            "Where-Object { $_.IdentityReference.Value -eq 'S-1-1-0' -and "
            "$_.AuditFlags.ToString() -match 'Success' }; "
            "$present=(@($check).Count -gt 0); "
            "if ($__REMOVE__) { if ($present) { exit 3 } else { exit 0 } } "
            "else { if ($present) { exit 0 } else { exit 3 } } "
            "} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 2 }"
        )
        return (script.replace("__DIR__", escaped)
                .replace("__ACTION__", "RemoveAuditRule" if remove else "AddAuditRule")
                .replace("__REMOVE__", "true" if remove else "false"))

    def _run_acl(self, directory, remove):
        code, _, err = run_command(
            [self._powershell(), "-NoProfile", "-NonInteractive", "-Command",
             self._acl_script(directory, remove)], timeout=60)
        return code == 0, "exit {} {}".format(code, err.strip())

    def setup(self, paths, quiet=False):
        if not is_admin():
            if not quiet:
                print("Administrator privileges are required for audit setup.")
            return False

        if not self.available():
            if not quiet:
                print("wevtutil/PowerShell not found.")
            return False

        directories = self._dirs(paths)

        if not directories:
            return False

        if self.applied == frozenset(directories):
            return True

        code, _, err = run_command(
            ["auditpol", "/set", "/subcategory:" + FILE_SYSTEM_AUDIT_GUID, "/success:enable"],
            timeout=20)

        if code != 0:
            warn("auditpol failed (File System auditing NOT enabled): {}".format(err.strip()))
            return False

        ok = True

        for directory in directories:
            done, detail = self._run_acl(directory, False)

            if not done:
                ok = False
                warn("Failed to set/verify SACL on {}: {}".format(directory, detail))

        if ok:
            self.applied = frozenset(directories)

            if not quiet:
                print("Windows audit SACL set on {} directories.".format(len(directories)))

        return ok

    def teardown(self, paths=None):
        if not is_admin():
            print("Administrator privileges are required.")
            return False

        paths = paths if paths is not None else [f["path"] for f in collect_key_files()]
        ok = True

        for directory in self._dirs(paths):
            done, detail = self._run_acl(directory, True)

            if not done:
                ok = False
                warn("Failed to remove SACL on {}: {}".format(directory, detail))

        self.applied = None
        return ok

    def recent_events(self):
        self.last_error = ""

        if not self.available():
            self.last_error = "wevtutil/PowerShell not found"
            return []

        query = "*[System[(EventID=4663) and TimeCreated[timediff(@SystemTime) <= {}]]]".format(
            AUDIT_LOOKBACK_SECONDS * 1000)
        code, out, err = run_command(
            ["wevtutil", "qe", "Security", "/q:" + query, "/c:300", "/rd:true", "/f:xml"],
            timeout=30)

        if code != 0:
            self.last_error = (err or "wevtutil exit code {}".format(code)).strip()[:300]
            return []

        if not out.strip():
            return []

        try:
            root = ET.fromstring("<Events>" + out + "</Events>")
        except ET.ParseError as exc:
            self.last_error = "cannot parse event XML: {}".format(exc)
            return []

        events = []

        for node in root.iter(WIN_EVENT_NS + "Event"):
            data = {}

            for item in node.iter(WIN_EVENT_NS + "Data"):
                data[item.get("Name", "")] = item.text or ""

            object_name = data.get("ObjectName", "")

            if "authorized_keys" not in object_name.lower():
                continue

            system = node.find(WIN_EVENT_NS + "System")
            created = system.find(WIN_EVENT_NS + "TimeCreated") if system is not None else None
            record = system.find(WIN_EVENT_NS + "EventRecordID") if system is not None else None
            timestamp = ""

            if created is not None:
                epoch = parse_iso(created.get("SystemTime", ""))

                if epoch:
                    timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc).astimezone().isoformat()

            pid = data.get("ProcessId", "")

            try:
                pid = int(pid, 16) if pid.lower().startswith("0x") else int(pid)
            except ValueError:
                pass

            domain = data.get("SubjectDomainName", "")
            user = data.get("SubjectUserName", "")
            process_name = data.get("ProcessName", "")

            event = blank_audit_event()
            event.update({
                "timestamp": timestamp,
                "serial": record.text if record is not None else "",
                "audit_id": "win-" + (record.text if record is not None else ""),
                "username": "{}\\{}".format(domain, user) if domain else user,
                "pid": pid,
                "process": os.path.basename(process_name),
                "exe": process_name,
                "success": "yes",
                "syscall": "AccessMask " + data.get("AccessMask", ""),
                "names": [object_name],
            })
            events.append(event)

        events.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
        return events

    def status(self):
        print("Backend: windows-security-log (experimental)")
        print("wevtutil/PowerShell: {}".format(self.available()))
        print("Administrator: {}".format(is_admin()))
        print(self.hint)


def select_backend():
    if IS_LINUX:
        return LinuxAuditBackend()

    if IS_WINDOWS:
        return WindowsAuditBackend()

    if IS_MAC or SYSTEM == "freebsd":
        return BsmAuditBackend()

    return AuditBackend()  # OpenBSD / NetBSD / others: detection only


def _actor_key(event):
    return (event.get("pid"), event.get("exe") or event.get("process"), event.get("uid"))


def _candidate_brief(event):
    return {
        "timestamp": event.get("timestamp", ""),
        "pid": event.get("pid", ""),
        "username": event.get("username", ""),
        "auid_username": event.get("auid_username", ""),
        "exe": event.get("exe", ""),
        "process": event.get("process", ""),
    }


ACTION_NAMETYPES = {"file_deleted": {"DELETE"}, "file_created": {"CREATE"}}


def find_audit_context(path, audit_events, changed_ts=None, action=None):
    """Attribute a detected change to an audit actor - or admit that we cannot.

    Returns a dict with:
      attribution  unique | low_confidence | ambiguous | none
      attribution_candidates  [brief actor, ...] (when more than one actor fits)
    plus the audit event's own fields when exactly one actor fits.

    Rules:
      * failed operations changed nothing and are ignored;
      * the audit record must name exactly this path (relative names are
        resolved against the process cwd);
      * records must be close in time to the file's own change time
        (ATTRIBUTION_TOLERANCE); with no such record the match is only
        'low_confidence';
      * the operation type (PATH nametype DELETE/CREATE) is preferred when the
        detected action is known;
      * if several DIFFERENT processes touched the file in that period, no
        culprit is named: the result is 'ambiguous' with the candidate list.
    """
    current = time.time()
    broad = []

    for event in audit_events or []:
        if event.get("success") == "no":
            continue

        cwd = event.get("cwd", "")
        matched = [n for n in event.get("names", [])
                   if n and same_path(_resolve_audit_name(n, cwd), path)]

        if not matched:
            continue

        epoch = parse_iso(event.get("timestamp", ""))

        if epoch is None:
            continue  # an undated record cannot be tied to a change

        if epoch - current > 5 or current - epoch > AUDIT_CONTEXT_WINDOW:
            continue

        broad.append((event, epoch, matched))

    if not broad:
        return {"attribution": "none", "attribution_candidates": []}

    pool = broad
    confidence = "unique"

    if changed_ts:
        near = [item for item in broad if abs(item[1] - changed_ts) <= ATTRIBUTION_TOLERANCE]

        if near:
            pool = near
        else:
            confidence = "low_confidence"

    wanted = ACTION_NAMETYPES.get(action)

    if wanted:
        typed = [item for item in pool
                 if any(set((item[0].get("name_types") or {}).get(n, [])) & wanted
                        for n in item[2])]

        if typed:
            pool = typed

    actors = {}

    for event, epoch, _ in pool:
        actors.setdefault(_actor_key(event), []).append((event, epoch))

    if len(actors) > 1:
        candidates = [_candidate_brief(group[0][0]) for group in actors.values()]
        return {"attribution": "ambiguous", "attribution_candidates": candidates[:5]}

    group = next(iter(actors.values()))
    reference = changed_ts or current
    group.sort(key=lambda item: abs(item[1] - reference))
    chosen = dict(group[0][0])
    chosen["attribution"] = confidence
    chosen["attribution_candidates"] = []
    return chosen


# ----------------------------------------------------------------------------
# Risk scoring
# ----------------------------------------------------------------------------

def has_option(options, name):
    return bool(re.search(r"(?:^|,)\s*" + re.escape(name) + r"(?:=|,|$)", options, re.I))


def is_privileged_account(account):
    uid = account.get("uid", "")
    name = str(account.get("username", "")).lower()
    return uid == 0 or name in ("root", "administrator", "administrators", "toor")


def key_risk_flags(key, account):
    flags = set()

    if not key:
        return flags

    options = key.get("options", "")

    if not options:
        flags.add("no_restrictions")

    if has_option(options, "cert-authority"):
        flags.add("cert_authority")

    if has_option(options, "command"):
        flags.add("forced_command")

    if has_option(options, "environment"):
        flags.add("environment_option")

    if key.get("type", "") == "ssh-dss":
        flags.add("weak_key_type")

    if is_privileged_account(account):
        flags.add("privileged_account")

    return flags


def compute_severity(action, flags, extra=None):
    """Heuristic only: real impact depends on context the guard cannot see."""
    extra = extra or {}

    if action in ("key_added", "key_modified"):
        if flags & {"privileged_account", "cert_authority"}:
            return "high"

        if action == "key_modified" and extra.get("restrictions_removed"):
            return "high"

        return "medium"  # any new/changed trust relationship deserves review

    if action == "file_write_observed":
        return "info" if extra.get("success") == "no" else "medium"

    if action == "file_deleted":
        return "medium"

    if action in ("permissions_changed", "owner_changed", "file_created"):
        return "medium" if "insecure_permissions" in flags else "low"

    if action == "key_removed":
        return "low"

    return "info"


# ----------------------------------------------------------------------------
# Events
# ----------------------------------------------------------------------------

def key_brief(key):
    if not key:
        return None

    return {
        "type": key.get("type", ""),
        "fingerprint": key.get("fingerprint", ""),
        "sha256": key.get("sha256", ""),
        "comment": key.get("comment", ""),
        "line": key.get("line", 0),
        "options": key.get("options", ""),
    }


def create_event(action, path, account, key=None, old_key=None, audit_context=None, extra=None):
    audit_context = audit_context or {}
    extra = extra or {}

    # Only an IP reported by the OS audit record counts as a confirmed source.
    source_ip = audit_context.get("source_ip", "")
    hints = [] if source_ip else session_hint_ips()
    location = geoip(source_ip)  # confirmed IPs only; no-op unless --geoip
    metadata = get_file_metadata(path)

    if action == "key_modified":
        flags = key_risk_flags(key, account) | key_risk_flags(old_key, account)
    else:
        flags = key_risk_flags(key, account)

    if metadata.get("insecure"):
        flags.add("insecure_permissions")

    uname = platform.uname()
    modifier = {
        name: audit_context.get(name, "")
        for name in ("uid", "username", "auid", "auid_username", "pid", "ppid",
                     "process", "parent_process", "exe", "command", "cwd",
                     "success", "syscall", "exit")
    }
    modifier["audit_serial"] = audit_context.get("serial", "")
    # How trustworthy is the "who"? unique | low_confidence | ambiguous | none |
    # unavailable (no/failed audit) | observed (audit record seen directly)
    modifier["attribution"] = audit_context.get("attribution") or (
        "observed" if audit_context else "none")
    modifier["candidates"] = audit_context.get("attribution_candidates", [])

    return {
        "id": "{}-{}".format(int(time.time()), uuid.uuid4().hex[:10]),
        "version": VERSION,
        "timestamp": local_now(),
        "timestamp_utc": utc_now(),
        "audit_timestamp": audit_context.get("timestamp", ""),
        "action": action,
        "severity": compute_severity(action, flags, extra),
        "risk_flags": sorted(flags),
        "details": extra,
        "account": {
            "username": account.get("username", ""),
            "uid": account.get("uid", ""),
            "home": account.get("home", ""),
            "shell": account.get("shell", ""),
        },
        "file": {"path": str(path), "owner": get_file_owner(path), "metadata": metadata},
        "key": key_brief(key),
        "old_key": key_brief(old_key),
        "modifier": modifier,
        "network": {
            "source_ip": source_ip,
            "source_ip_source": "audit" if source_ip else "unknown",
            "session_hint_ips": hints,  # unconfirmed: active SSH sessions at detection time
            "country": location.get("country", ""),
            "region": location.get("region", ""),
            "city": location.get("city", ""),
            "org": location.get("org", ""),
            "hostname": location.get("hostname", ""),
            "terminal": audit_context.get("terminal", ""),
        },
        "server": {
            "hostname": socket.gethostname(),
            "os": uname.system,
            "kernel": uname.release,
            "machine": uname.machine,
        },
    }


def format_summary(event):
    key = event.get("key") or event.get("old_key") or {}
    modifier = event.get("modifier", {})
    network = event.get("network", {})
    source = network.get("source_ip") or "unknown"
    hints = network.get("session_hint_ips") or []

    if not network.get("source_ip") and hints:
        source += " (unconfirmed session hint: {})".format(",".join(hints))

    return ("[{}] {} {} account={} file={} key={} comment={} by={} proc={} "
            "attribution={} from={}").format(
        event.get("timestamp", ""),
        event.get("severity", "info").upper(),
        event.get("action", ""),
        event.get("account", {}).get("username", ""),
        event.get("file", {}).get("path", ""),
        key.get("fingerprint", "-") or "-",
        key.get("comment", "") or "-",
        modifier.get("username") or modifier.get("auid_username") or "unknown",
        modifier.get("process") or "unknown",
        modifier.get("attribution") or "none",
        source,
    )


def notify(event):
    summary = format_summary(event)

    if CFG["syslog"]:
        try:
            if IS_WINDOWS:
                level = "ERROR" if event.get("severity") == "high" else "WARNING"
                run_command(["eventcreate", "/T", level, "/ID", "100", "/L", "APPLICATION",
                             "/SO", "ServerGuard", "/D", summary[:30000]], timeout=10)
            else:
                import syslog
                syslog.openlog("serverguard-ssh-key-guard")
                priority = syslog.LOG_WARNING if event.get("severity") in ("high", "medium") else syslog.LOG_NOTICE
                syslog.syslog(priority, summary)
        except Exception as exc:
            warn("syslog error: {}".format(exc))

    url = CFG["webhook"]

    if url and url.lower().startswith(("http://", "https://")):
        try:
            request = urllib.request.Request(
                url,
                data=json.dumps(event, ensure_ascii=False).encode("utf-8"),
                headers={"Content-Type": "application/json",
                         "User-Agent": "serverguard-ssh-key-guard/" + VERSION},
            )
            urllib.request.urlopen(request, timeout=5).read()
        except Exception as exc:
            warn("webhook error: {}".format(exc))


def emit(event):
    """Layer 1 (store) is independent of layer 3 (notify): a notification
    failure can never lose or block a detected change."""
    stored = append_event(event)

    try:
        notify(event)
    except Exception as exc:
        warn("notification failed: {}".format(exc))

    return stored


def print_event(event):
    if CFG["json"]:
        print(json.dumps(event, indent=2, ensure_ascii=False), flush=True)
    else:
        print(format_summary(event), flush=True)


# ----------------------------------------------------------------------------
# Scanning
# ----------------------------------------------------------------------------

def initialize(backend=None, quiet=False):
    """Create the baseline. Callers must hold state_lock() (scan_once does)."""
    snapshot = build_snapshot()

    save_state({
        "version": VERSION,
        "created": local_now(),
        "last_scan": local_now(),
        "files": snapshot,
    })

    if backend is not None and is_admin() and backend.available():
        backend.setup(list(snapshot.keys()), quiet=quiet)

    if not quiet:
        total = sum(len(item.get("keys", [])) for item in snapshot.values())
        print("SSH key baseline created.")
        print("Files monitored: {}".format(len(snapshot)))
        print("Keys found: {}".format(total))
        unreadable = sum(1 for item in snapshot.values() if item.get("status") == "error")

        if unreadable:
            print("Unreadable or unstable paths (skipped, run as root / retry): {}".format(unreadable))

    return True


def scan_once(initialize_if_missing=True, backend=None):
    """One scan, serialized across processes so a manual 'scan' can never race
    the running monitor on the state file."""
    with state_lock() as lock:
        if not lock.locked:
            warn("Could not obtain the state lock within 30s; skipping this scan.")
            return []

        return _scan_once_locked(initialize_if_missing, backend)


def _scan_once_locked(initialize_if_missing, backend):
    state = load_state()

    if not state or "files" not in state:
        if initialize_if_missing:
            initialize(backend)

        return []

    ensure_data_dir()
    scan_started = local_now()
    old_files = state.get("files", {})
    new_files = build_snapshot()
    last_scan = parse_iso(state.get("last_scan", "")) or 0
    pending = []
    error_paths = []

    # ---- Phase 1: compare snapshots --------------------------------------
    for path, new_info in list(new_files.items()):
        old_info = old_files.get(path)

        if new_info.get("status") == "error":
            # Unreadable / unstable is NOT "empty": keep the last good snapshot.
            error_paths.append(path)

            if old_info and old_info.get("status", "ok") != "error":
                new_files[path] = old_info

            continue

        if old_info is not None and old_info.get("status", "ok") == "error":
            continue  # there was no trustworthy baseline; adopt the current state

        account = {k: new_info.get(k, "") for k in ("username", "uid", "home", "shell")}

        if old_info is None:
            # New path (new account, sshd config change, or upgrade).
            # Adopt silently if the file already existed before the last scan.
            if (new_info.get("metadata") or {}).get("changed_ts", 0) <= last_scan:
                continue

            old_info = {"exists": False, "keys": [], "metadata": {}, "owner": {}}

        old_meta = old_info.get("metadata", {}) or {}
        new_meta = new_info.get("metadata", {}) or {}
        old_exists = bool(old_info.get("exists"))
        new_exists = bool(new_info.get("exists"))

        if old_exists != new_exists:
            pending.append(("file_created" if new_exists else "file_deleted",
                            path, account, None, None, None))

        elif new_exists:
            if old_meta.get("mode") and old_meta.get("mode") != new_meta.get("mode"):
                pending.append(("permissions_changed", path, account, None, None,
                                {"old_mode": old_meta.get("mode"), "new_mode": new_meta.get("mode")}))

            old_uid = (old_info.get("owner") or {}).get("uid", "")
            new_uid = (new_info.get("owner") or {}).get("uid", "")

            if old_uid != "" and new_uid != "" and old_uid != new_uid:
                pending.append(("owner_changed", path, account, None, None,
                                {"old_uid": old_uid, "new_uid": new_uid}))

        added, removed, modified = compare_keys(old_info.get("keys", []), new_info.get("keys", []))

        for key in added:
            pending.append(("key_added", path, account, key, None, None))

        for old_key, new_key in modified:
            pending.append(("key_modified", path, account, new_key, old_key, {
                "options": [old_key.get("options", ""), new_key.get("options", "")],
                "restrictions_removed": bool(old_key.get("options")) and not new_key.get("options"),
            }))

        for key in removed:
            pending.append(("key_removed", path, account, None, key, None))

    # ---- Phase 2: OS audit log (evidence layer) ---------------------------
    usable = backend is not None and backend.available()
    audit_events = []
    audit_error = ""
    audit_note = ""

    if usable:
        if pending:
            time.sleep(0.5)  # let the audit subsystem flush

        audit_events = backend.recent_events()
        audit_error = getattr(backend, "last_error", "") or ""

        if audit_error:
            audit_note = "audit_log_unreadable: {}".format(audit_error)
        elif pending and last_scan and time.time() - last_scan > AUDIT_LOOKBACK_SECONDS:
            audit_note = "audit_lookback_gap: monitor was not running for over {}s".format(
                AUDIT_LOOKBACK_SECONDS)

    previous_error = state.get("audit_error", "")

    if audit_error and not previous_error:
        warn("WARNING: audit log cannot be read ({}). Changes are still detected, "
             "but without attribution.".format(audit_error))
    elif previous_error and not audit_error and usable:
        warn("Audit log is readable again.")

    events = []
    now_ts = time.time()
    recent = {
        p: t for p, t in (state.get("recent_changes") or {}).items()
        if now_ts - t < 30
    }

    for action, path, account, key, old_key, extra in pending:
        if usable and not audit_error:
            changed = (new_files.get(path, {}).get("metadata") or {}).get("changed_ts") or None
            context = find_audit_context(path, audit_events, changed, action)
        else:
            context = {"attribution": "unavailable"}

        if audit_note:
            extra = dict(extra or {})
            extra["audit_note"] = audit_note

        event = create_event(action, path, account, key, old_key, context, extra)
        emit(event)
        events.append(event)
        recent[path] = now_ts

    # ---- Phase 3: writes the snapshot diff cannot explain ----------------
    # e.g. a key added and removed between two scans: the file is identical
    # again, but the audit log still recorded the write. Limits: it only sees
    # what the audit log still contains for the monitored paths (lookback
    # AUDIT_LOOKBACK_SECONDS); a cleared/unavailable log means such events are lost.
    seen = list(state.get("audit_seen") or [])

    if usable and not audit_error:
        seen_set = set(seen)
        cutoff = last_scan - 5
        normalized = {}

        for path in new_files:
            normalized[os.path.normcase(os.path.realpath(path))] = path

        emitted = set()

        for audit_event in audit_events:
            identity = audit_event.get("audit_id") or "{}|{}".format(
                audit_event.get("serial", ""), audit_event.get("timestamp", ""))

            if identity in seen_set:
                continue

            seen.append(identity)
            seen_set.add(identity)
            epoch = parse_iso(audit_event.get("timestamp", ""))

            if epoch is None or epoch < cutoff:
                continue  # happened before monitoring (re)started

            path = None

            for name in audit_event.get("names", []):
                if name:
                    resolved = _resolve_audit_name(name, audit_event.get("cwd", ""))
                    path = normalized.get(os.path.normcase(os.path.realpath(resolved)))

                    if path:
                        break

            if not path or path in recent:
                continue  # unrelated, or already explained by a detected change

            marker = (path, audit_event.get("pid"))

            if marker in emitted:
                continue

            emitted.add(marker)
            info = new_files[path]
            account = {k: info.get(k, "") for k in ("username", "uid", "home", "shell")}
            event = create_event(
                "file_write_observed", path, account, None, None, audit_event,
                {"success": audit_event.get("success", ""),
                 "note": "audit log shows a write but no net key change was detected"})
            emit(event)
            events.append(event)

    # ---- Phase 4: persist ------------------------------------------------
    if sorted(error_paths) != sorted(state.get("error_paths") or []):
        if error_paths:
            warn("WARNING: {} authorized_keys path(s) are unreadable/unstable and were NOT compared "
                 "(e.g. {}). Run as root/Administrator.".format(len(error_paths), error_paths[0]))
        else:
            warn("All authorized_keys paths are readable again.")

    state["version"] = VERSION
    state["last_scan"] = scan_started
    state["files"] = new_files
    state["audit_seen"] = seen[-1000:]
    state["recent_changes"] = recent
    state["error_paths"] = error_paths
    state["audit_error"] = audit_error
    save_state(state)
    return events


def monitor(interval=DEFAULT_INTERVAL, use_audit=True):
    ensure_data_dir()
    instance = FileLock(MONITOR_LOCK_FILE, blocking=False)

    if not instance.acquire():
        print("Another SSH Key Guard monitor is already running (lock: {}). Exiting.".format(
            MONITOR_LOCK_FILE))
        return

    backend = select_backend() if use_audit else AuditBackend()
    admin = is_admin()

    print("=" * 40)
    print("      SERVERGUARD SSH KEY GUARD")
    print("=" * 40)
    print("Version:  {}".format(VERSION))
    print("Platform: {} {}".format(platform.system(), platform.release()))
    print("Interval: {} seconds".format(interval))
    print("Data dir: {}".format(DATA_DIR))

    if CFG["geoip"]:
        print("NOTE: --geoip is on; confirmed source IPs are sent to ipinfo.io (third party).")

    print()

    if not admin:
        print("WARNING: not running with root/Administrator privileges.")
        print("Some accounts may be unreadable and audit attribution is disabled.")
        print()

    state = load_state()

    if not state or "files" not in state:
        print("No baseline found. Creating baseline...")

        with state_lock() as lock:
            if lock.locked:
                initialize(backend)
            else:
                warn("Could not obtain the state lock; baseline will be created on the first scan.")
    elif admin and backend.available():
        backend.setup([f["path"] for f in collect_key_files()])

    if use_audit and not backend.available():
        print("Audit backend: unavailable ({})".format(backend.hint))

    def stop(signum, frame):
        raise KeyboardInterrupt()

    for sig_name in ("SIGTERM", "SIGBREAK"):
        sig = getattr(signal, sig_name, None)

        if sig is not None:
            try:
                signal.signal(sig, stop)
            except Exception:
                pass

    print("SSH Key Guard monitoring started.\n", flush=True)
    last_refresh = time.time()

    try:
        while True:
            try:
                if admin and backend.available() and time.time() - last_refresh >= AUDIT_REFRESH_SECONDS:
                    try:
                        backend.setup([f["path"] for f in collect_key_files()], quiet=True)
                    except Exception as exc:
                        warn("Audit rule refresh error: {}".format(exc))

                    last_refresh = time.time()

                for event in scan_once(False, backend if admin else None):
                    print_event(event)

                time.sleep(interval)

            except KeyboardInterrupt:
                print("\nSSH Key Guard stopped.")
                break

            except Exception as exc:
                warn("Monitor error: {}".format(exc))
                time.sleep(interval)
    finally:
        instance.release()


# ----------------------------------------------------------------------------
# Reports / diagnostics
# ----------------------------------------------------------------------------

def show(label, value, indent=0):
    if value in ("", None, []):
        return

    print("{}{}: {}".format("  " * indent, label, value))


def show_events(limit=20, as_json=False, action=None):
    events = load_events()

    if action:
        events = [e for e in events if e.get("action") == action]

    if not events:
        print("No SSH key events found.")
        return

    try:
        limit = max(1, int(limit))
    except (TypeError, ValueError):
        limit = 20

    selected = list(reversed(events[-limit:]))

    if as_json:
        print(json.dumps(selected, indent=2, ensure_ascii=False))
        return

    print("=" * 40)
    print("          SSH KEY EVENTS")
    print("=" * 40)

    for event in selected:
        print("\n" + "-" * 40)
        show("ID", event.get("id"))
        show("Time", event.get("timestamp"))
        show("Audit time", event.get("audit_timestamp"))
        show("Severity", event.get("severity"))
        show("Action", event.get("action"))
        show("Risk flags", ", ".join(event.get("risk_flags", []) or []))
        show("Details", json.dumps(event.get("details")) if event.get("details") else "")

        account = event.get("account", {})
        show("Account", account.get("username"))
        show("UID", account.get("uid"))
        show("Home", account.get("home"))

        file_info = event.get("file", {})
        show("File", file_info.get("path"))
        show("File owner", (file_info.get("owner") or {}).get("username"))

        for title, key in (("Key", event.get("key")), ("Old key", event.get("old_key"))):
            if key:
                print("{}:".format(title))

                for label in ("type", "fingerprint", "sha256", "comment", "options", "line"):
                    show(label, key.get(label), 1)

        print("Modifier:")

        for label, value in (event.get("modifier") or {}).items():
            show(label, json.dumps(value, ensure_ascii=False) if isinstance(value, (list, dict)) else value, 1)

        print("Network:")

        for label, value in (event.get("network") or {}).items():
            show(label, value, 1)

        print("File metadata:")
        metadata = file_info.get("metadata") or {}

        for label in ("size", "inode", "mode", "mtime", "ctime", "sha256"):
            show(label, metadata.get(label), 1)

        print("-" * 40)


def doctor():
    backend = select_backend()
    sshd = parse_sshd_config()
    files = collect_key_files()
    states = [probe_stat(f["path"])[0] for f in files]

    print("=" * 40)
    print("      SSH KEY GUARD DIAGNOSTICS")
    print("=" * 40)
    print("Version:       {}".format(VERSION))
    print("Platform:      {} {} ({})".format(platform.system(), platform.release(), platform.machine()))
    print("Python:        {}".format(sys.version.split()[0]))
    print("Privileged:    {}".format(is_admin()))
    print("Data dir:      {}".format(DATA_DIR))
    print("sshd_config:   {}".format(sshd["path"] or "not found"))
    print("Match blocks:  {}".format(sshd["match_blocks"]))
    print("SSH ports:     {}".format(", ".join(str(p) for p in get_ssh_ports())))
    print("Key patterns:  {} (union of all blocks)".format(", ".join(get_key_patterns()) or "(none)"))

    if not IS_WINDOWS and is_admin() and find_sshd_binary():
        print("Per-user keys: exact, via 'sshd -T -f <config> -C' (falls back to the union on failure)")
    else:
        print("Per-user keys: union of all Match blocks (superset; needs root + sshd for exact values)")

    print("Accounts:      {}".format(len(get_accounts())))
    print("Key files:     {} ({} exist, {} unreadable)".format(
        len(files), states.count("ok"), states.count("error")))
    print("Audit backend: {} (available: {})".format(backend.name, backend.available()))

    if not backend.available():
        print("               {}".format(backend.hint))
    else:
        backend.recent_events()

        if backend.last_error:
            print("               audit log NOT readable: {}".format(backend.last_error))

    print("Event log:     {} (hash-chained; verify with 'verify-log')".format(EVENTS_FILE))

    if states.count("error"):
        print()
        print("WARNING: some paths are unreadable (run as root/Administrator). They are skipped,")
        print("not treated as deleted.")

    if sshd["authorizedkeyscommand"]:
        print()
        print("WARNING: AuthorizedKeysCommand is set ({}).".format(sshd["authorizedkeyscommand"]))
        print("Keys served by that command are NOT visible to file monitoring.")

    print()
    print("Reminder: local state/logs are not protected against a compromised root.")
    print("Forward events off-host (--syslog with remote forwarding, or --webhook).")


# ----------------------------------------------------------------------------
# Service installation
# ----------------------------------------------------------------------------

def systemd_quote(value):
    return '"' + (value.replace("\\", "\\\\").replace('"', '\\"')
                  .replace("%", "%%").replace("$", "$$")) + '"'


def install_service():
    if not is_admin():
        print("Root/Administrator privileges are required.")
        return False

    python = sys.executable
    script = os.path.abspath(__file__)

    if IS_LINUX and which("systemctl"):
        unit = Path("/etc/systemd/system/{}.service".format(SERVICE_NAME))
        content = (
            "[Unit]\nDescription=ServerGuard SSH Key Guard\n"
            "After=network.target auditd.service\n\n"
            "[Service]\nType=simple\nEnvironment=PYTHONUNBUFFERED=1\n"
            "ExecStart={} {} monitor\nRestart=always\nRestartSec=5\n\n"
            "[Install]\nWantedBy=multi-user.target\n"
        ).format(systemd_quote(python), systemd_quote(script))

        try:
            unit.write_text(content, encoding="utf-8")
        except OSError as exc:
            print("Cannot write {}: {}".format(unit, exc))
            return False

        for step in (["systemctl", "daemon-reload"],
                     ["systemctl", "enable", "--now", SERVICE_NAME + ".service"]):
            code, _, err = run_command(step, timeout=30)

            if code != 0:
                print("'{}' failed: {}".format(" ".join(step), err.strip()))
                return False

        code, out, _ = run_command(["systemctl", "is-active", SERVICE_NAME + ".service"])
        print("systemd service installed (state: {}).".format(out.strip() or "unknown"))
        return code == 0

    if IS_MAC:
        plist = Path("/Library/LaunchDaemons/{}.plist".format(LAUNCHD_LABEL))
        content = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>\n'
            "<key>Label</key><string>{}</string>\n"
            "<key>ProgramArguments</key><array><string>{}</string><string>{}</string>"
            "<string>monitor</string></array>\n"
            "<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n"
            "<key>StandardOutPath</key><string>/var/log/serverguard-ssh-key-guard.log</string>\n"
            "<key>StandardErrorPath</key><string>/var/log/serverguard-ssh-key-guard.log</string>\n"
            "</dict></plist>\n"
        ).format(xml_escape(LAUNCHD_LABEL), xml_escape(python), xml_escape(script))

        try:
            plist.write_text(content, encoding="utf-8")
            os.chmod(str(plist), 0o644)
        except OSError as exc:
            print("Cannot write {}: {}".format(plist, exc))
            return False

        code, _, err = run_command(["launchctl", "bootstrap", "system", str(plist)], timeout=30)

        if code != 0:
            code, _, err = run_command(["launchctl", "load", "-w", str(plist)], timeout=30)

        print("launchd daemon installed." if code == 0 else "launchctl failed: {}".format(err.strip()))
        return code == 0

    if IS_WINDOWS:
        command = '"{}" "{}" monitor'.format(python, script)
        code, _, err = run_command(
            ["schtasks", "/Create", "/TN", WIN_TASK_NAME, "/SC", "ONSTART", "/RU", "SYSTEM",
             "/RL", "HIGHEST", "/F", "/TR", command], timeout=30)

        if code != 0:
            print("schtasks failed: {}".format(err.strip()))
            return False

        code, _, err = run_command(["schtasks", "/Run", "/TN", WIN_TASK_NAME], timeout=30)
        print("Scheduled task installed." if code == 0 else
              "Task created but could not be started: {}".format(err.strip()))
        return code == 0

    print("Automatic service install is not implemented for {}.".format(platform.system()))
    print("Add to the root crontab:")
    print("  @reboot '{}' '{}' monitor >> /var/log/serverguard-ssh-key-guard.log 2>&1".format(
        python.replace("'", "'\\''"), script.replace("'", "'\\''")))
    return False


def uninstall_service():
    if not is_admin():
        print("Root/Administrator privileges are required.")
        return False

    ok = True

    if IS_LINUX and which("systemctl"):
        run_command(["systemctl", "disable", "--now", SERVICE_NAME + ".service"], timeout=30)
        unit = Path("/etc/systemd/system/{}.service".format(SERVICE_NAME))

        try:
            if unit.exists():
                unit.unlink()
        except OSError as exc:
            print("Cannot remove {}: {}".format(unit, exc))
            ok = False

        code, _, err = run_command(["systemctl", "daemon-reload"], timeout=30)

        if code != 0:
            print("daemon-reload failed: {}".format(err.strip()))
            ok = False

    elif IS_MAC:
        run_command(["launchctl", "bootout", "system/" + LAUNCHD_LABEL], timeout=30)
        plist = Path("/Library/LaunchDaemons/{}.plist".format(LAUNCHD_LABEL))

        try:
            if plist.exists():
                plist.unlink()
        except OSError as exc:
            print("Cannot remove {}: {}".format(plist, exc))
            ok = False

    elif IS_WINDOWS:
        run_command(["schtasks", "/End", "/TN", WIN_TASK_NAME], timeout=30)
        code, _, err = run_command(["schtasks", "/Delete", "/TN", WIN_TASK_NAME, "/F"], timeout=30)

        if code != 0:
            print("schtasks delete failed: {}".format(err.strip()))
            ok = False

    print("Service removed." if ok else "Service removal finished with errors.")
    return ok


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def apply_common(args):
    CFG["geoip"] = bool(getattr(args, "geoip", False))
    CFG["syslog"] = bool(getattr(args, "syslog", False))
    CFG["json"] = bool(getattr(args, "json", False))

    if getattr(args, "webhook", None):
        CFG["webhook"] = args.webhook


def build_parser():
    parser = argparse.ArgumentParser(description="ServerGuard SSH Key Guard {}".format(VERSION))
    sub = parser.add_subparsers(dest="command")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--geoip", action="store_true", help="look up CONFIRMED source IPs on ipinfo.io (sends those IPs to a third party)")
    common.add_argument("--webhook", help="POST each event as JSON to this URL")
    common.add_argument("--syslog", action="store_true", help="also log events to syslog / Windows Application log")
    common.add_argument("--json", action="store_true", help="print full JSON events")
    common.add_argument("--no-audit", action="store_true", help="disable OS audit integration")

    monitor_parser = sub.add_parser("monitor", parents=[common], help="run continuous monitoring")
    monitor_parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL)

    sub.add_parser("init", parents=[common], help="create/reset the baseline")
    sub.add_parser("scan", parents=[common], help="single scan")

    events_parser = sub.add_parser("events", help="show recorded events")
    events_parser.add_argument("count", nargs="?", type=int, default=20)
    events_parser.add_argument("--json", action="store_true")
    events_parser.add_argument("--action", help="filter by action (key_added, key_removed, ...)")

    sub.add_parser("audit", help="show OS audit backend status")
    sub.add_parser("audit-remove", help="remove audit rules / SACLs")
    sub.add_parser("verify-log", help="verify the hash chain of the event log")
    sub.add_parser("doctor", help="platform diagnostics")
    sub.add_parser("install-service", help="install as a system service")
    sub.add_parser("uninstall-service", help="remove the system service")
    sub.add_parser("version")
    return parser


def main():
    if sys.version_info < (3, 7):
        sys.exit("Python 3.7 or newer is required.")

    parser = build_parser()
    args = parser.parse_args()
    apply_common(args)

    if args.command in ("monitor", "init", "scan"):
        ensure_data_dir()

    backend = None if getattr(args, "no_audit", False) else select_backend()

    if args.command == "monitor":
        monitor(max(1, args.interval), use_audit=not args.no_audit)

    elif args.command == "init":
        with state_lock() as lock:
            if lock.locked:
                initialize(backend)
            else:
                warn("Could not obtain the state lock (another scan is running).")

    elif args.command == "scan":
        events = scan_once(True, backend if is_admin() else None)

        if not events:
            print("No SSH key changes detected.")

        for event in events:
            print_event(event)

    elif args.command == "events":
        show_events(args.count, args.json, args.action)

    elif args.command == "audit":
        select_backend().status()

    elif args.command == "audit-remove":
        if select_backend().teardown():
            print("SSH Key Guard audit rules removed.")

    elif args.command == "verify-log":
        sys.exit(0 if verify_event_log() else 1)

    elif args.command == "doctor":
        doctor()

    elif args.command == "install-service":
        install_service()

    elif args.command == "uninstall-service":
        uninstall_service()

    elif args.command == "version":
        print("ServerGuard SSH Key Guard {}".format(VERSION))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""ServerGuard Brute Force Guard (SSH).

CLI:
    brute_force_guard.py               run the monitor (systemd service)
    brute_force_guard.py --selftest    quick environment check (exit 0 = OK)
    brute_force_guard.py --cleanup     remove every firewall block created by the guard
    brute_force_guard.py --trust IP    add IP to the trusted list (never blocked)

Compatible with Python 3.6+.
"""

import collections
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

VERSION = "2.0"

BASE_DIR = Path("/opt/serverguard")
DATA_DIR = BASE_DIR / "data"

PROTECTION_CONFIG_FILE = DATA_DIR / "protection_config.json"
TRUSTED_FILE = DATA_DIR / "trusted_ips.json"
EVENTS_FILE = DATA_DIR / "ssh_events.json"
BLOCKS_FILE = DATA_DIR / "blocked_ips.json"
STATS_FILE = DATA_DIR / "stats.json"
STATE_FILE = DATA_DIR / "guard_state.json"

MAX_EVENTS = 2000
EVENT_RETENTION_DAYS = 7
MAX_TRACKED_IPS = 50000
MAX_RESUME_SECONDS = 600
FLUSH_INTERVAL = 5
MAINTENANCE_INTERVAL = 60
CONFIG_CHECK_INTERVAL = 5
COMMAND_TIMEOUT = 15

DEFAULT_CONFIG = {
    "enabled": True,
    "attempts": 5,
    "duration": 600,
    "permanent": False,
    "mode": "ip",
    "whitelist": [],
    "window": 3600,            # sliding window for counting failures (seconds)
    "trust_login_hours": 6,    # IP with a recent successful login is never banned (0 = off)
}

_UNREADABLE = object()

STOP = threading.Event()
LOCK = threading.RLock()
CURRENT_PROC = None

CACHED_CONFIG = dict(DEFAULT_CONFIG)
CACHED_CONFIG["whitelist"] = []
LAST_CONFIG_LOAD = 0
_LOCAL_CACHE = (0, set())

EVENTS = []
STATS = {}
STATE = {}
DIRTY = {"events": False, "stats": False, "state": False}

ATTEMPTS = {}          # ip -> deque of failure timestamps
PENDING_INVALID = {}   # (ip, user) -> ts   (avoid counting "Invalid user" + "Failed password" twice)
KEY_SEEN = {}          # (ip, user) -> ts   (publickey failures are noisy: count once per minute)
RECENT_SUCCESS = {}    # ip -> ts of last successful login


# --------------------------------------------------------------------------
# Basic helpers
# --------------------------------------------------------------------------

def log(message):
    print("[ServerGuard] %s" % message, flush=True)


def ensure_directories():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(BASE_DIR), 0o700)
        os.chmod(str(DATA_DIR), 0o700)
    except OSError:
        pass


def run_command(command, timeout=COMMAND_TIMEOUT, retries=3):
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    env["PATH"] = env.get("PATH", "") + ":/usr/local/sbin:/usr/sbin:/sbin"

    result = None
    for attempt in range(retries):
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=timeout,
                env=env,
            )
        except subprocess.TimeoutExpired:
            log("Command timed out: %s" % " ".join(command))
            return None
        except (OSError, subprocess.SubprocessError) as exc:
            log("Command error (%s): %s" % (command[0], exc))
            return None

        text = (result.stderr or "").lower()
        busy = ("xtables lock" in text or "could not get lock" in text
                or "resource temporarily unavailable" in text)

        if result.returncode != 0 and busy and attempt < retries - 1:
            time.sleep(1.5)
            continue

        return result

    return result


def load_json(path, default, quarantine=False):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default
    except ValueError as exc:
        log("Corrupted JSON in %s: %s" % (path, exc))
        if quarantine:
            try:
                path.replace(path.with_name("%s.corrupt-%d" % (path.name, int(time.time()))))
            except OSError:
                pass
        return default
    except OSError as exc:
        log("Cannot read %s: %s" % (path, exc))
        return default


def save_json(path, data):
    temporary = path.with_name(path.name + ".tmp")

    try:
        path.parent.mkdir(parents=True, exist_ok=True)

        fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(str(temporary), str(path))
        return True

    except (OSError, TypeError, ValueError) as exc:
        log("Cannot save %s: %s" % (path, exc))
        try:
            temporary.unlink()
        except OSError:
            pass
        return False


def as_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
    return default


def clamp_int(value, default, low, high):
    try:
        return max(low, min(int(value), high))
    except (TypeError, ValueError):
        return default


def utc_iso(timestamp=None):
    if timestamp is None:
        timestamp = time.time()
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def normalize_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Local / trusted addresses and config
# --------------------------------------------------------------------------

def get_local_ips():
    global _LOCAL_CACHE

    now = time.time()
    if now - _LOCAL_CACHE[0] < 60 and _LOCAL_CACHE[1]:
        return _LOCAL_CACHE[1]

    addresses = {"127.0.0.1", "::1"}

    result = run_command(["ip", "-o", "addr", "show"], timeout=5, retries=1)
    if result and result.returncode == 0:
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 4:
                address = normalize_ip(fields[3].split("/")[0])
                if address:
                    addresses.add(address)

    result = run_command(["hostname", "-I"], timeout=5, retries=1)
    if result and result.returncode == 0:
        for value in result.stdout.split():
            address = normalize_ip(value)
            if address:
                addresses.add(address)

    _LOCAL_CACHE = (now, addresses)
    return addresses


def load_trusted_ips():
    data = load_json(TRUSTED_FILE, [])
    result = []
    if isinstance(data, list):
        for entry in data:
            try:
                result.append(str(ipaddress.ip_network(str(entry).strip(), strict=False)))
            except ValueError:
                pass
    return result


def load_protection_config(force=False):
    global CACHED_CONFIG, LAST_CONFIG_LOAD

    now = time.time()
    if not force and now - LAST_CONFIG_LOAD < CONFIG_CHECK_INTERVAL:
        return dict(CACHED_CONFIG)

    data = load_json(PROTECTION_CONFIG_FILE, _UNREADABLE)

    if data is _UNREADABLE:
        if PROTECTION_CONFIG_FILE.exists():
            # unreadable right now (partial write?) -> keep last good config
            LAST_CONFIG_LOAD = now
            return dict(CACHED_CONFIG)
        data = {}

    if not isinstance(data, dict):
        data = {}

    config = dict(DEFAULT_CONFIG)
    config.update(data)

    config["enabled"] = as_bool(config.get("enabled"), True)
    config["permanent"] = as_bool(config.get("permanent"), False)
    config["attempts"] = clamp_int(config.get("attempts"), 5, 1, 100)
    config["duration"] = clamp_int(config.get("duration"), 600, 60, 30 * 86400)
    config["window"] = clamp_int(config.get("window"), 3600, 60, 86400)
    config["trust_login_hours"] = clamp_int(config.get("trust_login_hours"), 6, 0, 168)
    config["mode"] = "ip"

    entries = []
    user_whitelist = config.get("whitelist", [])
    if isinstance(user_whitelist, list):
        for entry in user_whitelist:
            try:
                entries.append(str(ipaddress.ip_network(str(entry).strip(), strict=False)))
            except ValueError:
                log("Ignoring invalid whitelist entry: %s" % entry)

    entries.extend(load_trusted_ips())
    entries.extend(get_local_ips())

    clean = []
    for entry in entries:
        try:
            normalized = str(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
        if normalized not in clean:
            clean.append(normalized)

    config["whitelist"] = clean

    CACHED_CONFIG = config
    LAST_CONFIG_LOAD = now
    return dict(config)


def is_whitelisted(ip, config):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for entry in config.get("whitelist", []):
        try:
            if address in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue

    return False


# --------------------------------------------------------------------------
# In-memory state (events, stats) with periodic flush
# --------------------------------------------------------------------------

def init_state():
    global EVENTS, STATS, STATE

    data = load_json(EVENTS_FILE, [], quarantine=True)
    EVENTS = data if isinstance(data, list) else []

    data = load_json(STATS_FILE, {}, quarantine=True)
    STATS = data if isinstance(data, dict) else {}
    for key in ("blocked", "unblocked", "failed", "success"):
        try:
            STATS[key] = int(STATS.get(key, 0))
        except (TypeError, ValueError):
            STATS[key] = 0

    data = load_json(STATE_FILE, {})
    STATE = data if isinstance(data, dict) else {}


def flush_state(force=False):
    with LOCK:
        if DIRTY["events"] or force:
            if save_json(EVENTS_FILE, EVENTS[-MAX_EVENTS:]):
                DIRTY["events"] = False
        if DIRTY["stats"] or force:
            if save_json(STATS_FILE, STATS):
                DIRTY["stats"] = False
        if DIRTY["state"] or force:
            if save_json(STATE_FILE, STATE):
                DIRTY["state"] = False


def save_event(event_type, ip, username, auth_method, raw, ts):
    with LOCK:
        EVENTS.append({
            "time": int(ts),
            "time_iso": utc_iso(ts),
            "type": event_type,
            "username": username,
            "ip": ip,
            "auth_method": auth_method,
            "raw": raw[:1000],
        })
        if len(EVENTS) > MAX_EVENTS * 2:
            del EVENTS[:-MAX_EVENTS]
        DIRTY["events"] = True


def update_stat(name):
    with LOCK:
        try:
            STATS[name] = int(STATS.get(name, 0)) + 1
        except (TypeError, ValueError):
            STATS[name] = 1
        DIRTY["stats"] = True


# --------------------------------------------------------------------------
# Block records (file based, written immediately)
# --------------------------------------------------------------------------

def load_blocks():
    data = load_json(BLOCKS_FILE, {}, quarantine=True)
    return data if isinstance(data, dict) else {}


def save_blocks(blocks):
    return save_json(BLOCKS_FILE, blocks)


def create_block(ip, failed_attempts, config):
    now = int(time.time())
    permanent = config["permanent"]
    duration = config["duration"]
    expires_at = None if permanent else now + duration

    blocks = load_blocks()
    blocks[ip] = {
        "ip": ip,
        "blocked_at": now,
        "blocked_at_iso": utc_iso(now),
        "failed_attempts": failed_attempts,
        "permanent": permanent,
        "duration": duration,
        "expires_at": expires_at,
        "expires_at_iso": utc_iso(expires_at) if expires_at else None,
        "reason": "SSH brute-force protection",
    }
    return save_blocks(blocks)


def remove_block_record(ip):
    blocks = load_blocks()
    if ip in blocks:
        del blocks[ip]
        save_blocks(blocks)


# --------------------------------------------------------------------------
# Firewall backends: UFW (if active) with iptables fallback
# --------------------------------------------------------------------------

def ufw_status_text():
    if not shutil.which("ufw"):
        return None
    result = run_command(["ufw", "status"])
    if result and result.returncode == 0:
        return result.stdout
    return None


def ufw_denied_set(text):
    denied = set()
    if not text:
        return denied

    for line in text.splitlines():
        body = line.split("#")[0].strip()
        upper = body.upper()

        if not body.startswith("Anywhere"):
            continue
        if "DENY" not in upper and "REJECT" not in upper:
            continue

        for token in body.split():
            address = normalize_ip(token)
            if address:
                denied.add(address)

    return denied


def _ipt(ip):
    return "ip6tables" if ":" in ip else "iptables"


def iptables_is_blocked(ip):
    tool = _ipt(ip)
    if not shutil.which(tool):
        return False
    result = run_command([tool, "-C", "INPUT", "-s", ip, "-j", "DROP"], retries=2)
    return bool(result and result.returncode == 0)


def iptables_block(ip):
    tool = _ipt(ip)
    if not shutil.which(tool):
        return False
    if iptables_is_blocked(ip):
        return True
    result = run_command([tool, "-I", "INPUT", "1", "-s", ip, "-j", "DROP"])
    return bool(result and result.returncode == 0)


def iptables_unblock(ip):
    tool = _ipt(ip)
    if not shutil.which(tool):
        return True
    for _ in range(5):
        if not iptables_is_blocked(ip):
            return True
        run_command([tool, "-D", "INPUT", "-s", ip, "-j", "DROP"])
    return not iptables_is_blocked(ip)


def ufw_block(ip, status_text):
    if ip in ufw_denied_set(status_text):
        return True

    result = run_command(["ufw", "insert", "1", "deny", "from", ip])

    if not (result and result.returncode == 0):
        # "insert 1" fails when there are no rules yet
        result = run_command(["ufw", "deny", "from", ip])

    return bool(result and result.returncode == 0)


def fw_block(ip):
    text = ufw_status_text()

    if text is not None and "Status: active" in text:
        if ufw_block(ip, text):
            return True
        log("[FW] UFW could not add the rule for %s, trying iptables" % ip)

    if iptables_block(ip):
        return True

    log("[FW ERROR] No working firewall backend (UFW inactive/failed and iptables unavailable)")
    return False


def fw_is_blocked(ip, text=None):
    if text is None:
        text = ufw_status_text()
    if text and ip in ufw_denied_set(text):
        return True
    return iptables_is_blocked(ip)


def fw_unblock(ip):
    if not normalize_ip(ip):
        return True

    ok = True

    text = ufw_status_text()
    if text and ip in ufw_denied_set(text):
        for _ in range(5):
            # --force is required, otherwise ufw asks for confirmation and aborts
            run_command(["ufw", "--force", "delete", "deny", "from", ip])
            text = ufw_status_text()
            if not text or ip not in ufw_denied_set(text):
                break
        else:
            ok = False

    if not iptables_unblock(ip):
        ok = False

    if not ok:
        log("[UNBLOCK ERROR] %s" % ip)

    return ok


# --------------------------------------------------------------------------
# Blocking logic
# --------------------------------------------------------------------------

def block_ip(ip, failed_attempts, config):
    address = normalize_ip(ip)

    if not address:
        log("[SAFETY] Invalid IP ignored: %s" % ip)
        return False

    if is_whitelisted(address, config):
        log("[WHITELIST] Skipping %s" % address)
        return False

    if address in get_local_ips():
        log("[SAFETY] Skipping local/server IP %s" % address)
        return False

    with LOCK:
        # record first, firewall second: a crash in between never leaves an orphan rule
        if not create_block(address, failed_attempts, config):
            log("[ERROR] Cannot write block record for %s" % address)
            return False

        if not fw_block(address):
            remove_block_record(address)
            return False

    update_stat("blocked")

    if config["permanent"]:
        log("[BLOCK] %s blocked permanently after %d failed attempts" % (address, failed_attempts))
    else:
        log("[BLOCK] %s blocked for %d seconds" % (address, config["duration"]))

    return True


def expire_blocks():
    blocks = load_blocks()
    if not blocks:
        return

    config = load_protection_config()
    now = int(time.time())
    changed = False

    for ip, block in list(blocks.items()):
        if not isinstance(block, dict) or not normalize_ip(ip):
            del blocks[ip]
            changed = True
            continue

        # IP was added to the whitelist after being blocked -> free it
        if is_whitelisted(ip, config):
            if fw_unblock(ip):
                del blocks[ip]
                changed = True
                update_stat("unblocked")
                log("[WHITELIST] %s unblocked (now whitelisted)" % ip)
            continue

        if block.get("permanent", False):
            continue

        try:
            expires_at = int(block.get("expires_at"))
        except (TypeError, ValueError):
            try:
                expires_at = int(block.get("blocked_at")) + int(block.get("duration"))
            except (TypeError, ValueError):
                expires_at = now

        if expires_at > now:
            continue

        if fw_unblock(ip):
            del blocks[ip]
            changed = True
            update_stat("unblocked")
            log("[EXPIRED] Temporary block expired for %s" % ip)

    if changed:
        save_blocks(blocks)


def reconcile_blocks():
    """Re-apply firewall rules that disappeared (ufw reset, reboot with iptables, ...)."""
    blocks = load_blocks()
    if not blocks:
        return

    text = ufw_status_text()
    denied = ufw_denied_set(text) if text else set()

    for ip in list(blocks):
        if not normalize_ip(ip):
            continue
        if ip in denied or iptables_is_blocked(ip):
            continue
        log("[RESTORE] Firewall rule missing for %s, re-applying" % ip)
        fw_block(ip)


def cleanup_events():
    cutoff = int(time.time() - EVENT_RETENTION_DAYS * 86400)

    with LOCK:
        cleaned = []
        for event in EVENTS:
            if not isinstance(event, dict):
                continue
            try:
                if int(event.get("time", 0)) >= cutoff:
                    cleaned.append(event)
            except (TypeError, ValueError):
                continue

        cleaned = cleaned[-MAX_EVENTS:]

        if len(cleaned) != len(EVENTS):
            EVENTS[:] = cleaned
            DIRTY["events"] = True


def cleanup_attempts():
    now = time.time()
    window = load_protection_config()["window"]

    for ip, queue in list(ATTEMPTS.items()):
        while queue and queue[0] < now - window:
            queue.popleft()
        if not queue:
            del ATTEMPTS[ip]

    for table in (PENDING_INVALID, KEY_SEEN):
        for key, stamp in list(table.items()):
            if now - stamp > 120:
                del table[key]

    for ip, stamp in list(RECENT_SUCCESS.items()):
        if now - stamp > 7 * 86400:
            del RECENT_SUCCESS[ip]


def register_failure(ip, ts, window):
    queue = ATTEMPTS.get(ip)

    if queue is None:
        if len(ATTEMPTS) >= MAX_TRACKED_IPS:
            cleanup_attempts()
        if len(ATTEMPTS) >= MAX_TRACKED_IPS:
            oldest = min(ATTEMPTS, key=lambda key: ATTEMPTS[key][-1])
            del ATTEMPTS[oldest]
        queue = ATTEMPTS[ip] = collections.deque()

    queue.append(ts)
    cutoff = ts - window

    while queue and queue[0] < cutoff:
        queue.popleft()

    return len(queue)


# --------------------------------------------------------------------------
# Log parsing
# --------------------------------------------------------------------------

IP_RE = r"(?P<ip>[0-9a-fA-F:.]+)"

FAILED_PATTERNS = (
    ("failed_password", re.compile(
        r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from " + IP_RE)),
    ("failed_publickey", re.compile(
        r"Failed publickey for (?P<invalid>invalid user )?(?P<user>\S+) from " + IP_RE)),
    ("failed_keyboard", re.compile(
        r"Failed keyboard-interactive/pam for (?P<invalid>invalid user )?(?P<user>\S+) from " + IP_RE)),
    ("invalid_user", re.compile(
        r"Invalid user (?P<user>.*?) from " + IP_RE)),
)

SUCCESS_PATTERN = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from " + IP_RE)


def recently_succeeded(ip, config, now):
    hours = config.get("trust_login_hours", 0)
    if hours <= 0:
        return False
    stamp = RECENT_SUCCESS.get(ip)
    return stamp is not None and now - stamp < hours * 3600


def handle_failed_login(username, address, raw, event_type, ts):
    config = load_protection_config()

    save_event(event_type, address, username, "", raw, ts)
    update_stat("failed")

    if not config["enabled"]:
        return

    if is_whitelisted(address, config):
        log("[WHITELIST] Failed SSH from %s" % address)
        return

    if recently_succeeded(address, config, ts):
        log("[SAFETY] %s failed login ignored (recent successful login)" % address)
        return

    attempts = register_failure(address, ts, config["window"])
    threshold = config["attempts"]

    log("[SSH FAILED] IP=%s user=%s attempt=%d/%d" % (address, username, attempts, threshold))

    if attempts < threshold:
        return

    existing = load_blocks().get(address)
    if isinstance(existing, dict):
        if existing.get("permanent", False):
            return
        try:
            if int(existing.get("expires_at", 0)) > int(time.time()):
                return
        except (TypeError, ValueError):
            pass

    if block_ip(address, attempts, config):
        ATTEMPTS.pop(address, None)


def handle_success_login(username, address, method, raw, ts):
    save_event("success", address, username, method, raw, ts)
    update_stat("success")
    RECENT_SUCCESS[address] = ts

    if address in ATTEMPTS:
        del ATTEMPTS[address]
        log("[SSH SUCCESS] Counter reset for %s" % address)
    else:
        log("[SSH SUCCESS] %s" % address)


def process_line(line, ts):
    line = line.strip()
    if not line:
        return

    match = SUCCESS_PATTERN.search(line)
    if match:
        address = normalize_ip(match.group("ip"))
        if address:
            handle_success_login(match.group("user"), address, match.group("method"), line, ts)
        return

    for event_type, pattern in FAILED_PATTERNS:
        match = pattern.search(line)
        if not match:
            continue

        groups = match.groupdict()
        address = normalize_ip(groups.get("ip"))
        if not address:
            return

        user = (groups.get("user") or "unknown").strip() or "unknown"
        invalid = bool(groups.get("invalid"))
        key = (address, user)
        counted = True

        # One real attempt produces several log lines. Count it only once.
        if event_type == "invalid_user":
            PENDING_INVALID[key] = ts
        elif invalid and key in PENDING_INVALID and abs(ts - PENDING_INVALID[key]) <= 30:
            del PENDING_INVALID[key]
            counted = False
        elif event_type == "failed_publickey":
            if ts - KEY_SEEN.get(key, 0) < 60:
                counted = False
            else:
                KEY_SEEN[key] = ts

        if counted:
            handle_failed_login(user, address, line, event_type, ts)
        return


def bootstrap_recent_success(hours):
    """Remember who logged in successfully before the guard (re)started."""
    if hours <= 0 or not shutil.which("journalctl"):
        return

    result = run_command([
        "journalctl", "--no-pager", "-o", "short-unix",
        "-t", "sshd", "-t", "sshd-session",
        "--since", "%d hours ago" % hours,
    ], timeout=30, retries=1)

    if not result or result.returncode != 0:
        return

    count = 0
    for line in result.stdout.splitlines():
        match = SUCCESS_PATTERN.search(line)
        if not match:
            continue
        address = normalize_ip(match.group("ip"))
        if not address:
            continue
        try:
            stamp = float(line.split(" ", 1)[0])
        except ValueError:
            stamp = time.time()
        RECENT_SUCCESS[address] = max(stamp, RECENT_SUCCESS.get(address, 0))
        count += 1

    if count:
        log("Loaded %d recent successful logins (trusted for %d h)" % (count, hours))


# --------------------------------------------------------------------------
# Log source
# --------------------------------------------------------------------------

def build_source_command(since_ts):
    if shutil.which("journalctl"):
        command = [
            "journalctl", "-f", "--no-pager", "-o", "short-unix",
            "-t", "sshd", "-t", "sshd-session", "-t", "sshd-auth",
        ]
        if since_ts:
            command += ["--since", "@%d" % int(since_ts), "-n", "all"]
        else:
            command += ["-n", "0"]
        return command, "journal"

    for path in ("/var/log/auth.log", "/var/log/secure"):
        if os.path.exists(path):
            return ["tail", "-n", "0", "-F", path], "file"

    return None, None


def split_timestamp(line, kind):
    if kind == "journal":
        head, _, rest = line.partition(" ")
        try:
            return float(head), rest
        except ValueError:
            pass
    return time.time(), line


def run_monitor():
    global CURRENT_PROC

    failures = 0

    while not STOP.is_set():
        last = float(STATE.get("last_ts") or 0)
        since = max(last, time.time() - MAX_RESUME_SECONDS) if last > 0 else None

        command, kind = build_source_command(since)

        if command is None:
            log("[ERROR] No SSH log source found (journalctl, /var/log/auth.log, /var/log/secure). Retry in 30s")
            STOP.wait(30)
            continue

        log("Starting SSH log monitor (%s)..." % kind)

        process = None
        started = time.time()

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
                errors="replace",
                bufsize=1,
            )
            CURRENT_PROC = process

            for raw_line in process.stdout:
                if STOP.is_set():
                    break

                ts, text = split_timestamp(raw_line.rstrip("\n"), kind)

                if ts < last:
                    continue

                try:
                    with LOCK:
                        process_line(text, ts)
                        STATE["last_ts"] = ts
                        DIRTY["state"] = True
                except Exception as exc:  # never let one bad line kill the monitor
                    log("Line processing error: %s" % exc)

        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            log("Monitor error: %s" % exc)

        finally:
            CURRENT_PROC = None
            if process is not None:
                if process.poll() is None:
                    try:
                        process.terminate()
                        process.wait(timeout=3)
                    except (OSError, subprocess.SubprocessError):
                        try:
                            process.kill()
                        except OSError:
                            pass
                try:
                    process.stdout.close()
                except Exception:
                    pass

        if STOP.is_set():
            break

        failures = failures + 1 if time.time() - started < 10 else 0
        delay = min(3 * (2 ** min(failures, 5)), 60)
        log("Log source stopped. Restarting in %d seconds..." % delay)
        STOP.wait(delay)


def maintenance_loop():
    last_slow = 0.0

    while not STOP.wait(FLUSH_INTERVAL):
        try:
            with LOCK:
                flush_state()

                now = time.time()
                if now - last_slow >= MAINTENANCE_INTERVAL:
                    expire_blocks()
                    reconcile_blocks()
                    cleanup_events()
                    cleanup_attempts()
                    last_slow = now
        except Exception as exc:
            log("Maintenance error: %s" % exc)


# --------------------------------------------------------------------------
# CLI helpers
# --------------------------------------------------------------------------

def selftest():
    try:
        ensure_directories()
    except OSError as exc:
        print("selftest: cannot create data directory: %s" % exc)
        return 1

    if sys.version_info < (3, 6):
        print("selftest: Python 3.6+ required")
        return 1

    command, kind = build_source_command(None)
    if command is None:
        print("selftest: no SSH log source (journalctl / auth.log / secure)")
        return 1

    if not (shutil.which("ufw") or shutil.which("iptables")):
        print("selftest: WARNING no ufw/iptables found, blocking will not work")

    print("selftest OK (log source: %s, version %s)" % (kind, VERSION))
    return 0


def cleanup_all():
    try:
        ensure_directories()
    except OSError:
        pass

    blocks = load_blocks()
    failed = 0

    for ip in list(blocks):
        if fw_unblock(ip):
            del blocks[ip]
        else:
            failed += 1

    save_blocks(blocks)
    print("cleanup: %d block(s) left, %d removed" % (len(blocks), 0 if failed else 0))
    return 0 if failed == 0 else 1


def trust_ip(value):
    address = normalize_ip(value)
    if not address:
        print("Invalid IP: %s" % value)
        return 1

    ensure_directories()
    data = load_json(TRUSTED_FILE, [])
    if not isinstance(data, list):
        data = []

    if address not in data:
        data.append(address)
        if not save_json(TRUSTED_FILE, data):
            return 1

    print("trusted: %s" % address)
    return 0


# --------------------------------------------------------------------------
# Service entry point
# --------------------------------------------------------------------------

def _stop(signum, frame):
    STOP.set()
    proc = CURRENT_PROC
    if proc is not None:
        try:
            proc.terminate()
        except OSError:
            pass


def run_service():
    ensure_directories()
    init_state()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    log("========================================")
    log("ServerGuard Brute Force Guard v%s" % VERSION)
    log("========================================")

    config = load_protection_config(force=True)

    log("Protection: %s" % ("ON" if config["enabled"] else "OFF"))
    log("Block after: %d failed attempts within %d s" % (config["attempts"], config["window"]))

    if config["permanent"]:
        log("Block type: PERMANENT")
    else:
        log("Block type: TEMPORARY (%d seconds)" % config["duration"])

    log("Whitelist entries (incl. server/trusted IPs): %d" % len(config["whitelist"]))

    with LOCK:
        bootstrap_recent_success(config["trust_login_hours"])
        expire_blocks()
        reconcile_blocks()

    worker = threading.Thread(target=maintenance_loop, name="maintenance", daemon=True)
    worker.start()

    try:
        run_monitor()
    finally:
        STOP.set()
        worker.join(timeout=10)
        flush_state(force=True)
        log("Stopped.")


def main():
    args = sys.argv[1:]

    if args:
        if args[0] == "--selftest":
            return selftest()
        if args[0] == "--cleanup":
            return cleanup_all()
        if args[0] == "--trust" and len(args) > 1:
            return trust_ip(args[1])
        if args[0] in ("--version", "-V"):
            print(VERSION)
            return 0

    run_service()
    return 0


if __name__ == "__main__":
    sys.exit(main())

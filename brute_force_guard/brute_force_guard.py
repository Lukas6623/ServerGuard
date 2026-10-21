#!/usr/bin/env python3

import fcntl
import ipaddress
import json
import os
import re
import select
import subprocess
import sys
import tempfile
import time
import threading
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path("/opt/serverguard")
DATA_DIR = BASE_DIR / "data"
PROTECTION_CONFIG_FILE = DATA_DIR / "protection_config.json"
EVENTS_FILE = DATA_DIR / "ssh_events.json"
BLOCKS_FILE = DATA_DIR / "blocked_ips.json"
STATS_FILE = DATA_DIR / "stats.json"
ATTEMPTS_FILE = DATA_DIR / "failed_attempts.json"
LOCK_FILE = DATA_DIR / "brute_force_guard.lock"

MAX_EVENTS = 2000
EVENT_RETENTION_DAYS = 7
CLEANUP_INTERVAL = 60
CONFIG_CHECK_INTERVAL = 5
COMMAND_TIMEOUT = 10
ATTEMPT_WINDOW_SECONDS = 3600
MAX_RAW_LINE = 1000

DEFAULT_CONFIG = {
    "enabled": True,
    "attempts": 5,
    "duration": 600,
    "permanent": False,
    "mode": "ip",
    "whitelist": [],
}

FAILED_ATTEMPTS = {}
CACHED_CONFIG = dict(DEFAULT_CONFIG)
LAST_CONFIG_LOAD = 0.0
LAST_CONFIG_MTIME = None
LOCAL_IPS_CACHE = {"127.0.0.1", "::1"}
LOCAL_IPS_CACHE_AT = 0.0
FILE_LOCK = threading.RLock()

FAILED_PATTERNS = (
    ("failed_password", re.compile(r"Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)\b")),
    ("failed_publickey", re.compile(r"Failed publickey for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)\b")),
    ("failed_keyboard_interactive", re.compile(r"Failed keyboard-interactive/pam for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)\b")),
)

SUCCESS_PATTERNS = (
    ("password", re.compile(r"Accepted password for (\S+) from ([0-9a-fA-F:.]+)\b")),
    ("publickey", re.compile(r"Accepted publickey for (\S+) from ([0-9a-fA-F:.]+)\b")),
    ("keyboard-interactive", re.compile(r"Accepted keyboard-interactive/pam for (\S+) from ([0-9a-fA-F:.]+)\b")),
)

AUXILIARY_PATTERNS = (
    re.compile(r"Invalid user (\S+) from ([0-9a-fA-F:.]+)\b"),
    re.compile(r"authentication failure.*rhost=([0-9a-fA-F:.]+)", re.IGNORECASE),
)


def log(message):
    print(f"[ServerGuard] {message}", flush=True)


def ensure_directories():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        DATA_DIR.chmod(0o700)
    except OSError:
        pass


def run_command(command, timeout=COMMAND_TIMEOUT):
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log(f"Command error ({command[0]}): {exc}")
        return None


def load_json(path, default):
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        return default
    except (OSError, json.JSONDecodeError) as exc:
        log(f"Cannot read {path}: {exc}")
        return default


def save_json(path, data):
    temporary_path = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with FILE_LOCK:
            fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
            temporary_path = Path(name)
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump(data, file, indent=2, ensure_ascii=False)
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, path)
            try:
                dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        return True
    except (OSError, TypeError, ValueError) as exc:
        log(f"Cannot save {path}: {exc}")
        if temporary_path:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
        return False


def as_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on", "enabled"}:
            return True
        if lowered in {"0", "false", "no", "off", "disabled"}:
            return False
    return default


def load_protection_config(force=False):
    global CACHED_CONFIG, LAST_CONFIG_LOAD, LAST_CONFIG_MTIME
    now = time.monotonic()
    try:
        mtime = PROTECTION_CONFIG_FILE.stat().st_mtime_ns
    except OSError:
        mtime = None
    if not force and now - LAST_CONFIG_LOAD < CONFIG_CHECK_INTERVAL and mtime == LAST_CONFIG_MTIME:
        return dict(CACHED_CONFIG)

    data = load_json(PROTECTION_CONFIG_FILE, dict(DEFAULT_CONFIG))
    if not isinstance(data, dict):
        data = {}

    config = dict(DEFAULT_CONFIG)
    config.update(data)
    config["enabled"] = as_bool(config.get("enabled"), True)
    config["permanent"] = as_bool(config.get("permanent"), False)

    try:
        config["attempts"] = max(2, min(int(config.get("attempts", 5)), 100))
    except (TypeError, ValueError, OverflowError):
        config["attempts"] = DEFAULT_CONFIG["attempts"]

    try:
        config["duration"] = max(60, min(int(config.get("duration", 600)), 30 * 86400))
    except (TypeError, ValueError, OverflowError):
        config["duration"] = DEFAULT_CONFIG["duration"]

    whitelist = config.get("whitelist", [])
    clean_whitelist = []
    if isinstance(whitelist, list):
        for entry in whitelist:
            try:
                normalized = str(ipaddress.ip_network(str(entry).strip(), strict=False))
                if normalized not in clean_whitelist:
                    clean_whitelist.append(normalized)
            except (ValueError, TypeError):
                log(f"Ignoring invalid whitelist entry: {entry!r}")

    config["whitelist"] = clean_whitelist
    config["mode"] = "ip"
    CACHED_CONFIG = config
    LAST_CONFIG_LOAD = now
    LAST_CONFIG_MTIME = mtime
    return dict(config)


def utc_iso(timestamp=None):
    if timestamp is None:
        timestamp = time.time()
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def load_events():
    data = load_json(EVENTS_FILE, [])
    return data if isinstance(data, list) else []


def save_event(event_type, ip, username="unknown", auth_method="", raw=""):
    events = load_events()
    now = int(time.time())
    events.append({
        "time": now,
        "time_iso": utc_iso(now),
        "type": str(event_type)[:64],
        "username": str(username or "unknown")[:128],
        "ip": str(ip)[:64],
        "auth_method": str(auth_method)[:64],
        "raw": str(raw)[:MAX_RAW_LINE],
    })
    save_json(EVENTS_FILE, events[-MAX_EVENTS:])


def load_blocks():
    data = load_json(BLOCKS_FILE, {})
    return data if isinstance(data, dict) else {}


def save_blocks(blocks):
    return save_json(BLOCKS_FILE, blocks)


def load_stats():
    data = load_json(STATS_FILE, {})
    return data if isinstance(data, dict) else {}


def update_stat(name):
    stats = load_stats()
    try:
        stats[name] = max(0, int(stats.get(name, 0))) + 1
    except (TypeError, ValueError, OverflowError):
        stats[name] = 1
    save_json(STATS_FILE, stats)


def normalize_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip().strip("[]")))
    except (ValueError, AttributeError, TypeError):
        return None


def get_local_ips():
    global LOCAL_IPS_CACHE, LOCAL_IPS_CACHE_AT
    now = time.monotonic()
    if now - LOCAL_IPS_CACHE_AT < 60:
        return set(LOCAL_IPS_CACHE)
    addresses = {"127.0.0.1", "::1"}
    result = run_command(["hostname", "-I"], timeout=3)
    if result and result.returncode == 0:
        for value in result.stdout.split():
            address = normalize_ip(value)
            if address:
                addresses.add(address)
    LOCAL_IPS_CACHE = addresses
    LOCAL_IPS_CACHE_AT = now
    return set(addresses)


def is_whitelisted(ip, config):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in config.get("whitelist", []):
        try:
            if address in ipaddress.ip_network(entry, strict=False):
                return True
        except (ValueError, TypeError):
            continue
    return False


def ufw_status():
    result = run_command(["ufw", "status"], timeout=5)
    if not result or result.returncode != 0:
        return None, result
    first_line = result.stdout.strip().splitlines()
    active = bool(first_line and re.search(r"^Status:\s+active\s*$", first_line[0], re.IGNORECASE))
    return active, result


def ufw_is_blocked(ip):
    address = normalize_ip(ip)
    if not address:
        return False
    active, result = ufw_status()
    if active is not True or not result:
        return False
    target = ipaddress.ip_address(address)
    for line in result.stdout.splitlines():
        fields = line.split()
        if not any(field.upper() in {"DENY", "REJECT"} for field in fields):
            continue
        for field in fields:
            token = field.strip("(),[]")
            if token.lower() in {"anywhere", "anywhere(v6)", "anywhere (v6)"}:
                continue
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                continue
            if target.version == network.version and target in network:
                return True
    return False


def ufw_block(ip):
    address = normalize_ip(ip)
    if not address:
        log(f"Refusing to block invalid IP: {ip}")
        return False
    active, result = ufw_status()
    if active is not True:
        state = "unavailable" if result is None else "inactive or status unknown"
        log(f"[BLOCK ERROR] UFW is {state}; refusing to report {address} as blocked")
        return False
    if ufw_is_blocked(address):
        log(f"[BLOCK EXISTS] {address}")
        return True
    result = run_command(["ufw", "insert", "1", "deny", "from", address], timeout=10)
    if result and result.returncode == 0 and ufw_is_blocked(address):
        log(f"[BLOCK] {address}")
        return True
    error = result.stderr.strip() if result else "command failed"
    if result and result.stdout.strip():
        error = f"{error} {result.stdout.strip()}".strip()
    log(f"[BLOCK ERROR] {address}: {error or 'rule could not be verified'}")
    return False


def ufw_unblock(ip):
    address = normalize_ip(ip)
    if not address:
        return False
    active, result = ufw_status()
    if active is not True:
        log(f"[UNBLOCK ERROR] UFW is inactive or unavailable; leaving record for {address}")
        return False
    if not ufw_is_blocked(address):
        return True
    result = run_command(["ufw", "delete", "deny", "from", address], timeout=10)
    if result and result.returncode == 0 and not ufw_is_blocked(address):
        log(f"[UNBLOCK] {address}")
        return True
    error = result.stderr.strip() if result else "command failed"
    log(f"[UNBLOCK ERROR] {address}: {error or 'rule still present'}")
    return False


def create_block(ip, failed_attempts, config):
    now = int(time.time())
    permanent = bool(config["permanent"])
    duration = int(config["duration"])
    expires_at = None if permanent else now + duration
    blocks = load_blocks()
    blocks[ip] = {
        "ip": ip,
        "blocked_at": now,
        "blocked_at_iso": utc_iso(now),
        "failed_attempts": int(failed_attempts),
        "permanent": permanent,
        "duration": duration,
        "expires_at": expires_at,
        "expires_at_iso": utc_iso(expires_at) if expires_at else None,
        "reason": "SSH brute-force protection",
    }
    if not save_blocks(blocks):
        log(f"[DATA ERROR] Could not save block record for {ip}")
        return False
    return True


def block_ip(ip, failed_attempts, config):
    address = normalize_ip(ip)
    if not address:
        log(f"[SAFETY] Invalid IP ignored: {ip}")
        return False
    if is_whitelisted(address, config):
        log(f"[WHITELIST] Skipping {address}")
        return False
    if address in get_local_ips():
        log(f"[SAFETY] Skipping local/server IP {address}")
        return False
    if not ufw_block(address):
        return False
    if not create_block(address, failed_attempts, config):
        log(f"[DATA ERROR] Firewall rule for {address} exists but block record failed to save")
        return False
    update_stat("blocked")
    if config["permanent"]:
        log(f"{address} blocked permanently after {failed_attempts} failed attempts")
    else:
        log(f"{address} blocked for {config['duration']} seconds")
    return True


def load_attempts():
    data = load_json(ATTEMPTS_FILE, {})
    if not isinstance(data, dict):
        data = {}
    now = time.time()
    valid = {}
    for ip, item in data.items():
        address = normalize_ip(ip)
        if not address or not isinstance(item, dict):
            continue
        try:
            count = max(0, min(int(item.get("count", 0)), 100000))
            last = float(item.get("last", 0))
        except (TypeError, ValueError, OverflowError):
            continue
        if count and 0 <= now - last <= ATTEMPT_WINDOW_SECONDS:
            valid[address] = {"count": count, "last": last}
    return valid


def save_attempts():
    return save_json(ATTEMPTS_FILE, FAILED_ATTEMPTS)


def expire_blocks():
    blocks = load_blocks()
    if not blocks:
        return
    now = int(time.time())
    changed = False
    for ip, block in list(blocks.items()):
        address = normalize_ip(ip)
        if not address or not isinstance(block, dict):
            del blocks[ip]
            changed = True
            continue
        if as_bool(block.get("permanent", False), False):
            continue
        try:
            expires_at = int(block.get("expires_at"))
        except (TypeError, ValueError, OverflowError):
            continue
        if expires_at > now:
            continue
        if ufw_unblock(address):
            del blocks[ip]
            changed = True
            update_stat("unblocked")
            log(f"[EXPIRED] Temporary block expired for {address}")
    if changed:
        save_blocks(blocks)


def cleanup_events():
    events = load_events()
    cutoff = int(time.time() - EVENT_RETENTION_DAYS * 86400)
    cleaned = []
    for event in events:
        if not isinstance(event, dict):
            continue
        try:
            timestamp = int(event.get("time", 0))
        except (TypeError, ValueError, OverflowError):
            continue
        if timestamp >= cutoff:
            cleaned.append(event)
    cleaned = cleaned[-MAX_EVENTS:]
    if len(cleaned) != len(events):
        save_json(EVENTS_FILE, cleaned)


def cleanup_attempts():
    now = time.time()
    changed = False
    for ip, data in list(FAILED_ATTEMPTS.items()):
        try:
            last = float(data.get("last", 0))
            count = int(data.get("count", 0))
        except (AttributeError, TypeError, ValueError, OverflowError):
            del FAILED_ATTEMPTS[ip]
            changed = True
            continue
        if count <= 0 or now - last > ATTEMPT_WINDOW_SECONDS or last > now + 60:
            del FAILED_ATTEMPTS[ip]
            changed = True
    if changed:
        save_attempts()


def _already_blocked(address):
    item = load_blocks().get(address)
    if not isinstance(item, dict):
        return False
    if as_bool(item.get("permanent", False), False):
        return True
    try:
        return int(item.get("expires_at", 0)) > int(time.time())
    except (TypeError, ValueError, OverflowError):
        return False


def handle_failed_login(username, ip, raw, event_type="failed"):
    address = normalize_ip(ip)
    if not address:
        return
    username = str(username or "unknown")[:128]
    config = load_protection_config()
    save_event(event_type, address, username, "", raw)
    update_stat("failed")

    if not config["enabled"] or is_whitelisted(address, config):
        return
    if address in get_local_ips():
        log(f"[SAFETY] Ignoring failed login from local/server address {address}")
        return
    if _already_blocked(address):
        return

    current = FAILED_ATTEMPTS.setdefault(address, {"count": 0, "last": 0.0})
    now = time.time()
    if now - float(current.get("last", 0)) > ATTEMPT_WINDOW_SECONDS:
        current["count"] = 0
    current["count"] = int(current.get("count", 0)) + 1
    current["last"] = now
    attempts = current["count"]
    save_attempts()

    log(f"[SSH FAILED] IP={address} user={username} attempt={attempts}/{config['attempts']}")
    if attempts < config["attempts"]:
        return
    if block_ip(address, attempts, config):
        FAILED_ATTEMPTS.pop(address, None)
        save_attempts()


def handle_success_login(username, ip, auth_method, raw):
    address = normalize_ip(ip)
    if not address:
        return
    save_event("success", address, username, auth_method, raw)
    update_stat("success")
    if address in FAILED_ATTEMPTS:
        del FAILED_ATTEMPTS[address]
        save_attempts()
        log(f"[SSH SUCCESS] Counter reset for {address}")
    else:
        log(f"[SSH SUCCESS] {address}")


def process_line(line):
    line = line.strip()
    if not line:
        return

    for auth_method, pattern in SUCCESS_PATTERNS:
        match = pattern.search(line)
        if match:
            handle_success_login(match.group(1), match.group(2), auth_method, line)
            return

    for event_type, pattern in FAILED_PATTERNS:
        match = pattern.search(line)
        if match:
            handle_failed_login(match.group(1), match.group(2), line, event_type)
            return

    for pattern in AUXILIARY_PATTERNS:
        match = pattern.search(line)
        if match:
            if pattern is AUXILIARY_PATTERNS[0]:
                username, ip = match.group(1), match.group(2)
            else:
                username, ip = "unknown", match.group(1)
            address = normalize_ip(ip)
            if address:
                save_event("auth_detail", address, username, "", line)
            return


def run_journal():
    command = ["journalctl", "-f", "-n", "0", "-u", "ssh.service", "-u", "sshd.service", "-o", "cat", "--no-pager"]
    log("Starting SSH journal monitor...")
    while True:
        process = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
            )
            if process.stdout is None:
                raise RuntimeError("Could not open journal output")
            pending = b""
            while True:
                ready, _, _ = select.select([process.stdout], [], [], 1.0)
                if ready:
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if chunk:
                        pending += chunk
                        while b"\n" in pending:
                            raw_line, pending = pending.split(b"\n", 1)
                            process_line(raw_line.decode("utf-8", errors="replace"))
                    elif process.poll() is not None:
                        break
                elif process.poll() is not None:
                    if pending:
                        process_line(pending.decode("utf-8", errors="replace"))
                    break
                now = time.monotonic()
                if now - run_journal.last_cleanup >= CLEANUP_INTERVAL:
                    expire_blocks()
                    cleanup_events()
                    cleanup_attempts()
                    load_protection_config()
                    run_journal.last_cleanup = now
        except KeyboardInterrupt:
            raise
        except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
            log(f"Journal error: {exc}")
        finally:
            if process:
                if process.stdout:
                    try:
                        process.stdout.close()
                    except OSError:
                        pass
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
        log("SSH journal stopped. Restarting in 3 seconds...")
        time.sleep(3)


run_journal.last_cleanup = 0.0


def acquire_single_instance_lock():
    ensure_directories()
    lock_file = LOCK_FILE.open("w", encoding="utf-8")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_file.close()
        raise RuntimeError("Another Brute Force Guard instance is already running")
    try:
        lock_file.write(str(os.getpid()))
        lock_file.flush()
    except OSError:
        pass
    return lock_file


def main():
    ensure_directories()
    lock_file = None
    try:
        lock_file = acquire_single_instance_lock()
        global FAILED_ATTEMPTS
        FAILED_ATTEMPTS = load_attempts()
        config = load_protection_config(force=True)
        log("========================================")
        log("ServerGuard Brute Force Guard")
        log("========================================")
        log(f"Protection: {'ON' if config['enabled'] else 'OFF'}")
        log(f"Block after: {config['attempts']} failed attempts")
        if config["permanent"]:
            log("Block type: PERMANENT")
        else:
            log(f"Block type: TEMPORARY ({config['duration']} seconds)")
        log(f"Whitelist entries: {len(config['whitelist'])}")
        if FAILED_ATTEMPTS:
            log(f"Restored counters for {len(FAILED_ATTEMPTS)} IP address(es)")
        expire_blocks()
        run_journal()
    except KeyboardInterrupt:
        log("Stopped.")
    except RuntimeError as exc:
        log(str(exc))
        sys.exit(1)
    finally:
        if lock_file:
            lock_file.close()


if __name__ == "__main__":
    main()

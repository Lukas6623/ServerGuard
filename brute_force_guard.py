
#!/usr/bin/env python3

import ipaddress
import json
import subprocess
import time

from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path("/opt/serverguard")
DATA_DIR = BASE_DIR / "data"

PROTECTION_CONFIG_FILE = DATA_DIR / "protection_config.json"
EVENTS_FILE = DATA_DIR / "ssh_events.json"
BLOCKS_FILE = DATA_DIR / "blocked_ips.json"
STATS_FILE = DATA_DIR / "stats.json"

MAX_EVENTS = 2000
EVENT_RETENTION_DAYS = 7
CLEANUP_INTERVAL = 60
CONFIG_CHECK_INTERVAL = 5
COMMAND_TIMEOUT = 15

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
LAST_CONFIG_LOAD = 0


def log(message):
    print(f"[ServerGuard] {message}", flush=True)


def ensure_directories():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def run_command(command, timeout=COMMAND_TIMEOUT):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result
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
    temporary_path = path.with_suffix(".tmp")

    try:
        path.parent.mkdir(parents=True, exist_ok=True)

        with temporary_path.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=2, ensure_ascii=False)
            file.write("\n")

        temporary_path.replace(path)

        try:
            path.chmod(0o600)
        except OSError:
            pass

        return True

    except (OSError, TypeError, ValueError) as exc:
        log(f"Cannot save {path}: {exc}")

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
        return value.strip().lower() in {
            "1", "true", "yes", "on", "enabled"
        }

    return default


def load_protection_config():
    global CACHED_CONFIG, LAST_CONFIG_LOAD

    now = time.time()

    if now - LAST_CONFIG_LOAD < CONFIG_CHECK_INTERVAL:
        return dict(CACHED_CONFIG)

    data = load_json(PROTECTION_CONFIG_FILE, dict(DEFAULT_CONFIG))

    if not isinstance(data, dict):
        data = {}

    config = dict(DEFAULT_CONFIG)
    config.update(data)

    config["enabled"] = as_bool(config.get("enabled"), True)
    config["permanent"] = as_bool(config.get("permanent"), False)

    try:
        config["attempts"] = max(
            1,
            min(int(config.get("attempts", 5)), 100),
        )
    except (TypeError, ValueError):
        config["attempts"] = DEFAULT_CONFIG["attempts"]

    try:
        config["duration"] = max(
            60,
            min(int(config.get("duration", 600)), 30 * 24 * 60 * 60),
        )
    except (TypeError, ValueError):
        config["duration"] = DEFAULT_CONFIG["duration"]

    whitelist = config.get("whitelist", [])
    clean_whitelist = []

    if isinstance(whitelist, list):
        for entry in whitelist:
            try:
                network = ipaddress.ip_network(str(entry).strip(), strict=False)
                normalized = str(network)

                if normalized not in clean_whitelist:
                    clean_whitelist.append(normalized)
            except ValueError:
                log(f"Ignoring invalid whitelist entry: {entry}")

    config["whitelist"] = clean_whitelist
    config["mode"] = "ip"

    CACHED_CONFIG = config
    LAST_CONFIG_LOAD = now

    return dict(config)


def utc_iso(timestamp=None):
    if timestamp is None:
        timestamp = time.time()

    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc,
    ).isoformat()


def load_events():
    data = load_json(EVENTS_FILE, [])
    return data if isinstance(data, list) else []


def save_event(event_type, ip, username="unknown", auth_method="", raw=""):
    events = load_events()
    now = int(time.time())

    events.append({
        "time": now,
        "time_iso": utc_iso(now),
        "type": event_type,
        "username": username,
        "ip": ip,
        "auth_method": auth_method,
        "raw": raw[:1000],
    })

    save_json(EVENTS_FILE, events[-MAX_EVENTS:])


def load_blocks():
    data = load_json(BLOCKS_FILE, {})
    return data if isinstance(data, dict) else {}


def save_blocks(blocks):
    save_json(BLOCKS_FILE, blocks)


def load_stats():
    data = load_json(STATS_FILE, {})
    return data if isinstance(data, dict) else {}


def update_stat(name):
    stats = load_stats()

    try:
        stats[name] = int(stats.get(name, 0)) + 1
    except (TypeError, ValueError):
        stats[name] = 1

    save_json(STATS_FILE, stats)


def normalize_ip(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        return None


def get_local_ips():
    addresses = {"127.0.0.1", "::1"}

    result = run_command(["hostname", "-I"], timeout=5)

    if result and result.returncode == 0:
        for value in result.stdout.split():
            address = normalize_ip(value)

            if address:
                addresses.add(address)

    return addresses


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


def ufw_is_blocked(ip):
    result = run_command(["ufw", "status"])

    if not result or result.returncode != 0:
        return False

    for line in result.stdout.splitlines():
        fields = line.split()

        if len(fields) < 2:
            continue

        if fields[0] != ip:
            continue

        if fields[1].upper() in {"DENY", "REJECT"}:
            return True

    return False


def ufw_block(ip):
    if not normalize_ip(ip):
        log(f"Refusing to block invalid IP: {ip}")
        return False

    if ufw_is_blocked(ip):
        return True

    result = run_command([
        "ufw", "insert", "1", "deny", "from", ip
    ])

    if result and result.returncode == 0:
        log(f"[BLOCK] {ip}")
        return True

    error = result.stderr.strip() if result else "command failed"
    log(f"[BLOCK ERROR] {ip}: {error}")
    return False


def ufw_unblock(ip):
    if not normalize_ip(ip):
        return False

    result = run_command([
        "ufw", "delete", "deny", "from", ip
    ])

    if result and result.returncode == 0:
        log(f"[UNBLOCK] {ip}")
        return True

    output = ""
    if result:
        output = f"{result.stdout}\n{result.stderr}".lower()

    if any(message in output for message in (
        "could not delete",
        "not found",
        "no rules found",
        "could not find",
    )):
        return True

    error = result.stderr.strip() if result else "command failed"
    log(f"[UNBLOCK ERROR] {ip}: {error}")
    return False


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

    save_blocks(blocks)


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

    create_block(address, failed_attempts, config)
    update_stat("blocked")

    if config["permanent"]:
        log(f"{address} blocked permanently after {failed_attempts} failed attempts")
    else:
        log(f"{address} blocked for {config['duration']} seconds")

    return True


def expire_blocks():
    blocks = load_blocks()

    if not blocks:
        return

    now = int(time.time())
    changed = False

    for ip, block in list(blocks.items()):
        if not isinstance(block, dict):
            del blocks[ip]
            changed = True
            continue

        if block.get("permanent", False):
            continue

        expires_at = block.get("expires_at")

        try:
            expires_at = int(expires_at)
        except (TypeError, ValueError):
            continue

        if expires_at > now:
            continue

        if ufw_unblock(ip):
            del blocks[ip]
            changed = True
            update_stat("unblocked")
            log(f"[EXPIRED] Temporary block expired for {ip}")

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
        except (TypeError, ValueError):
            continue

        if timestamp >= cutoff:
            cleaned.append(event)

    cleaned = cleaned[-MAX_EVENTS:]

    if len(cleaned) != len(events):
        save_json(EVENTS_FILE, cleaned)


def cleanup_attempts():
    now = time.time()

    for ip, data in list(FAILED_ATTEMPTS.items()):
        if not isinstance(data, dict):
            del FAILED_ATTEMPTS[ip]
            continue

        try:
            last = float(data["last"])
        except (KeyError, TypeError, ValueError):
            del FAILED_ATTEMPTS[ip]
            continue

        if now - last > 3600:
            del FAILED_ATTEMPTS[ip]


FAILED_PATTERNS = (
    (
        "failed_password",
        __import__("re").compile(
            r"Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)"
        ),
    ),
    (
        "failed_publickey",
        __import__("re").compile(
            r"Failed publickey for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)"
        ),
    ),
    (
        "invalid_user",
        __import__("re").compile(
            r"Invalid user (\S+) from ([0-9a-fA-F:.]+)"
        ),
    ),
    (
        "authentication_failure",
        __import__("re").compile(
            r"authentication failure.*rhost=([0-9a-fA-F:.]+)",
            __import__("re").IGNORECASE,
        ),
    ),
)

SUCCESS_PATTERNS = (
    (
        "password",
        __import__("re").compile(
            r"Accepted password for (\S+) from ([0-9a-fA-F:.]+)"
        ),
    ),
    (
        "publickey",
        __import__("re").compile(
            r"Accepted publickey for (\S+) from ([0-9a-fA-F:.]+)"
        ),
    ),
    (
        "keyboard-interactive",
        __import__("re").compile(
            r"Accepted keyboard-interactive/pam for (\S+) from ([0-9a-fA-F:.]+)"
        ),
    ),
)


def handle_failed_login(username, ip, raw, event_type="failed"):
    address = normalize_ip(ip)

    if not address:
        return

    username = username or "unknown"
    config = load_protection_config()

    save_event(event_type, address, username, "", raw)
    update_stat("failed")

    if not config["enabled"]:
        return

    if is_whitelisted(address, config):
        log(f"[WHITELIST] Failed SSH from {address}")
        return

    current = FAILED_ATTEMPTS.setdefault(
        address,
        {"count": 0, "last": 0},
    )

    current["count"] += 1
    current["last"] = time.time()

    attempts = current["count"]
    threshold = config["attempts"]

    log(
        f"[SSH FAILED] IP={address} "
        f"user={username} attempt={attempts}/{threshold}"
    )

    if attempts < threshold:
        return

    blocks = load_blocks()
    existing = blocks.get(address)

    if isinstance(existing, dict):
        if existing.get("permanent", False):
            return

        try:
            if int(existing.get("expires_at", 0)) > int(time.time()):
                return
        except (TypeError, ValueError):
            pass

    if block_ip(address, attempts, config):
        FAILED_ATTEMPTS.pop(address, None)


def handle_success_login(username, ip, auth_method, raw):
    address = normalize_ip(ip)

    if not address:
        return

    save_event("success", address, username, auth_method, raw)
    update_stat("success")

    if address in FAILED_ATTEMPTS:
        del FAILED_ATTEMPTS[address]
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
            handle_success_login(
                match.group(1),
                match.group(2),
                auth_method,
                line,
            )
            return

    for event_type, pattern in FAILED_PATTERNS:
        match = pattern.search(line)

        if not match:
            continue

        if event_type == "authentication_failure":
            username = "unknown"
            ip = match.group(1)
        else:
            username = match.group(1)
            ip = match.group(2)

        handle_failed_login(
            username,
            ip,
            line,
            event_type,
        )
        return


def run_journal():
    command = [
        "journalctl",
        "-f",
        "-n", "0",
        "-u", "ssh",
        "-u", "sshd",
        "-o", "cat",
    ]

    log("Starting SSH journal monitor...")

    while True:
        process = None

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            if process.stdout is None:
                raise RuntimeError("Could not open journal output")

            while True:
                line = process.stdout.readline()

                if line:
                    process_line(line)
                    continue

                if process.poll() is not None:
                    error = ""

                    if process.stderr:
                        error = process.stderr.read().strip()

                    if error:
                        log(f"journalctl: {error}")

                    break

                now = time.time()

                if now - run_journal.last_cleanup >= CLEANUP_INTERVAL:
                    expire_blocks()
                    cleanup_events()
                    cleanup_attempts()
                    run_journal.last_cleanup = now

                time.sleep(0.2)

        except KeyboardInterrupt:
            raise

        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            log(f"Journal error: {exc}")

        finally:
            if process and process.poll() is None:
                process.terminate()

                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()

        log("SSH journal stopped. Restarting in 3 seconds...")
        time.sleep(3)


run_journal.last_cleanup = 0


def main():
    ensure_directories()

    log("========================================")
    log("ServerGuard Brute Force Guard")
    log("========================================")

    config = load_protection_config()

    log(f"Protection: {'ON' if config['enabled'] else 'OFF'}")
    log(f"Block after: {config['attempts']} failed attempts")

    if config["permanent"]:
        log("Block type: PERMANENT")
    else:
        log(f"Block type: TEMPORARY ({config['duration']} seconds)")

    log(f"Whitelist entries: {len(config['whitelist'])}")

    try:
        run_journal()
    except KeyboardInterrupt:
        log("Stopped.")


if __name__ == "__main__":
    main()

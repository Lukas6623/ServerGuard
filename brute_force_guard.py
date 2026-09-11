#!/usr/bin/env python3

import json
import re
import subprocess
import time
from pathlib import Path
from datetime import datetime, timezone


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path("/opt/serverguard")
DATA_DIR = BASE_DIR / "data"

EVENTS_FILE = DATA_DIR / "ssh_events.json"
BLOCKS_FILE = DATA_DIR / "blocked_ips.json"

# IMPORTANT:
# Add your trusted/public IP here.
# These addresses will NEVER be blocked.
WHITELIST_IPS = {
    # "1.2.3.4",
}

# Number of failed attempts
LEVEL_1 = 5
LEVEL_2 = 10
LEVEL_3 = 20

# Block durations
BLOCK_1 = 10 * 60          # 10 minutes
BLOCK_2 = 20 * 60          # 20 minutes
BLOCK_3 = 2 * 60 * 60      # 2 hours

MAX_EVENTS = 10000


# ============================================================
# DIRECTORIES
# ============================================================

DATA_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# JSON HELPERS
# ============================================================

def load_json(path, default):
    try:
        if not path.exists():
            return default

        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        return data

    except Exception:
        return default


def save_json(path, data):
    temp = path.with_suffix(".tmp")

    with temp.open("w", encoding="utf-8") as f:
        json.dump(
            data,
            f,
            indent=2,
            ensure_ascii=False
        )

    temp.replace(path)


# ============================================================
# DATA
# ============================================================

events = load_json(EVENTS_FILE, [])

blocks = load_json(
    BLOCKS_FILE,
    {}
)


# ============================================================
# TIME
# ============================================================

def now():
    return int(time.time())


def iso_time(timestamp=None):
    if timestamp is None:
        timestamp = now()

    return datetime.fromtimestamp(
        timestamp,
        timezone.utc
    ).isoformat()


# ============================================================
# IP VALIDATION
# ============================================================

IP_REGEX = re.compile(
    r"^(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"[0-9a-fA-F:]+"
    r")$"
)


def valid_ip(ip):
    return bool(IP_REGEX.match(ip))


# ============================================================
# FIREWALL
# ============================================================

def ufw_block(ip):
    if ip in WHITELIST_IPS:
        print(
            f"[WHITELIST] Refusing to block {ip}",
            flush=True
        )
        return False

    try:
        result = subprocess.run(
            [
                "ufw",
                "insert",
                "1",
                "deny",
                "from",
                ip
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return result.returncode == 0

    except Exception as e:
        print(
            f"[ERROR] UFW block failed for {ip}: {e}",
            flush=True
        )

        return False


def ufw_unblock(ip):
    if ip in WHITELIST_IPS:
        return

    try:
        subprocess.run(
            [
                "ufw",
                "delete",
                "deny",
                "from",
                ip
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    except Exception:
        pass


# ============================================================
# BLOCK LEVEL
# ============================================================

def get_block_duration(failed_count):

    if failed_count >= LEVEL_3:
        return None

    if failed_count >= LEVEL_2:
        return BLOCK_3

    if failed_count >= LEVEL_1:
        return BLOCK_1

    return 0


def get_level(failed_count):

    if failed_count > LEVEL_3:
        return "permanent"

    if failed_count >= LEVEL_3:
        return "2_hours"

    if failed_count >= LEVEL_2:
        return "20_minutes"

    if failed_count >= LEVEL_1:
        return "10_minutes"

    return "none"


# ============================================================
# BLOCK IP
# ============================================================

def block_ip(ip, failed_count):

    if ip in WHITELIST_IPS:
        return

    duration = get_block_duration(failed_count)
    level = get_level(failed_count)

    current = blocks.get(ip)

    # Already permanently blocked
    if current and current.get("permanent"):
        return

    # Remove old temporary block from firewall
    if current:
        ufw_unblock(ip)

    # Permanent block
    if duration is None:

        if ufw_block(ip):

            blocks[ip] = {
                "ip": ip,
                "level": level,
                "failed_attempts": failed_count,
                "blocked_at": now(),
                "blocked_at_iso": iso_time(),
                "expires_at": None,
                "permanent": True
            }

            save_json(
                BLOCKS_FILE,
                blocks
            )

            print(
                f"[BLOCK] {ip} permanently blocked "
                f"after {failed_count} failed attempts",
                flush=True
            )

        return

    # Temporary block
    expires = now() + duration

    if ufw_block(ip):

        blocks[ip] = {
            "ip": ip,
            "level": level,
            "failed_attempts": failed_count,
            "blocked_at": now(),
            "blocked_at_iso": iso_time(),
            "expires_at": expires,
            "expires_at_iso": iso_time(expires),
            "permanent": False
        }

        save_json(
            BLOCKS_FILE,
            blocks
        )

        print(
            f"[BLOCK] {ip} blocked for "
            f"{duration // 60} minutes "
            f"(attempts: {failed_count})",
            flush=True
        )


# ============================================================
# EXPIRE BLOCKS
# ============================================================

def cleanup_expired_blocks():

    changed = False

    for ip in list(blocks.keys()):

        if ip in WHITELIST_IPS:
            ufw_unblock(ip)
            del blocks[ip]
            changed = True
            continue

        block = blocks[ip]

        if block.get("permanent"):
            continue

        expires = block.get("expires_at")

        if expires is None:
            continue

        if now() >= expires:

            print(
                f"[UNBLOCK] Temporary block expired: {ip}",
                flush=True
            )

            ufw_unblock(ip)

            del blocks[ip]

            changed = True

    if changed:
        save_json(
            BLOCKS_FILE,
            blocks
        )


# ============================================================
# EVENT STORAGE
# ============================================================

def save_event(
    event_type,
    username,
    ip,
    message
):

    event = {
        "time": now(),
        "time_iso": iso_time(),
        "type": event_type,
        "username": username,
        "ip": ip,
        "message": message
    }

    events.append(event)

    if len(events) > MAX_EVENTS:
        del events[:-MAX_EVENTS]

    save_json(
        EVENTS_FILE,
        events
    )


# ============================================================
# FAILED ATTEMPTS
# ============================================================

def get_failed_count(ip):

    count = 0

    for event in events:

        if event.get("type") != "failed":
            continue

        if event.get("ip") != ip:
            continue

        count += 1

    return count


# ============================================================
# SUCCESS
# ============================================================

def handle_success(
    username,
    ip,
    message
):

    save_event(
        "success",
        username,
        ip,
        message
    )

    print(
        f"[SSH SUCCESS] "
        f"user={username} "
        f"ip={ip}",
        flush=True
    )


# ============================================================
# FAILED
# ============================================================

def handle_failed(
    username,
    ip,
    message
):

    save_event(
        "failed",
        username,
        ip,
        message
    )

    failed_count = get_failed_count(ip)

    print(
        f"[SSH FAILED] "
        f"user={username} "
        f"ip={ip} "
        f"attempts={failed_count}",
        flush=True
    )

    if ip in WHITELIST_IPS:

        print(
            f"[WHITELIST] {ip} will never be blocked",
            flush=True
        )

        return

    if failed_count >= LEVEL_1:

        block_ip(
            ip,
            failed_count
        )


# ============================================================
# SSH LOG PARSER
# ============================================================

FAILED_REGEX = re.compile(
    r"Failed \S+ for (?:invalid user )?(\S+) "
    r"from ([0-9a-fA-F:.]+)"
)

ACCEPTED_REGEX = re.compile(
    r"Accepted \S+ for (\S+) "
    r"from ([0-9a-fA-F:.]+)"
)


def process_log_line(line):

    # --------------------------------------------------------
    # SUCCESSFUL LOGIN
    # --------------------------------------------------------

    match = ACCEPTED_REGEX.search(line)

    if match:

        username = match.group(1)
        ip = match.group(2)

        if valid_ip(ip):

            handle_success(
                username,
                ip,
                line.strip()
            )

        return


    # --------------------------------------------------------
    # FAILED LOGIN
    # --------------------------------------------------------

    match = FAILED_REGEX.search(line)

    if match:

        username = match.group(1)
        ip = match.group(2)

        if valid_ip(ip):

            handle_failed(
                username,
                ip,
                line.strip()
            )


# ============================================================
# JOURNALCTL
# ============================================================

def start_journal():

    commands = [
        [
            "journalctl",
            "-f",
            "-n",
            "0",
            "-u",
            "ssh"
        ],
        [
            "journalctl",
            "-f",
            "-n",
            "0",
            "-u",
            "sshd"
        ],
        [
            "journalctl",
            "-f",
            "-n",
            "0",
            "-t",
            "sshd"
        ]
    ]

    # Ubuntu normally uses ssh.service
    command = commands[0]

    return subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )


# ============================================================
# MAIN LOOP
# ============================================================

def main():

    print(
        "==================================================",
        flush=True
    )

    print(
        "ServerGuard SSH Protection",
        flush=True
    )

    print(
        "Protection mode: ACTIVE",
        flush=True
    )

    print(
        "Password logging: DISABLED",
        flush=True
    )

    print(
        "==================================================",
        flush=True
    )

    journal = start_journal()

    last_cleanup = 0

    try:

        while True:

            # ------------------------------------------------
            # Cleanup expired blocks every 10 seconds
            # ------------------------------------------------

            if now() - last_cleanup >= 10:

                cleanup_expired_blocks()

                last_cleanup = now()

            # ------------------------------------------------
            # Read SSH log
            # ------------------------------------------------

            line = journal.stdout.readline()

            if line:

                process_log_line(
                    line
                )

            else:

                time.sleep(0.2)

    except KeyboardInterrupt:

        print(
            "\n[STOP] ServerGuard protection stopped.",
            flush=True
        )

    finally:

        try:
            journal.terminate()
        except Exception:
            pass


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()

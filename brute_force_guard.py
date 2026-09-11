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

# ------------------------------------------------------------
# Event storage limits
# ------------------------------------------------------------

# Maximum number of events stored in ssh_events.json
MAX_EVENTS = 2000

# Events older than this many days are automatically removed
EVENT_RETENTION_DAYS = 7

# Cleanup interval
CLEANUP_INTERVAL = 60


# ============================================================
# WHITELIST
# ============================================================

# IMPORTANT:
# Add your trusted/public IP here.
# These addresses will NEVER be blocked.

WHITELIST_IPS = {
    # "1",
}


# ============================================================
# BRUTE FORCE LEVELS
# ============================================================

LEVEL_1 = 5
LEVEL_2 = 10
LEVEL_3 = 20


# ============================================================
# BLOCK DURATIONS
# ============================================================

BLOCK_1 = 10 * 60          # 10 minutes
BLOCK_2 = 20 * 60          # 20 minutes
BLOCK_3 = 2 * 60 * 60      # 2 hours


# ============================================================
# DIRECTORIES
# ============================================================

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# JSON HELPERS
# ============================================================

def load_json(path, default):

    try:

        if not path.exists():
            return default

        with path.open(
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(f)

        return data

    except Exception as e:

        print(
            f"[ERROR] Cannot load {path}: {e}",
            flush=True
        )

        return default


def save_json(path, data):

    temp = path.with_suffix(".tmp")

    try:

        with temp.open(
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                data,
                f,
                indent=2,
                ensure_ascii=False
            )

            f.write("\n")

        temp.replace(path)

    except Exception as e:

        print(
            f"[ERROR] Cannot save {path}: {e}",
            flush=True
        )

        try:

            if temp.exists():
                temp.unlink()

        except Exception:
            pass


# ============================================================
# DATA
# ============================================================

events = load_json(
    EVENTS_FILE,
    []
)

blocks = load_json(
    BLOCKS_FILE,
    {}
)


# Make sure loaded data has correct types

if not isinstance(events, list):
    events = []


if not isinstance(blocks, dict):
    blocks = {}


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
# EVENT CLEANUP
# ============================================================

def cleanup_old_events():

    global events

    if not events:
        return False

    current_time = now()

    cutoff = (
        current_time
        - EVENT_RETENTION_DAYS * 24 * 60 * 60
    )

    original_count = len(events)

    # --------------------------------------------------------
    # Remove events older than retention period
    # --------------------------------------------------------

    cleaned_events = []

    for event in events:

        event_time = event.get(
            "time"
        )

        if not isinstance(
            event_time,
            (int, float)
        ):
            continue

        if event_time >= cutoff:

            cleaned_events.append(
                event
            )

    events = cleaned_events

    # --------------------------------------------------------
    # Limit maximum number of events
    # --------------------------------------------------------

    if len(events) > MAX_EVENTS:

        events = events[
            -MAX_EVENTS:
        ]

    changed = (
        len(events) != original_count
    )

    if changed:

        save_json(
            EVENTS_FILE,
            events
        )

        print(
            f"[CLEANUP] SSH events: "
            f"{original_count} -> {len(events)}",
            flush=True
        )

    return changed


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

    if not ip:
        return False

    if len(ip) > 45:
        return False

    return bool(
        IP_REGEX.match(ip)
    )


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
            f"[ERROR] UFW block failed "
            f"for {ip}: {e}",
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

def get_block_duration(
    failed_count
):

    # 21+ = permanent

    if failed_count > LEVEL_3:
        return None

    # 20 = 2 hours

    if failed_count >= LEVEL_3:
        return BLOCK_3

    # 10 = 20 minutes

    if failed_count >= LEVEL_2:
        return BLOCK_2

    # 5 = 10 minutes

    if failed_count >= LEVEL_1:
        return BLOCK_1

    return 0


def get_level(
    failed_count
):

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

def block_ip(
    ip,
    failed_count
):

    if ip in WHITELIST_IPS:
        return

    duration = get_block_duration(
        failed_count
    )

    level = get_level(
        failed_count
    )

    current = blocks.get(
        ip
    )

    # --------------------------------------------------------
    # Already permanently blocked
    # --------------------------------------------------------

    if current and current.get(
        "permanent"
    ):

        return

    # --------------------------------------------------------
    # Already temporarily blocked
    #
    # Do not repeatedly recreate the same UFW rule.
    # --------------------------------------------------------

    if current:

        expires = current.get(
            "expires_at"
        )

        if (
            not current.get("permanent")
            and expires is not None
            and now() < expires
        ):

            return

        # Old temporary block
        ufw_unblock(ip)

    # --------------------------------------------------------
    # Permanent block
    # --------------------------------------------------------

    if duration is None:

        if ufw_block(ip):

            blocks[ip] = {
                "ip": ip,
                "level": level,
                "failed_attempts": failed_count,
                "blocked_at": now(),
                "blocked_at_iso": iso_time(),
                "expires_at": None,
                "expires_at_iso": None,
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

    # --------------------------------------------------------
    # Temporary block
    # --------------------------------------------------------

    blocked_at = now()

    expires = (
        blocked_at
        + duration
    )

    if ufw_block(ip):

        blocks[ip] = {
            "ip": ip,
            "level": level,
            "failed_attempts": failed_count,
            "blocked_at": blocked_at,
            "blocked_at_iso": iso_time(
                blocked_at
            ),
            "expires_at": expires,
            "expires_at_iso": iso_time(
                expires
            ),
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

    for ip in list(
        blocks.keys()
    ):

        # ----------------------------------------------------
        # Whitelist protection
        # ----------------------------------------------------

        if ip in WHITELIST_IPS:

            ufw_unblock(ip)

            del blocks[ip]

            changed = True

            print(
                f"[WHITELIST] Removed block "
                f"for {ip}",
                flush=True
            )

            continue

        block = blocks[ip]

        # ----------------------------------------------------
        # Permanent blocks stay forever
        # ----------------------------------------------------

        if block.get(
            "permanent"
        ):

            continue

        expires = block.get(
            "expires_at"
        )

        if expires is None:
            continue

        # ----------------------------------------------------
        # Temporary block expired
        # ----------------------------------------------------

        if now() >= expires:

            print(
                f"[UNBLOCK] Temporary block expired: "
                f"{ip}",
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
# GENERAL CLEANUP
# ============================================================

def cleanup():

    cleanup_old_events()

    cleanup_expired_blocks()


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

    events.append(
        event
    )

    # --------------------------------------------------------
    # Keep only the newest events
    # --------------------------------------------------------

    if len(events) > MAX_EVENTS:

        del events[
            :-MAX_EVENTS
        ]

    save_json(
        EVENTS_FILE,
        events
    )


# ============================================================
# FAILED ATTEMPTS
# ============================================================

def get_failed_count(ip):

    count = 0

    cutoff = (
        now()
        - EVENT_RETENTION_DAYS * 24 * 60 * 60
    )

    for event in events:

        if event.get(
            "type"
        ) != "failed":

            continue

        if event.get(
            "ip"
        ) != ip:

            continue

        event_time = event.get(
            "time"
        )

        if not isinstance(
            event_time,
            (int, float)
        ):

            continue

        if event_time < cutoff:
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

    failed_count = get_failed_count(
        ip
    )

    print(
        f"[SSH FAILED] "
        f"user={username} "
        f"ip={ip} "
        f"attempts={failed_count}",
        flush=True
    )

    # --------------------------------------------------------
    # Whitelist
    # --------------------------------------------------------

    if ip in WHITELIST_IPS:

        print(
            f"[WHITELIST] {ip} "
            f"will never be blocked",
            flush=True
        )

        return

    # --------------------------------------------------------
    # Block after threshold
    # --------------------------------------------------------

    if failed_count >= LEVEL_1:

        block_ip(
            ip,
            failed_count
        )


# ============================================================
# SSH LOG PARSER
# ============================================================

FAILED_REGEX = re.compile(
    r"Failed \S+ for "
    r"(?:invalid user )?"
    r"(\S+) "
    r"from "
    r"([0-9a-fA-F:.]+)"
)


ACCEPTED_REGEX = re.compile(
    r"Accepted \S+ for "
    r"(\S+) "
    r"from "
    r"([0-9a-fA-F:.]+)"
)


def process_log_line(line):

    # --------------------------------------------------------
    # SUCCESSFUL LOGIN
    # --------------------------------------------------------

    match = ACCEPTED_REGEX.search(
        line
    )

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

    match = FAILED_REGEX.search(
        line
    )

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
# STORAGE INFORMATION
# ============================================================

def print_storage_info():

    print(
        f"[DATA] Events: {EVENTS_FILE}",
        flush=True
    )

    print(
        f"[DATA] Blocks: {BLOCKS_FILE}",
        flush=True
    )

    print(
        f"[DATA] Event retention: "
        f"{EVENT_RETENTION_DAYS} days",
        flush=True
    )

    print(
        f"[DATA] Maximum events: "
        f"{MAX_EVENTS}",
        flush=True
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

    print_storage_info()

    print(
        f"[DATA] Loaded events: "
        f"{len(events)}",
        flush=True
    )

    print(
        f"[DATA] Loaded blocks: "
        f"{len(blocks)}",
        flush=True
    )

    # --------------------------------------------------------
    # Initial cleanup
    # --------------------------------------------------------

    cleanup()

    # --------------------------------------------------------
    # Start SSH journal
    # --------------------------------------------------------

    journal = start_journal()

    last_cleanup = 0

    try:

        while True:

            current_time = now()

            # ------------------------------------------------
            # Cleanup every minute
            # ------------------------------------------------

            if (
                current_time
                - last_cleanup
                >= CLEANUP_INTERVAL
            ):

                cleanup()

                last_cleanup = current_time

            # ------------------------------------------------
            # Read SSH log
            # ------------------------------------------------

            line = journal.stdout.readline()

            if line:

                process_log_line(
                    line
                )

            else:

                time.sleep(
                    0.2
                )

    except KeyboardInterrupt:

        print(
            "\n[STOP] ServerGuard protection stopped.",
            flush=True
        )

    except Exception as e:

        print(
            f"[ERROR] Main loop: {e}",
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

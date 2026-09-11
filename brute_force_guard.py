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
STATS_FILE = DATA_DIR / "ip_stats.json"


# ============================================================
# EVENT STORAGE LIMITS
# ============================================================

# Maximum number of events stored in ssh_events.json
MAX_EVENTS = 2000

# Events older than this many days are automatically removed
EVENT_RETENTION_DAYS = 7

# Cleanup interval
CLEANUP_INTERVAL = 60


# ============================================================
# IP STATISTICS LIMITS
# ============================================================

# IP statistics are removed if the IP has no activity
# for this many days.
#
# This prevents ip_stats.json from growing forever.
#
# IMPORTANT:
# Active/permanently blocked IPs are NOT removed.
#
STATS_RETENTION_DAYS = 30


# ============================================================
# WHITELIST
# ============================================================

# IMPORTANT:
# Add your trusted/public IP here.
# These addresses will NEVER be blocked.

WHITELIST_IPS = {
    # "1.1",
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

ip_stats = load_json(
    STATS_FILE,
    {}
)


# ============================================================
# DATA VALIDATION
# ============================================================

if not isinstance(events, list):
    events = []


if not isinstance(blocks, dict):
    blocks = {}


if not isinstance(ip_stats, dict):
    ip_stats = {}


# ============================================================
# TIME
# ============================================================

def now():

    return int(
        time.time()
    )


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

    if not ip:
        return False

    if len(ip) > 45:
        return False

    return bool(
        IP_REGEX.match(ip)
    )


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

    cleaned_events = []

    for event in events:

        if not isinstance(
            event,
            dict
        ):
            continue

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
    # Maximum event limit
    # --------------------------------------------------------

    if len(events) > MAX_EVENTS:

        events = events[
            -MAX_EVENTS:
        ]

    changed = (
        len(events)
        != original_count
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
# IP STATISTICS
# ============================================================

def create_empty_stats():

    return {
        "failed_attempts": 0,
        "successful_logins": 0,
        "first_seen": now(),
        "last_seen": now(),
        "last_failed": None,
        "last_success": None,
        "users": []
    }


def normalize_stats():

    global ip_stats

    changed = False

    for ip in list(
        ip_stats.keys()
    ):

        stats = ip_stats[ip]

        if not isinstance(
            stats,
            dict
        ):

            ip_stats[ip] = create_empty_stats()

            changed = True

            continue

        if "failed_attempts" not in stats:

            stats["failed_attempts"] = 0
            changed = True

        if "successful_logins" not in stats:

            stats["successful_logins"] = 0
            changed = True

        if "first_seen" not in stats:

            stats["first_seen"] = now()
            changed = True

        if "last_seen" not in stats:

            stats["last_seen"] = now()
            changed = True

        if "last_failed" not in stats:

            stats["last_failed"] = None
            changed = True

        if "last_success" not in stats:

            stats["last_success"] = None
            changed = True

        if "users" not in stats:

            stats["users"] = []
            changed = True

        if not isinstance(
            stats["users"],
            list
        ):

            stats["users"] = []
            changed = True

    if changed:

        save_json(
            STATS_FILE,
            ip_stats
        )


def rebuild_stats_from_events():

    """
    Creates ip_stats.json from existing ssh_events.json
    if statistics do not exist yet.

    This runs only when ip_stats.json is missing/empty.
    """

    global ip_stats

    if ip_stats:
        return

    if not events:
        return

    print(
        "[STATS] Building IP statistics "
        "from existing SSH events...",
        flush=True
    )

    new_stats = {}

    for event in events:

        if not isinstance(
            event,
            dict
        ):
            continue

        ip = event.get(
            "ip"
        )

        if not valid_ip(ip):
            continue

        event_type = event.get(
            "type"
        )

        username = event.get(
            "username"
        )

        event_time = event.get(
            "time"
        )

        if not isinstance(
            event_time,
            (int, float)
        ):
            event_time = now()

        if ip not in new_stats:

            new_stats[ip] = {
                "failed_attempts": 0,
                "successful_logins": 0,
                "first_seen": event_time,
                "last_seen": event_time,
                "last_failed": None,
                "last_success": None,
                "users": []
            }

        stats = new_stats[ip]

        # ----------------------------------------------------
        # First/last activity
        # ----------------------------------------------------

        if event_time < stats["first_seen"]:

            stats["first_seen"] = event_time

        if event_time > stats["last_seen"]:

            stats["last_seen"] = event_time

        # ----------------------------------------------------
        # Username
        # ----------------------------------------------------

        if (
            username
            and isinstance(username, str)
            and username not in stats["users"]
        ):

            stats["users"].append(
                username
            )

        # ----------------------------------------------------
        # Failed
        # ----------------------------------------------------

        if event_type == "failed":

            stats["failed_attempts"] += 1

            if (
                stats["last_failed"] is None
                or event_time > stats["last_failed"]
            ):

                stats["last_failed"] = event_time

        # ----------------------------------------------------
        # Successful
        # ----------------------------------------------------

        elif event_type == "success":

            stats["successful_logins"] += 1

            if (
                stats["last_success"] is None
                or event_time > stats["last_success"]
            ):

                stats["last_success"] = event_time

    ip_stats = new_stats

    save_json(
        STATS_FILE,
        ip_stats
    )

    print(
        f"[STATS] Created statistics "
        f"for {len(ip_stats)} IPs",
        flush=True
    )


def cleanup_old_stats():

    global ip_stats

    if not ip_stats:
        return False

    current_time = now()

    cutoff = (
        current_time
        - STATS_RETENTION_DAYS * 24 * 60 * 60
    )

    changed = False

    removed = 0

    for ip in list(
        ip_stats.keys()
    ):

        stats = ip_stats.get(
            ip
        )

        if not isinstance(
            stats,
            dict
        ):

            del ip_stats[ip]

            changed = True
            removed += 1

            continue

        last_seen = stats.get(
            "last_seen"
        )

        if not isinstance(
            last_seen,
            (int, float)
        ):

            last_seen = current_time

        # ----------------------------------------------------
        # Never remove currently blocked IPs
        # ----------------------------------------------------

        if ip in blocks:

            continue

        # ----------------------------------------------------
        # Never remove whitelisted IPs
        # ----------------------------------------------------

        if ip in WHITELIST_IPS:

            continue

        # ----------------------------------------------------
        # Remove inactive IP statistics
        # ----------------------------------------------------

        if last_seen < cutoff:

            del ip_stats[ip]

            changed = True
            removed += 1

    if changed:

        save_json(
            STATS_FILE,
            ip_stats
        )

        print(
            f"[CLEANUP] IP statistics removed: "
            f"{removed}",
            flush=True
        )

    return changed


def get_failed_count(ip):

    stats = ip_stats.get(
        ip
    )

    if not isinstance(
        stats,
        dict
    ):

        return 0

    failed_attempts = stats.get(
        "failed_attempts",
        0
    )

    if not isinstance(
        failed_attempts,
        int
    ):

        return 0

    return failed_attempts


def update_ip_stats(
    username,
    ip,
    event_type
):

    global ip_stats

    if ip not in ip_stats:

        ip_stats[ip] = {
            "failed_attempts": 0,
            "successful_logins": 0,
            "first_seen": now(),
            "last_seen": now(),
            "last_failed": None,
            "last_success": None,
            "users": []
        }

    stats = ip_stats[ip]

    current_time = now()

    stats["last_seen"] = current_time

    # --------------------------------------------------------
    # Store username
    # --------------------------------------------------------

    if (
        username
        and isinstance(username, str)
        and username not in stats["users"]
    ):

        stats["users"].append(
            username
        )

        # Avoid endless growth from malicious usernames.
        #
        # Keep only the latest 20 different usernames.
        #
        if len(stats["users"]) > 20:

            stats["users"] = stats["users"][-20:]

    # --------------------------------------------------------
    # Failed login
    # --------------------------------------------------------

    if event_type == "failed":

        stats["failed_attempts"] = (
            stats.get(
                "failed_attempts",
                0
            )
            + 1
        )

        stats["last_failed"] = current_time

    # --------------------------------------------------------
    # Successful login
    # --------------------------------------------------------

    elif event_type == "success":

        stats["successful_logins"] = (
            stats.get(
                "successful_logins",
                0
            )
            + 1
        )

        stats["last_success"] = current_time

    save_json(
        STATS_FILE,
        ip_stats
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

    # --------------------------------------------------------
    # 21+ = permanent
    # --------------------------------------------------------

    if failed_count > LEVEL_3:
        return None

    # --------------------------------------------------------
    # 20 = 2 hours
    # --------------------------------------------------------

    if failed_count >= LEVEL_3:
        return BLOCK_3

    # --------------------------------------------------------
    # 10 = 20 minutes
    # --------------------------------------------------------

    if failed_count >= LEVEL_2:
        return BLOCK_2

    # --------------------------------------------------------
    # 5 = 10 minutes
    # --------------------------------------------------------

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
    # Do NOT recreate the same UFW rule.
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

        # ----------------------------------------------------
        # Old temporary block
        # ----------------------------------------------------

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

        if duration >= 60:

            duration_text = (
                f"{duration // 60} minutes"
            )

        else:

            duration_text = (
                f"{duration} seconds"
            )

        print(
            f"[BLOCK] {ip} blocked for "
            f"{duration_text} "
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

    cleanup_old_stats()


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
    # Keep only newest events
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
# SUCCESS
# ============================================================

def handle_success(
    username,
    ip,
    message
):

    # --------------------------------------------------------
    # Update fast IP statistics
    # --------------------------------------------------------

    update_ip_stats(
        username,
        ip,
        "success"
    )

    # --------------------------------------------------------
    # Save event history
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Update IP statistics FIRST
    #
    # This replaces the old expensive full events scan.
    # --------------------------------------------------------

    update_ip_stats(
        username,
        ip,
        "failed"
    )

    # --------------------------------------------------------
    # Save event history
    # --------------------------------------------------------

    save_event(
        "failed",
        username,
        ip,
        message
    )

    # --------------------------------------------------------
    # Get counter directly from ip_stats.json
    # --------------------------------------------------------

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
        f"[DATA] IP statistics: {STATS_FILE}",
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

    print(
        f"[DATA] IP statistics retention: "
        f"{STATS_RETENTION_DAYS} days",
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

    print(
        f"[DATA] Loaded IP statistics: "
        f"{len(ip_stats)}",
        flush=True
    )

    # --------------------------------------------------------
    # Build statistics from existing events if necessary
    # --------------------------------------------------------

    rebuild_stats_from_events()

    # --------------------------------------------------------
    # Normalize loaded statistics
    # --------------------------------------------------------

    normalize_stats()

    # --------------------------------------------------------
    # Initial cleanup
    # --------------------------------------------------------

    cleanup()

    # --------------------------------------------------------
    # Start SSH journal
    # --------------------------------------------------------

    journal = start_journal()

    last_cleanup = now()

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

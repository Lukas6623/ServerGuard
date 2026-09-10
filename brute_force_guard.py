#!/usr/bin/env python3

import subprocess
import re
import json
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta


# ============================================================
# SERVERGUARD - REALTIME BRUTE FORCE GUARD
# ============================================================

VERSION = "2.2.0"


# ============================================================
# CONFIGURATION
# ============================================================

MAX_ATTEMPTS = 10
WINDOW_SECONDS = 10 * 60
CHECK_INTERVAL = 2

# ------------------------------------------------------------
# SAFETY
# ------------------------------------------------------------
# True  = detect only
# False = real UFW blocking
DRY_RUN = True

# Never block these IP addresses
WHITELIST = {
    "127.0.0.1",
    "::1",
}


# ============================================================
# STORAGE LIMITS
# ============================================================

DATA_DIR = "data"

BLOCKED_FILE = os.path.join(
    DATA_DIR,
    "blocked_ips.json"
)

EVENTS_FILE = os.path.join(
    DATA_DIR,
    "events.json"
)

# Maximum number of important events saved to disk.
MAX_SAVED_EVENTS = 200


# ============================================================
# MEMORY
# ============================================================

# IP -> list of recent SSH events
recent_events = defaultdict(list)

# IPs that were REALLY blocked
blocked_ips = set()

# Used to prevent the same event from being processed twice
recent_event_keys = set()


# ============================================================
# COLORS
# ============================================================

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
GRAY = "\033[90m"
RESET = "\033[0m"


# ============================================================
# DIRECTORY
# ============================================================

def ensure_data_directory():
    os.makedirs(DATA_DIR, exist_ok=True)


# ============================================================
# BLOCKED IP STORAGE
# ============================================================

def load_blocked_ips():

    global blocked_ips

    ensure_data_directory()

    if not os.path.exists(BLOCKED_FILE):
        blocked_ips = set()
        return

    try:

        with open(
            BLOCKED_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if isinstance(data, list):
            blocked_ips = set(data)
        else:
            blocked_ips = set()

    except Exception as error:

        print(
            f"{YELLOW}[WARNING] "
            f"Could not read {BLOCKED_FILE}: "
            f"{error}{RESET}"
        )

        blocked_ips = set()


def save_blocked_ips():

    ensure_data_directory()

    temporary_file = BLOCKED_FILE + ".tmp"

    try:

        with open(
            temporary_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                sorted(blocked_ips),
                file,
                indent=2
            )

        os.replace(
            temporary_file,
            BLOCKED_FILE
        )

    except Exception as error:

        print(
            f"{RED}[ERROR] "
            f"Could not save blocked IPs: "
            f"{error}{RESET}"
        )

        if os.path.exists(temporary_file):
            os.remove(temporary_file)


# ============================================================
# EVENT LOG
# ============================================================

def load_events():

    ensure_data_directory()

    if not os.path.exists(EVENTS_FILE):
        return []

    try:

        with open(
            EVENTS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if isinstance(data, list):
            return data

    except Exception:
        pass

    return []


def save_event(
    ip,
    attempts,
    users,
    event_types,
    action,
    risk
):
    """
    Save ONLY important events.

    This function is never called for every SSH attempt.
    """

    events = load_events()

    event = {
        "time": datetime.now().isoformat(
            timespec="seconds"
        ),
        "ip": ip,
        "attempts": attempts,
        "users": users,
        "types": event_types,
        "action": action,
        "risk": risk
    }

    events.append(event)

    # Keep only the newest events.
    if len(events) > MAX_SAVED_EVENTS:
        events = events[-MAX_SAVED_EVENTS:]

    temporary_file = EVENTS_FILE + ".tmp"

    try:

        with open(
            temporary_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                events,
                file,
                indent=2
            )

        os.replace(
            temporary_file,
            EVENTS_FILE
        )

    except Exception as error:

        print(
            f"{YELLOW}[WARNING] "
            f"Could not save security event: "
            f"{error}{RESET}"
        )

        if os.path.exists(temporary_file):
            os.remove(temporary_file)


# ============================================================
# UFW
# ============================================================

def check_ufw():

    try:

        result = subprocess.run(
            [
                "ufw",
                "status"
            ],
            capture_output=True,
            text=True
        )

        output = result.stdout.lower()

        return "status: active" in output

    except FileNotFoundError:

        return False

    except Exception:

        return False


def block_ip(ip):

    if ip in WHITELIST:

        print(
            f"{YELLOW}[WHITELIST] "
            f"Skipping {ip}{RESET}"
        )

        return False

    if ip in blocked_ips:

        print(
            f"{CYAN}[ALREADY BLOCKED] "
            f"{ip}{RESET}"
        )

        return False

    command = [
        "ufw",
        "insert",
        "1",
        "deny",
        "from",
        ip
    ]

    # ========================================================
    # DRY RUN
    # ========================================================

    if DRY_RUN:

        print()
        print(
            f"{YELLOW}[DRY-RUN] "
            f"Would BLOCK: {ip}{RESET}"
        )

        print(
            f"{YELLOW}[DRY-RUN] "
            f"ufw insert 1 deny from {ip}{RESET}"
        )

        # VERY IMPORTANT:
        #
        # We DO NOT:
        #   - add IP to blocked_ips
        #   - save blocked_ips.json
        #
        # because this is only simulation.

        return False

    # ========================================================
    # REAL PROTECTION
    # ========================================================

    print()
    print(
        f"{RED}[BLOCKING] {ip}{RESET}"
    )

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

    except FileNotFoundError:

        print(
            f"{RED}[ERROR] "
            f"UFW is not installed.{RESET}"
        )

        return False

    except Exception as error:

        print(
            f"{RED}[ERROR] "
            f"UFW execution failed: "
            f"{error}{RESET}"
        )

        return False

    # ========================================================
    # SUCCESS
    # ========================================================

    if result.returncode == 0:

        blocked_ips.add(ip)

        save_blocked_ips()

        print(
            f"{GREEN}[BLOCKED] "
            f"{ip}{RESET}"
        )

        return True

    # ========================================================
    # FAILURE
    # ========================================================

    print(
        f"{RED}[ERROR] "
        f"Failed to block {ip}{RESET}"
    )

    if result.stderr.strip():

        print(
            f"{RED}{result.stderr.strip()}{RESET}"
        )

    return False


# ============================================================
# SSH JOURNAL
# ============================================================

def get_ssh_logs():

    commands = [

        [
            "journalctl",
            "-u",
            "ssh",
            "--no-pager",
            "--since",
            "10 seconds ago",
            "-o",
            "short-iso"
        ],

        [
            "journalctl",
            "-u",
            "sshd",
            "--no-pager",
            "--since",
            "10 seconds ago",
            "-o",
            "short-iso"
        ]

    ]

    for command in commands:

        try:

            result = subprocess.run(
                command,
                capture_output=True,
                text=True
            )

            if (
                result.returncode == 0
                and result.stdout.strip()
            ):

                return result.stdout.splitlines()

        except Exception:

            continue

    return []


# ============================================================
# SSH EVENT PARSER
# ============================================================

def parse_ssh_event(line):

    # --------------------------------------------------------
    # Failed password for invalid user
    # --------------------------------------------------------

    match = re.search(
        r"Failed password for invalid user "
        r"(\S+) from "
        r"(\d+\.\d+\.\d+\.\d+)",
        line
    )

    if match:

        return {
            "ip": match.group(2),
            "username": match.group(1),
            "type": "failed_password"
        }

    # --------------------------------------------------------
    # Failed password
    # --------------------------------------------------------

    match = re.search(
        r"Failed password for "
        r"(\S+) from "
        r"(\d+\.\d+\.\d+\.\d+)",
        line
    )

    if match:

        return {
            "ip": match.group(2),
            "username": match.group(1),
            "type": "failed_password"
        }

    # --------------------------------------------------------
    # Invalid user
    # --------------------------------------------------------

    match = re.search(
        r"Invalid user "
        r"(\S+) from "
        r"(\d+\.\d+\.\d+\.\d+)",
        line
    )

    if match:

        return {
            "ip": match.group(2),
            "username": match.group(1),
            "type": "invalid_user"
        }

    # --------------------------------------------------------
    # Failed public key
    # --------------------------------------------------------

    match = re.search(
        r"Failed publickey for "
        r"(\S+) from "
        r"(\d+\.\d+\.\d+\.\d+)",
        line
    )

    if match:

        return {
            "ip": match.group(2),
            "username": match.group(1),
            "type": "failed_publickey"
        }

    # --------------------------------------------------------
    # Ignore generic PAM authentication failure
    # --------------------------------------------------------

    if "authentication failure" in line:

        return None

    return None


# ============================================================
# EVENT DEDUPLICATION
# ============================================================

def make_event_key(
    ip,
    username,
    event_type
):
    """
    Creates a short in-memory key.

    No data is written to disk.
    """

    return (
        ip,
        username,
        event_type
    )


# ============================================================
# CLEAN OLD EVENTS
# ============================================================

def cleanup_events():

    cutoff = (
        datetime.now()
        - timedelta(
            seconds=WINDOW_SECONDS
        )
    )

    for ip in list(recent_events.keys()):

        recent_events[ip] = [
            event
            for event in recent_events[ip]
            if event["time"] >= cutoff
        ]

        if not recent_events[ip]:

            del recent_events[ip]

    # --------------------------------------------------------
    # Keep deduplication memory small.
    # --------------------------------------------------------

    if len(recent_event_keys) > 5000:

        recent_event_keys.clear()


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk(attempts):

    if attempts >= 50:
        return "CRITICAL"

    if attempts >= 20:
        return "HIGH"

    if attempts >= 5:
        return "MEDIUM"

    return "LOW"


# ============================================================
# PROCESS NEW SSH EVENTS
# ============================================================

def process_logs():

    lines = get_ssh_logs()

    if not lines:
        return

    now = datetime.now()

    for line in lines:

        event = parse_ssh_event(line)

        if not event:
            continue

        ip = event["ip"]
        username = event["username"]
        event_type = event["type"]

        # ----------------------------------------------------
        # Ignore whitelist
        # ----------------------------------------------------

        if ip in WHITELIST:
            continue

        # ----------------------------------------------------
        # Ignore already blocked
        # ----------------------------------------------------

        if ip in blocked_ips:
            continue

        # ----------------------------------------------------
        # Deduplication
        # ----------------------------------------------------

        event_key = make_event_key(
            ip,
            username,
            event_type
        )

        # We don't want the same journal entry to be counted
        # several times because journalctl windows overlap.
        #
        # The key is kept only in RAM.

        if event_key in recent_event_keys:

            # Don't immediately ignore forever.
            # The key will be cleared during cleanup.
            continue

        recent_event_keys.add(event_key)

        # ----------------------------------------------------
        # Store event in RAM only
        # ----------------------------------------------------

        recent_events[ip].append(
            {
                "username": username,
                "type": event_type,
                "time": now
            }
        )


# ============================================================
# THREAT ANALYSIS
# ============================================================

def check_threats():

    cleanup_events()

    for ip, events in list(
        recent_events.items()
    ):

        if ip in WHITELIST:
            continue

        if ip in blocked_ips:
            continue

        attempts = len(events)

        if attempts < MAX_ATTEMPTS:
            continue

        # ----------------------------------------------------
        # Users
        # ----------------------------------------------------

        users = sorted(
            set(
                event["username"]
                for event in events
            )
        )

        # ----------------------------------------------------
        # Event types
        # ----------------------------------------------------

        event_types = sorted(
            set(
                event["type"]
                for event in events
            )
        )

        risk = get_risk(attempts)

        # ----------------------------------------------------
        # Display threat
        # ----------------------------------------------------

        print()
        print("=" * 60)

        print(
            f"{RED}[THREAT DETECTED]{RESET}"
        )

        print(
            f"IP:       {ip}"
        )

        print(
            f"Attempts: {attempts}"
        )

        if len(users) <= 8:

            print(
                f"Users:    "
                f"{', '.join(users)}"
            )

        else:

            print(
                f"Users:    "
                f"{', '.join(users[:8])} "
                f"... +{len(users) - 8}"
            )

        print(
            f"Types:    "
            f"{', '.join(event_types)}"
        )

        print(
            f"Window:   "
            f"{WINDOW_SECONDS // 60} minutes"
        )

        print(
            f"Risk:     {risk}"
        )

        print("=" * 60)

        # ====================================================
        # DRY RUN
        # ====================================================

        if DRY_RUN:

            print(
                f"{YELLOW}"
                f"[DRY-RUN] Would BLOCK: {ip}"
                f"{RESET}"
            )

            print(
                f"{GRAY}"
                f"[DRY-RUN] "
                f"No files modified."
                f"{RESET}"
            )

            # ------------------------------------------------
            # IMPORTANT:
            #
            # We do NOT save this event repeatedly.
            # The same attacker will remain in RAM.
            # ------------------------------------------------

            continue

        # ====================================================
        # REAL BLOCK
        # ====================================================

        blocked = block_ip(ip)

        if blocked:

            # Save ONLY the important security event.
            save_event(
                ip=ip,
                attempts=attempts,
                users=users,
                event_types=event_types,
                action="blocked",
                risk=risk
            )

            # Remove from RAM.
            recent_events.pop(
                ip,
                None
            )


# ============================================================
# STARTUP
# ============================================================

def print_banner():

    print()
    print("SERVERGUARD")
    print("===========")
    print()
    print("REALTIME BRUTE FORCE GUARD")
    print("---------------------------")
    print(
        f"Version: {VERSION}"
    )

    print(
        f"Threshold: "
        f"{MAX_ATTEMPTS} attempts / "
        f"{WINDOW_SECONDS // 60} minutes"
    )

    print(
        f"Check interval: "
        f"{CHECK_INTERVAL}s"
    )

    if DRY_RUN:

        print(
            f"Mode: "
            f"{YELLOW}DRY-RUN{RESET}"
        )

    else:

        print(
            f"Mode: "
            f"{RED}PROTECTION ACTIVE{RESET}"
        )

    print(
        f"Loaded blocked IPs: "
        f"{len(blocked_ips)}"
    )

    print(
        f"Event history limit: "
        f"{MAX_SAVED_EVENTS}"
    )

    print()


def startup_checks():

    if DRY_RUN:

        return True

    print(
        f"{YELLOW}"
        "[SAFETY CHECK] Checking UFW..."
        f"{RESET}"
    )

    if not check_ufw():

        print()

        print(
            f"{RED}"
            "WARNING: UFW is not active!"
            f"{RESET}"
        )

        print(
            "ServerGuard will NOT enable UFW automatically."
        )

        print(
            "Configure SSH access first."
        )

        print()

        return False

    print(
        f"{GREEN}"
        "UFW is active."
        f"{RESET}"
    )

    return True


# ============================================================
# MAIN
# ============================================================

def main():

    ensure_data_directory()

    load_blocked_ips()

    print_banner()

    # --------------------------------------------------------
    # Establish baseline.
    #
    # Old SSH events are ignored.
    # --------------------------------------------------------

    get_ssh_logs()

    print(
        "Existing SSH logs ignored."
    )

    print()
    print(
        "Monitoring NEW SSH attacks..."
    )

    print(
        "Press Ctrl+C to stop."
    )

    print()

    # --------------------------------------------------------
    # Safety check
    # --------------------------------------------------------

    if not startup_checks():

        if not DRY_RUN:

            print(
                f"{YELLOW}"
                "Protection NOT started."
                f"{RESET}"
            )

            return

    # --------------------------------------------------------
    # Main loop
    # --------------------------------------------------------

    try:

        while True:

            process_logs()

            check_threats()

            time.sleep(
                CHECK_INTERVAL
            )

    except KeyboardInterrupt:

        print()

        print(
            "ServerGuard stopped."
        )

        print()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()

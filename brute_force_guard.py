#!/usr/bin/env python3

import os
import re
import json
import time
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path


# ============================================================
# SERVERGUARD BRUTE FORCE PROTECTION
# ============================================================

VERSION = "2.3.0"


# ============================================================
# CONFIGURATION
# ============================================================

MAX_ATTEMPTS = 10

WINDOW_SECONDS = 10 * 60

CHECK_INTERVAL = 2

MAX_SAVED_EVENTS = 200


# ------------------------------------------------------------
# Protection mode
#
# Normal manual launch:
#     DRY_RUN = True
#
# systemd:
#     SERVERGUARD_PROTECTION=1
#     -> real protection
# ------------------------------------------------------------

DRY_RUN = (
    os.getenv(
        "SERVERGUARD_PROTECTION",
        "0"
    ) != "1"
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(
    "/opt/serverguard"
)

DATA_DIR = (
    BASE_DIR /
    "data"
)

BLOCKED_FILE = (
    DATA_DIR /
    "blocked_ips.json"
)

EVENTS_FILE = (
    DATA_DIR /
    "events.json"
)


# ============================================================
# WHITELIST
# ============================================================

WHITELIST = {
    "127.0.0.1",
    "::1"
}


# ============================================================
# REGEX
# ============================================================

FAILED_PASSWORD_INVALID_RE = re.compile(
    r"Failed password for invalid user "
    r"(\S+) from "
    r"([0-9a-fA-F:.]+)"
)

FAILED_PASSWORD_RE = re.compile(
    r"Failed password for "
    r"(\S+) from "
    r"([0-9a-fA-F:.]+)"
)

INVALID_USER_RE = re.compile(
    r"Invalid user "
    r"(\S+) from "
    r"([0-9a-fA-F:.]+)"
)

FAILED_PUBLICKEY_RE = re.compile(
    r"Failed publickey for "
    r"(?:invalid user )?"
    r"(\S+) from "
    r"([0-9a-fA-F:.]+)"
)


# ============================================================
# RUNTIME STATE
# ============================================================

recent_events = []

blocked_ips = set()

handled_ips = set()

seen_events = set()


# ============================================================
# TIME
# ============================================================

def now_utc():
    return datetime.now(
        timezone.utc
    )


# ============================================================
# DIRECTORY
# ============================================================

def ensure_data_directory():

    try:

        DATA_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

    except Exception as error:

        print(
            f"[!] Cannot create data directory: {error}"
        )


# ============================================================
# LOAD BLOCKED IPS
# ============================================================

def load_blocked_ips():

    global blocked_ips

    ensure_data_directory()

    if not BLOCKED_FILE.exists():

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

            blocked_ips = {
                str(ip).strip()
                for ip in data
                if str(ip).strip()
            }

        else:

            blocked_ips = set()


    except Exception as error:

        print(
            f"[!] Cannot load blocked IPs: {error}"
        )

        blocked_ips = set()


# ============================================================
# SAVE BLOCKED IPS
# ============================================================

def save_blocked_ips():

    ensure_data_directory()

    temporary_file = (
        BLOCKED_FILE.with_suffix(
            ".tmp"
        )
    )

    try:

        data = sorted(
            blocked_ips
        )


        with open(
            temporary_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                data,
                file,
                indent=2,
                ensure_ascii=False
            )


        os.replace(
            temporary_file,
            BLOCKED_FILE
        )


    except Exception as error:

        print(
            f"[!] Cannot save blocked IPs: {error}"
        )

        try:

            if temporary_file.exists():
                temporary_file.unlink()

        except Exception:
            pass


# ============================================================
# LOAD EVENTS
# ============================================================

def load_events():

    ensure_data_directory()

    if not EVENTS_FILE.exists():

        return


    try:

        with open(
            EVENTS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)


        if not isinstance(
            data,
            list
        ):
            return


        # ----------------------------------------------------
        # We do not need old events in runtime.
        # They are only historical records.
        # ----------------------------------------------------

    except Exception:
        pass


# ============================================================
# SAVE IMPORTANT EVENT
# ============================================================

def save_event(event):

    ensure_data_directory()

    events = []


    if EVENTS_FILE.exists():

        try:

            with open(
                EVENTS_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

                if isinstance(
                    data,
                    list
                ):
                    events = data

        except Exception:

            events = []


    events.append(
        event
    )


    if len(events) > MAX_SAVED_EVENTS:

        events = events[
            -MAX_SAVED_EVENTS:
        ]


    temporary_file = (
        EVENTS_FILE.with_suffix(
            ".tmp"
        )
    )


    try:

        with open(
            temporary_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                events,
                file,
                indent=2,
                ensure_ascii=False
            )


        os.replace(
            temporary_file,
            EVENTS_FILE
        )


    except Exception as error:

        print(
            f"[!] Cannot save security event: {error}"
        )

        try:

            if temporary_file.exists():
                temporary_file.unlink()

        except Exception:
            pass


# ============================================================
# CHECK UFW
# ============================================================

def check_ufw():

    try:

        result = subprocess.run(
            [
                "ufw",
                "status"
            ],
            capture_output=True,
            text=True,
            timeout=10
        )


        output = (
            result.stdout +
            "\n" +
            result.stderr
        )


        if "Status: active" in output:

            return True


        return False


    except Exception as error:

        print(
            f"[!] Cannot check UFW: {error}"
        )

        return False


# ============================================================
# VALIDATE IP
# ============================================================

def is_valid_ip(ip):

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------

    ipv4 = re.match(
        r"^(?:\d{1,3}\.){3}\d{1,3}$",
        ip
    )


    if ipv4:

        try:

            parts = [
                int(x)
                for x in ip.split(".")
            ]

            return all(
                0 <= x <= 255
                for x in parts
            )

        except Exception:

            return False


    # --------------------------------------------------------
    # IPv6
    # --------------------------------------------------------

    if ":" in ip:

        # Basic IPv6 validation.
        # SSH logs give us an already parsed address.
        return bool(
            re.match(
                r"^[0-9a-fA-F:]+$",
                ip
            )
        )


    return False


# ============================================================
# PARSE SSH EVENT
# ============================================================

def parse_ssh_event(line):

    if not line:
        return None


    # --------------------------------------------------------
    # Ignore generic authentication failure.
    #
    # OpenSSH may produce another log entry for the same
    # failed authentication. Counting it would double-count.
    # --------------------------------------------------------

    if "authentication failure" in line.lower():

        return None


    # --------------------------------------------------------
    # Failed password for invalid user
    # --------------------------------------------------------

    match = FAILED_PASSWORD_INVALID_RE.search(
        line
    )

    if match:

        username = match.group(1)

        ip = match.group(2)

        return {
            "ip": ip,
            "username": username,
            "type": "failed_password"
        }


    # --------------------------------------------------------
    # Failed password
    # --------------------------------------------------------

    match = FAILED_PASSWORD_RE.search(
        line
    )

    if match:

        username = match.group(1)

        ip = match.group(2)

        return {
            "ip": ip,
            "username": username,
            "type": "failed_password"
        }


    # --------------------------------------------------------
    # Invalid user
    # --------------------------------------------------------

    match = INVALID_USER_RE.search(
        line
    )

    if match:

        username = match.group(1)

        ip = match.group(2)

        return {
            "ip": ip,
            "username": username,
            "type": "invalid_user"
        }


    # --------------------------------------------------------
    # Failed public key
    # --------------------------------------------------------

    match = FAILED_PUBLICKEY_RE.search(
        line
    )

    if match:

        username = match.group(1)

        ip = match.group(2)

        return {
            "ip": ip,
            "username": username,
            "type": "failed_publickey"
        }


    return None


# ============================================================
# EVENT ID
# ============================================================

def make_event_id(line):

    # --------------------------------------------------------
    # We use the complete journal line as a temporary
    # duplicate protection key.
    # --------------------------------------------------------

    return line.strip()


# ============================================================
# READ NEW SSH LOGS
# ============================================================

def read_new_ssh_logs():

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
                text=True,
                timeout=10
            )


            if result.returncode != 0:

                continue


            output = result.stdout.strip()


            if output:

                return output.splitlines()


        except Exception:

            continue


    # --------------------------------------------------------
    # Fallback to auth.log
    # --------------------------------------------------------

    auth_log = Path(
        "/var/log/auth.log"
    )


    if auth_log.exists():

        try:

            result = subprocess.run(
                [
                    "tail",
                    "-n",
                    "100",
                    str(auth_log)
                ],
                capture_output=True,
                text=True,
                timeout=10
            )


            if result.returncode == 0:

                return result.stdout.splitlines()


        except Exception:

            pass


    return []


# ============================================================
# REMOVE OLD EVENTS
# ============================================================

def cleanup_old_events():

    current_time = time.time()


    minimum_time = (
        current_time -
        WINDOW_SECONDS
    )


    global recent_events

    recent_events = [
        event
        for event in recent_events
        if event["timestamp"] >= minimum_time
    ]


# ============================================================
# ADD EVENT
# ============================================================

def add_event(
    ip,
    username,
    event_type
):

    current_time = time.time()


    recent_events.append(
        {
            "timestamp": current_time,
            "ip": ip,
            "username": username,
            "type": event_type
        }
    )


# ============================================================
# GET IP EVENTS
# ============================================================

def get_ip_events(ip):

    cleanup_old_events()


    return [
        event
        for event in recent_events
        if event["ip"] == ip
    ]


# ============================================================
# RISK
# ============================================================

def calculate_risk(
    attempts
):

    if attempts >= 50:

        return "CRITICAL"


    if attempts >= 20:

        return "HIGH"


    if attempts >= 10:

        return "MEDIUM"


    if attempts >= 5:

        return "LOW"


    return "LOW"


# ============================================================
# DISPLAY THREAT
# ============================================================

def show_threat(
    ip,
    events
):

    attempts = len(
        events
    )


    users = sorted(
        {
            event["username"]
            for event in events
            if event.get("username")
        }
    )


    event_types = sorted(
        {
            event["type"]
            for event in events
        }
    )


    risk = calculate_risk(
        attempts
    )


    print()

    print(
        "============================================================"
    )

    print(
        "[THREAT DETECTED]"
    )

    print(
        f"IP:       {ip}"
    )

    print(
        f"Attempts: {attempts}"
    )

    print(
        "Users:    "
        + (
            ", ".join(users)
            if users
            else "unknown"
        )
    )

    print(
        "Types:    "
        + (
            ", ".join(event_types)
            if event_types
            else "unknown"
        )
    )

    print(
        "Window:   10 minutes"
    )

    print(
        f"Risk:     {risk}"
    )

    print(
        "============================================================"
    )


# ============================================================
# BLOCK IP
# ============================================================

def block_ip(ip):

    if ip in WHITELIST:

        print(
            f"[!] BLOCK SKIPPED: {ip} is whitelisted."
        )

        return False


    if not is_valid_ip(ip):

        print(
            f"[!] BLOCK SKIPPED: invalid IP: {ip}"
        )

        return False


    if ip in blocked_ips:

        return True


    # --------------------------------------------------------
    # DRY RUN
    # --------------------------------------------------------

    if DRY_RUN:

        print(
            f"[DRY-RUN] Would BLOCK: {ip}"
        )

        print(
            "[DRY-RUN] No files modified."
        )

        return False


    # --------------------------------------------------------
    # UFW check
    # --------------------------------------------------------

    if not check_ufw():

        print(
            "[!] UFW is not active."
        )

        print(
            f"[!] Cannot block {ip}."
        )

        return False


    # --------------------------------------------------------
    # UFW block
    # --------------------------------------------------------

    print(
        f"[*] Blocking IP: {ip}"
    )


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
            capture_output=True,
            text=True,
            timeout=15
        )


    except Exception as error:

        print(
            f"[!] UFW command failed: {error}"
        )

        return False


    # --------------------------------------------------------
    # Check result
    # --------------------------------------------------------

    if result.returncode != 0:

        output = (
            result.stdout +
            "\n" +
            result.stderr
        ).strip()


        print(
            "[!] Failed to block IP."
        )


        if output:

            print(
                f"    {output}"
            )


        return False


    # --------------------------------------------------------
    # Successful block
    # --------------------------------------------------------

    blocked_ips.add(
        ip
    )


    handled_ips.add(
        ip
    )


    save_blocked_ips()


    print(
        f"[+] BLOCKED: {ip}"
    )


    return True


# ============================================================
# SAVE THREAT EVENT
# ============================================================

def save_threat_event(
    ip,
    events,
    blocked
):

    users = sorted(
        {
            event["username"]
            for event in events
            if event.get("username")
        }
    )


    event_types = sorted(
        {
            event["type"]
            for event in events
        }
    )


    event = {
        "timestamp": now_utc().isoformat(),
        "ip": ip,
        "attempts": len(events),
        "users": users,
        "types": event_types,
        "window_seconds": WINDOW_SECONDS,
        "risk": calculate_risk(
            len(events)
        ),
        "action": (
            "blocked"
            if blocked
            else "detected"
        ),
        "dry_run": DRY_RUN
    }


    save_event(
        event
    )


# ============================================================
# HANDLE ATTACK
# ============================================================

def handle_attack(
    ip
):

    # --------------------------------------------------------
    # Already blocked
    # --------------------------------------------------------

    if ip in blocked_ips:

        handled_ips.add(
            ip
        )

        return


    # --------------------------------------------------------
    # Already handled during this runtime
    # --------------------------------------------------------

    if ip in handled_ips:

        return


    events = get_ip_events(
        ip
    )


    if len(events) < MAX_ATTEMPTS:

        return


    # --------------------------------------------------------
    # Threat
    # --------------------------------------------------------

    show_threat(
        ip,
        events
    )


    # --------------------------------------------------------
    # Real protection
    # --------------------------------------------------------

    if DRY_RUN:

        print(
            f"[DRY-RUN] Would BLOCK: {ip}"
        )

        print(
            "[DRY-RUN] Protection is not modifying the server."
        )


        # ----------------------------------------------------
        # IMPORTANT:
        #
        # We mark the IP as handled even in DRY-RUN.
        #
        # This prevents the same IP from producing the same
        # threat message every 2 seconds.
        #
        # It is NOT written to blocked_ips.json.
        # ----------------------------------------------------

        handled_ips.add(
            ip
        )


        save_threat_event(
            ip,
            events,
            False
        )


        return


    # --------------------------------------------------------
    # Real block
    # --------------------------------------------------------

    blocked = block_ip(
        ip
    )


    if blocked:

        save_threat_event(
            ip,
            events,
            True
        )

    else:

        # ----------------------------------------------------
        # If UFW failed, don't spam every 2 seconds forever.
        #
        # We remember that this threat was processed for this
        # runtime. On restart it will be checked again.
        # ----------------------------------------------------

        handled_ips.add(
            ip
        )


        save_threat_event(
            ip,
            events,
            False
        )


# ============================================================
# PROCESS LOG LINE
# ============================================================

def process_log_line(
    line
):

    if not line:
        return


    event_id = make_event_id(
        line
    )


    if event_id in seen_events:

        return


    seen_events.add(
        event_id
    )


    # --------------------------------------------------------
    # Prevent unlimited memory growth.
    # --------------------------------------------------------

    if len(seen_events) > 5000:

        # Keep only the newest part.
        # Sets are unordered, therefore simply clearing is
        # acceptable because journal --since only returns
        # recent entries.
        seen_events.clear()


    event = parse_ssh_event(
        line
    )


    if not event:

        return


    ip = event["ip"]

    username = event["username"]

    event_type = event["type"]


    # --------------------------------------------------------
    # Ignore localhost
    # --------------------------------------------------------

    if ip in WHITELIST:

        return


    # --------------------------------------------------------
    # Ignore already blocked IPs
    # --------------------------------------------------------

    if ip in blocked_ips:

        return


    # --------------------------------------------------------
    # Add to memory
    # --------------------------------------------------------

    add_event(
        ip,
        username,
        event_type
    )


    # --------------------------------------------------------
    # Check attack
    # --------------------------------------------------------

    handle_attack(
        ip
    )


# ============================================================
# STARTUP INFORMATION
# ============================================================

def print_startup():

    print()

    print(
        "============================================================"
    )

    print(
        "SERVERGUARD BRUTE FORCE PROTECTION"
    )

    print(
        f"Version: {VERSION}"
    )

    print(
        "============================================================"
    )

    print()


    print(
        f"Maximum attempts: {MAX_ATTEMPTS}"
    )

    print(
        "Detection window: 10 minutes"
    )

    print(
        f"Check interval:   {CHECK_INTERVAL} seconds"
    )

    print()


    if DRY_RUN:

        print(
            "MODE: DRY-RUN"
        )

        print(
            "No IPs will be blocked."
        )

    else:

        print(
            "MODE: ACTIVE PROTECTION"
        )

        print(
            "Threatening IPs will be blocked by UFW."
        )


    print()


    print(
        f"Blocked IPs: {len(blocked_ips)}"
    )


    print()


# ============================================================
# STARTUP UFW CHECK
# ============================================================

def startup_checks():

    if DRY_RUN:

        return True


    print(
        "[*] Checking UFW..."
    )


    if not check_ufw():

        print()

        print(
            "[!] SECURITY ERROR"
        )

        print(
            "[!] UFW is inactive."
        )

        print(
            "[!] Active protection cannot start."
        )

        print(
            "[!] Enable/configure UFW first."
        )

        print()

        return False


    print(
        "[+] UFW is active."
    )

    print()


    return True


# ============================================================
# IGNORE OLD LOGS
# ============================================================

def warmup_logs():

    print(
        "[*] Reading current SSH journal..."
    )


    lines = read_new_ssh_logs()


    # --------------------------------------------------------
    # We deliberately DO NOT process old logs on startup.
    #
    # Otherwise the server could immediately block IPs based
    # on attacks that happened before ServerGuard started.
    # --------------------------------------------------------

    print(
        f"[*] Existing SSH log entries ignored: {len(lines)}"
    )

    print()


# ============================================================
# MAIN MONITOR LOOP
# ============================================================

def monitor():

    print(
        "Monitoring NEW SSH attacks..."
    )

    print(
        "Press Ctrl+C to stop."
    )

    print()


    while True:

        try:

            lines = read_new_ssh_logs()


            for line in lines:

                process_log_line(
                    line
                )


            cleanup_old_events()


            time.sleep(
                CHECK_INTERVAL
            )


        except KeyboardInterrupt:

            print()

            print(
                "[*] ServerGuard protection stopped."
            )

            break


        except Exception as error:

            print()

            print(
                f"[!] Monitor error: {error}"
            )

            print(
                "[*] Restarting monitor..."
            )

            print()


            time.sleep(
                CHECK_INTERVAL
            )


# ============================================================
# MAIN
# ============================================================

def main():

    ensure_data_directory()

    load_blocked_ips()

    load_events()


    print_startup()


    if not startup_checks():

        return 1


    warmup_logs()


    monitor()


    return 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    raise SystemExit(
        main()
    )

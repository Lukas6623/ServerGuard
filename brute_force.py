
#!/usr/bin/env python3

import ipaddress
import re
import subprocess
from collections import defaultdict
from pathlib import Path


MODULE_NAME = "brute_force"
MODULE_VERSION = "1.1.0"

MAX_LOG_LINES = 1000
MAX_USERS_DISPLAY = 8
COMMAND_TIMEOUT = 15

LOG_FILES = (
    "/var/log/auth.log",
    "/var/log/secure",
)

ATTACK_PATTERNS = (
    (
        "failed_password",
        re.compile(
            r"Failed password for invalid user\s+(\S+)\s+from\s+(\S+)",
            re.IGNORECASE,
        ),
    ),
    (
        "failed_password",
        re.compile(
            r"Failed password for\s+(\S+)\s+from\s+(\S+)",
            re.IGNORECASE,
        ),
    ),
    (
        "invalid_user",
        re.compile(
            r"Invalid user\s+(\S+)\s+from\s+(\S+)",
            re.IGNORECASE,
        ),
    ),
    (
        "failed_publickey",
        re.compile(
            r"Failed publickey for (?:invalid user\s+)?(\S+)\s+from\s+(\S+)",
            re.IGNORECASE,
        ),
    ),
)


def run_command(command, timeout=COMMAND_TIMEOUT):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
            check=False,
        )

        if result.returncode != 0:
            return ""

        return result.stdout

    except (OSError, subprocess.SubprocessError):
        return ""


def get_ssh_logs():
    for service in ("ssh", "sshd"):
        output = run_command([
            "journalctl",
            "-u", service,
            "--no-pager",
            "-n", str(MAX_LOG_LINES),
            "-o", "short-iso",
        ])

        if output.strip():
            return output

    for filename in LOG_FILES:
        try:
            with Path(filename).open(
                "r",
                encoding="utf-8",
                errors="replace",
            ) as log_file:
                lines = log_file.readlines()

            if lines:
                return "".join(lines[-MAX_LOG_LINES:])

        except OSError:
            continue

    return ""


def clean_username(username):
    if not username:
        return "unknown"

    username = username.strip().lstrip("=")

    if not username:
        return "unknown"

    username = username.split()[0]
    username = re.sub(r"[^a-zA-Z0-9_.@+-]", "", username)

    return username or "unknown"


def is_valid_ip(value):
    if not value:
        return False

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_attack(line):
    for attack_type, pattern in ATTACK_PATTERNS:
        match = pattern.search(line)

        if not match:
            continue

        username = clean_username(match.group(1))
        ip = match.group(2).rstrip(",;")

        if not is_valid_ip(ip):
            continue

        if username.lower() == "invalid":
            username = "unknown"

        return {
            "ip": ip,
            "username": username,
            "type": attack_type,
        }

    return None


def analyze_logs(logs):
    attackers = defaultdict(
        lambda: {
            "attempts": 0,
            "users": set(),
            "types": defaultdict(int),
        }
    )

    total_attempts = 0

    for line in logs.splitlines():
        attack = parse_attack(line)

        if attack is None:
            continue

        ip = attack["ip"]
        username = attack["username"]
        attack_type = attack["type"]

        attackers[ip]["attempts"] += 1
        attackers[ip]["types"][attack_type] += 1

        if username != "unknown":
            attackers[ip]["users"].add(username)

        total_attempts += 1

    return attackers, total_attempts


def get_risk(attempts):
    if attempts >= 50:
        return "CRITICAL"

    if attempts >= 20:
        return "HIGH"

    if attempts >= 5:
        return "MEDIUM"

    return "LOW"


def print_header():
    print()
    print("SERVERGUARD")
    print("===========")
    print()
    print("BRUTE FORCE MONITOR")
    print("--------------------")


def print_attackers(attackers, total_attempts):
    if not attackers:
        print()
        print("No SSH brute-force attempts detected.")
        print()
        return

    sorted_attackers = sorted(
        attackers.items(),
        key=lambda item: item[1]["attempts"],
        reverse=True,
    )

    print()
    print(f"{'IP ADDRESS':<40}{'ATTEMPTS':>10}   USERS")
    print("-" * 90)

    for ip, data in sorted_attackers:
        users = sorted(data["users"])
        users_text = ", ".join(users) if users else "unknown"

        if len(users) > MAX_USERS_DISPLAY:
            displayed = users[:MAX_USERS_DISPLAY]
            remaining = len(users) - MAX_USERS_DISPLAY
            users_text = ", ".join(displayed) + f" ... +{remaining}"

        print(
            f"{ip:<40}"
            f"{data['attempts']:>10}   "
            f"{users_text}"
        )

    print("-" * 90)
    print(f"{'TOTAL':<40}{total_attempts:>10}   attempts")
    print(f"{'ATTACKERS':<40}{len(attackers):>10}   IPs")

    root_attackers = sum(
        1
        for data in attackers.values()
        if "root" in data["users"]
    )

    print(f"{'ROOT ATTACKS':<40}{root_attackers:>10}   IPs")

    unique_users = {
        username
        for data in attackers.values()
        for username in data["users"]
    }

    print(f"{'UNIQUE USERS':<40}{len(unique_users):>10}")
    print()
    print(f"RISK: {get_risk(total_attempts)}")
    print()


def print_statistics(attackers):
    if not attackers:
        return

    totals = defaultdict(int)

    for data in attackers.values():
        for attack_type, count in data["types"].items():
            totals[attack_type] += count

    print("EVENT TYPES")
    print("-----------")
    print(f"Failed password:   {totals['failed_password']}")
    print(f"Invalid user:      {totals['invalid_user']}")
    print(f"Failed publickey:  {totals['failed_publickey']}")
    print()


def main():
    print_header()

    logs = get_ssh_logs()

    if not logs.strip():
        print()
        print("Unable to read SSH authentication logs.")
        print("Check journal access or log file permissions.")
        print()
        return

    attackers, total_attempts = analyze_logs(logs)

    print_attackers(attackers, total_attempts)
    print_statistics(attackers)


if __name__ == "__main__":
    main()


#!/usr/bin/env python3

import subprocess
import re
from collections import defaultdict


# ============================================================
# SERVERGUARD - BRUTE FORCE MONITOR
# ============================================================

MODULE_NAME = "brute_force"
MODULE_VERSION = "1.1.0"

MAX_LOG_LINES = 1000


# ============================================================
# COMMAND
# ============================================================

def run_command(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )

        return result.stdout

    except Exception:
        return ""


# ============================================================
# GET SSH LOGS
# ============================================================

def get_ssh_logs():

    # 1. Ubuntu / Debian
    output = run_command(
        f"journalctl -u ssh --no-pager -n {MAX_LOG_LINES} 2>/dev/null"
    )

    if output.strip():
        return output

    # 2. Некоторые системы используют sshd
    output = run_command(
        f"journalctl -u sshd --no-pager -n {MAX_LOG_LINES} 2>/dev/null"
    )

    if output.strip():
        return output

    # 3. Старый вариант через auth.log
    output = run_command(
        f"grep -Ei "
        f"'Failed password|Invalid user|Failed publickey|authentication failure' "
        f"/var/log/auth.log 2>/dev/null | tail -n {MAX_LOG_LINES}"
    )

    return output


# ============================================================
# CLEAN USERNAME
# ============================================================

def clean_username(username):

    if not username:
        return "unknown"

    username = username.strip()

    # Иногда parser получает:
    # user=
    # user=admin
    # =admin
    # =
    username = username.lstrip("=")

    if not username:
        return "unknown"

    # Убираем мусор после username
    username = username.split()[0]

    # Разрешаем обычные Linux usernames
    username = re.sub(
        r"[^a-zA-Z0-9_.@+-]",
        "",
        username
    )

    if not username:
        return "unknown"

    return username


# ============================================================
# VALID IP
# ============================================================

def is_valid_ip(value):

    if not value:
        return False

    # IPv4
    if re.fullmatch(
        r"(?:\d{1,3}\.){3}\d{1,3}",
        value
    ):
        return True

    # IPv6
    if ":" in value:
        return True

    return False


# ============================================================
# PARSE ATTACK
# ============================================================

def parse_attack(line):

    # --------------------------------------------------------
    # Failed password for invalid user USER from IP
    # --------------------------------------------------------

    match = re.search(
        r"Failed password for invalid user\s+(\S+)\s+from\s+([0-9a-fA-F:.]+)",
        line,
        re.IGNORECASE
    )

    if match:

        username = clean_username(
            match.group(1)
        )

        ip = match.group(2)

        if is_valid_ip(ip):

            return {
                "ip": ip,
                "username": username,
                "type": "failed_password"
            }

    # --------------------------------------------------------
    # Failed password for USER from IP
    # --------------------------------------------------------

    match = re.search(
        r"Failed password for\s+(\S+)\s+from\s+([0-9a-fA-F:.]+)",
        line,
        re.IGNORECASE
    )

    if match:

        username = clean_username(
            match.group(1)
        )

        ip = match.group(2)

        if username == "invalid":
            username = "unknown"

        if is_valid_ip(ip):

            return {
                "ip": ip,
                "username": username,
                "type": "failed_password"
            }

    # --------------------------------------------------------
    # Invalid user USER from IP
    # --------------------------------------------------------

    match = re.search(
        r"Invalid user\s+(\S+)\s+from\s+([0-9a-fA-F:.]+)",
        line,
        re.IGNORECASE
    )

    if match:

        username = clean_username(
            match.group(1)
        )

        ip = match.group(2)

        if is_valid_ip(ip):

            return {
                "ip": ip,
                "username": username,
                "type": "invalid_user"
            }

    # --------------------------------------------------------
    # Failed publickey
    # --------------------------------------------------------

    match = re.search(
        r"Failed publickey for\s+(?:invalid user\s+)?(\S+)\s+from\s+([0-9a-fA-F:.]+)",
        line,
        re.IGNORECASE
    )

    if match:

        username = clean_username(
            match.group(1)
        )

        ip = match.group(2)

        if is_valid_ip(ip):

            return {
                "ip": ip,
                "username": username,
                "type": "failed_publickey"
            }

    # --------------------------------------------------------
    # authentication failure
    #
    # Здесь НЕ считаем отдельную атаку.
    #
    # Эта запись PAM часто относится к той же попытке,
    # поэтому возвращаем None, чтобы не было двойного счёта.
    # --------------------------------------------------------

    return None


# ============================================================
# ANALYZE LOGS
# ============================================================

def analyze_logs(logs):

    attackers = defaultdict(
        lambda: {
            "attempts": 0,
            "users": set(),
            "types": defaultdict(int)
        }
    )

    total_attempts = 0

    # --------------------------------------------------------
    # Каждая строка журнала обрабатывается один раз.
    # --------------------------------------------------------

    for line in logs.splitlines():

        line = line.strip()

        if not line:
            continue

        attack = parse_attack(line)

        if attack is None:
            continue

        ip = attack["ip"]
        username = attack["username"]
        attack_type = attack["type"]

        attackers[ip]["attempts"] += 1

        if username != "unknown":
            attackers[ip]["users"].add(username)

        attackers[ip]["types"][attack_type] += 1

        total_attempts += 1

    return attackers, total_attempts


# ============================================================
# RISK
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
# PRINT HEADER
# ============================================================

def print_header():

    print()
    print("SERVERGUARD")
    print("===========")
    print()
    print("BRUTE FORCE MONITOR")
    print("--------------------")


# ============================================================
# PRINT ATTACKERS
# ============================================================

def print_attackers(attackers, total_attempts):

    if not attackers:

        print()
        print("No SSH brute-force attempts detected.")
        print()

        return

    sorted_attackers = sorted(
        attackers.items(),
        key=lambda item: item[1]["attempts"],
        reverse=True
    )

    print()

    print(
        f"{'IP ADDRESS':<18}"
        f"{'ATTEMPTS':>10}   "
        f"USERS"
    )

    print("-" * 75)

    for ip, data in sorted_attackers:

        attempts = data["attempts"]

        users = sorted(
            data["users"]
        )

        if users:
            users_text = ", ".join(users)
        else:
            users_text = "unknown"

        # Если пользователей очень много,
        # не раздуваем консоль.
        MAX_USERS_DISPLAY = 8

        if len(users) > MAX_USERS_DISPLAY:

            displayed = users[:MAX_USERS_DISPLAY]

            users_text = (
                ", ".join(displayed)
                + f" ... +{len(users) - MAX_USERS_DISPLAY}"
            )

        print(
            f"{ip:<18}"
            f"{attempts:>10}   "
            f"{users_text}"
        )

    print("-" * 75)

    print(
        f"{'TOTAL':<18}"
        f"{total_attempts:>10}   attempts"
    )

    print(
        f"{'ATTACKERS':<18}"
        f"{len(attackers):>10}   IPs"
    )

    root_attackers = sum(
        1
        for data in attackers.values()
        if "root" in data["users"]
    )

    print(
        f"{'ROOT ATTACKS':<18}"
        f"{root_attackers:>10}   IPs"
    )

    unique_users = set()

    for data in attackers.values():
        unique_users.update(
            data["users"]
        )

    print(
        f"{'UNIQUE USERS':<18}"
        f"{len(unique_users):>10}"
    )

    print()

    print(
        f"RISK: {get_risk(total_attempts)}"
    )

    print()


# ============================================================
# PRINT STATISTICS
# ============================================================

def print_statistics(attackers):

    if not attackers:
        return

    failed_password = 0
    invalid_users = 0
    failed_publickey = 0

    for data in attackers.values():

        types = data["types"]

        failed_password += types.get(
            "failed_password",
            0
        )

        invalid_users += types.get(
            "invalid_user",
            0
        )

        failed_publickey += types.get(
            "failed_publickey",
            0
        )

    print("EVENT TYPES")
    print("-----------")

    print(
        f"Failed password:   {failed_password}"
    )

    print(
        f"Invalid user:      {invalid_users}"
    )

    print(
        f"Failed publickey:  {failed_publickey}"
    )

    print()


# ============================================================
# MAIN
# ============================================================

def main():

    print_header()

    logs = get_ssh_logs()

    if not logs.strip():

        print()
        print("Unable to read SSH authentication logs.")
        print()

        return

    attackers, total_attempts = analyze_logs(
        logs
    )

    print_attackers(
        attackers,
        total_attempts
    )

    print_statistics(
        attackers
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()

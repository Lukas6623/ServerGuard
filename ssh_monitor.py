#!/usr/bin/env python3

import json
import os
import re
import subprocess
from collections import Counter


# ============================================================
# SERVERGUARD SSH MONITOR
# ============================================================

MODULE_NAME = "ssh_monitor"
MODULE_VERSION = "0.2.0"

SERVER_INFO_FILE = "data/server_info.json"

MAX_LOG_LINES = 3000


# ============================================================
# COMMAND HELPERS
# ============================================================

def run_command(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15
        )

        return result.stdout.strip()

    except Exception:
        return ""


def command_exists(command):
    result = subprocess.run(
        f"command -v {command}",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


# ============================================================
# JSON
# ============================================================

def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)

    except Exception:
        return {}


# ============================================================
# SSH LOG COLLECTION
# ============================================================

def get_ssh_logs():
    """
    Collect SSH logs.

    We prefer auth.log when available because it gives us one
    consistent source and avoids duplicated journal entries.

    If auth.log is unavailable, use journalctl.
    """

    logs = []

    # --------------------------------------------------------
    # Ubuntu auth.log
    # --------------------------------------------------------

    auth_log = "/var/log/auth.log"

    if os.path.exists(auth_log):

        output = run_command(
            f"tail -n {MAX_LOG_LINES} "
            f"{auth_log} 2>/dev/null"
        )

        if output:
            logs = output.splitlines()

    # --------------------------------------------------------
    # Fallback: journalctl
    # --------------------------------------------------------

    if not logs and command_exists("journalctl"):

        output = run_command(
            f"journalctl -u ssh --no-pager "
            f"-n {MAX_LOG_LINES} 2>/dev/null"
        )

        if output:
            logs = output.splitlines()

    # --------------------------------------------------------
    # Remove exact duplicate lines
    # --------------------------------------------------------

    logs = list(dict.fromkeys(logs))

    return logs


# ============================================================
# SUCCESSFUL LOGINS
# ============================================================

def parse_successful_logins(logs):

    results = []

    pattern = re.compile(
        r"Accepted\s+(\S+)\s+for\s+(\S+)"
        r"\s+from\s+([0-9a-fA-F:.]+)"
        r"\s+port\s+(\d+)"
    )

    for line in logs:

        match = pattern.search(line)

        if not match:
            continue

        method = match.group(1)
        username = match.group(2)
        ip = match.group(3)
        port = match.group(4)

        results.append({
            "user": username,
            "ip": ip,
            "port": int(port),
            "method": method,
            "log": line
        })

    return results


# ============================================================
# FAILED PASSWORD
# ============================================================

def parse_failed_passwords(logs):

    results = []

    pattern = re.compile(
        r"Failed password for "
        r"(invalid user\s+)?(\S+)"
        r"\s+from\s+([0-9a-fA-F:.]+)"
        r"\s+port\s+(\d+)"
    )

    for line in logs:

        match = pattern.search(line)

        if not match:
            continue

        invalid_prefix = match.group(1)
        username = match.group(2)
        ip = match.group(3)
        port = match.group(4)

        results.append({
            "user": username,
            "ip": ip,
            "port": int(port),
            "invalid_user": bool(invalid_prefix),
            "type": "failed_password",
            "log": line
        })

    return results


# ============================================================
# INVALID USERS
# ============================================================

def parse_invalid_users(logs):

    results = []

    pattern = re.compile(
        r"Invalid user\s+(\S+)"
        r"\s+from\s+([0-9a-fA-F:.]+)"
        r"\s+port\s+(\d+)"
    )

    for line in logs:

        match = pattern.search(line)

        if not match:
            continue

        username = match.group(1)
        ip = match.group(2)
        port = match.group(3)

        results.append({
            "user": username,
            "ip": ip,
            "port": int(port),
            "type": "invalid_user",
            "log": line
        })

    return results


# ============================================================
# FAILED PUBLIC KEY
# ============================================================

def parse_failed_public_keys(logs):

    results = []

    pattern = re.compile(
        r"Failed publickey for "
        r"(?:invalid user\s+)?(\S+)"
        r"\s+from\s+([0-9a-fA-F:.]+)"
        r"\s+port\s+(\d+)"
    )

    for line in logs:

        match = pattern.search(line)

        if not match:
            continue

        username = match.group(1)
        ip = match.group(2)
        port = match.group(3)

        results.append({
            "user": username,
            "ip": ip,
            "port": int(port),
            "type": "failed_publickey",
            "log": line
        })

    return results


# ============================================================
# AUTHENTICATION FAILURE
# ============================================================

def parse_authentication_failures(logs):
    """
    IMPORTANT:

    PAM authentication failure is NOT counted as a separate
    login attempt.

    It is supporting information for a Failed password event.

    We keep it only for diagnostics.
    """

    results = []

    pattern = re.compile(
        r"authentication failure.*?"
        r"(?:rhost=([0-9a-fA-F:.]+))?"
        r".*?(?:user=(\S+))?"
    )

    for line in logs:

        if "authentication failure" not in line.lower():
            continue

        ip_match = re.search(
            r"\brhost=([0-9a-fA-F:.]+)",
            line
        )

        user_match = re.search(
            r"\buser=(\S+)",
            line
        )

        ip = ip_match.group(1) if ip_match else None
        username = user_match.group(1) if user_match else None

        results.append({
            "user": username,
            "ip": ip,
            "type": "authentication_failure",
            "log": line
        })

    return results


# ============================================================
# PAM REPEATED FAILURES
# ============================================================

def parse_pam_repeated_failures(logs):

    results = []

    pattern = re.compile(
        r"PAM\s+(\d+)\s+more authentication failures"
    )

    for line in logs:

        match = pattern.search(line)

        if not match:
            continue

        count = int(match.group(1))

        ip_match = re.search(
            r"\brhost=([0-9a-fA-F:.]+)",
            line
        )

        user_match = re.search(
            r"\buser=(\S+)",
            line
        )

        ip = ip_match.group(1) if ip_match else None
        username = user_match.group(1) if user_match else None

        results.append({
            "user": username,
            "ip": ip,
            "additional_failures": count,
            "type": "pam_repeated_failures",
            "log": line
        })

    return results


# ============================================================
# ROOT ATTEMPTS
# ============================================================

def get_root_attempts(failed_passwords, failed_public_keys):

    results = []

    for event in failed_passwords:

        if event.get("user") == "root":

            results.append(event)

    for event in failed_public_keys:

        if event.get("user") == "root":

            results.append(event)

    return results


# ============================================================
# CURRENT SSH CONNECTIONS
# ============================================================

def get_current_ssh_connections():

    if not command_exists("ss"):
        return []

    output = run_command(
        "ss -tnp 2>/dev/null"
    )

    results = []

    for line in output.splitlines():

        if "ESTAB" not in line:
            continue

        parts = line.split()

        if len(parts) < 5:
            continue

        state = parts[0]
        local = parts[3]
        remote = parts[4]

        # We only want connections to SSH port 22.
        local_port_match = re.search(
            r":22$",
            local
        )

        if not local_port_match:
            continue

        process = None
        pid = None

        process_match = re.search(
            r'users:\(\("([^"]+)",pid=(\d+)',
            line
        )

        if process_match:

            process = process_match.group(1)
            pid = process_match.group(2)

        # ----------------------------------------------------
        # Remote IP
        # ----------------------------------------------------

        remote_ip = remote

        ipv4_match = re.match(
            r"(.+):(\d+)$",
            remote
        )

        if ipv4_match:
            remote_ip = ipv4_match.group(1)

        ipv6_match = re.match(
            r"\[(.+)\]:(\d+)$",
            remote
        )

        if ipv6_match:
            remote_ip = ipv6_match.group(1)

        results.append({
            "state": state,
            "local": local,
            "remote": remote,
            "remote_ip": remote_ip,
            "process": process,
            "pid": pid
        })

    return results


# ============================================================
# ATTACKER STATISTICS
# ============================================================

def build_attacker_statistics(
    failed_passwords,
    invalid_users,
    failed_public_keys,
    pam_repeated_failures
):

    counter = Counter()

    # --------------------------------------------------------
    # Failed passwords
    # --------------------------------------------------------

    for event in failed_passwords:

        ip = event.get("ip")

        if ip:
            counter[ip] += 1

    # --------------------------------------------------------
    # Invalid users
    #
    # IMPORTANT:
    #
    # Invalid user is normally followed by Failed password.
    # We therefore DO NOT count it again.
    # --------------------------------------------------------

    # --------------------------------------------------------
    # Public key failures
    # --------------------------------------------------------

    for event in failed_public_keys:

        ip = event.get("ip")

        if ip:
            counter[ip] += 1

    # --------------------------------------------------------
    # PAM repeated failures
    #
    # These are additional failed attempts.
    # --------------------------------------------------------

    for event in pam_repeated_failures:

        ip = event.get("ip")

        if ip:

            counter[ip] += event.get(
                "additional_failures",
                0
            )

    attackers = []

    for ip, attempts in counter.most_common():

        attackers.append({
            "ip": ip,
            "attempts": attempts
        })

    return attackers


# ============================================================
# FAILED ATTEMPT COUNT
# ============================================================

def calculate_failed_attempts(
    failed_passwords,
    failed_public_keys,
    pam_repeated_failures
):

    total = 0

    # Every Failed password = one attempt
    total += len(failed_passwords)

    # Every Failed publickey = one attempt
    total += len(failed_public_keys)

    # PAM "N more" = additional attempts
    for event in pam_repeated_failures:

        total += event.get(
            "additional_failures",
            0
        )

    return total


# ============================================================
# RISK
# ============================================================

def calculate_risk(
    failed_count,
    unique_attackers,
    root_attempts
):

    if failed_count >= 50:
        level = "critical"

    elif failed_count >= 20:
        level = "high"

    elif failed_count >= 5:
        level = "medium"

    else:
        level = "low"

    problems = []

    if failed_count > 0:

        problems.append(
            f"{failed_count} failed SSH authentication attempts"
        )

    if unique_attackers > 0:

        problems.append(
            f"{unique_attackers} unique attacking IP addresses"
        )

    if root_attempts > 0:

        problems.append(
            f"{root_attempts} failed SSH attempts against root"
        )

    return level, problems


# ============================================================
# MAIN ANALYSIS
# ============================================================

def analyze_ssh():

    server_info = load_json(
        SERVER_INFO_FILE
    )

    logs = get_ssh_logs()

    successful_logins = parse_successful_logins(
        logs
    )

    failed_passwords = parse_failed_passwords(
        logs
    )

    invalid_users = parse_invalid_users(
        logs
    )

    failed_public_keys = parse_failed_public_keys(
        logs
    )

    authentication_failures = (
        parse_authentication_failures(
            logs
        )
    )

    pam_repeated_failures = (
        parse_pam_repeated_failures(
            logs
        )
    )

    current_connections = (
        get_current_ssh_connections()
    )

    failed_count = calculate_failed_attempts(
        failed_passwords,
        failed_public_keys,
        pam_repeated_failures
    )

    root_attempts = get_root_attempts(
        failed_passwords,
        failed_public_keys
    )

    attackers = build_attacker_statistics(
        failed_passwords,
        invalid_users,
        failed_public_keys,
        pam_repeated_failures
    )

    risk_level, problems = calculate_risk(
        failed_count,
        len(attackers),
        len(root_attempts)
    )

    # --------------------------------------------------------
    # Successful users
    # --------------------------------------------------------

    successful_users = Counter(
        event["user"]
        for event in successful_logins
    )

    # --------------------------------------------------------
    # Failed users
    # --------------------------------------------------------

    failed_users = Counter()

    for event in failed_passwords:

        username = event.get("user")

        if username:
            failed_users[username] += 1

    for event in failed_public_keys:

        username = event.get("user")

        if username:
            failed_users[username] += 1

    # --------------------------------------------------------
    # Invalid users
    # --------------------------------------------------------

    invalid_user_counter = Counter(
        event["user"]
        for event in invalid_users
        if event.get("user")
    )

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    result = {

        "module": MODULE_NAME,

        "version": MODULE_VERSION,

        "status": "ok",

        "server": {

            "hostname": server_info.get(
                "server", {}
            ).get("hostname"),

            "addresses": server_info.get(
                "server", {}
            ).get("addresses", [])
        },

        "log_source": {
            "path": (
                "/var/log/auth.log"
                if os.path.exists("/var/log/auth.log")
                else "journalctl"
            ),
            "lines_analyzed": len(logs)
        },

        "ssh": {

            "successful_logins": {

                "total": len(
                    successful_logins
                ),

                "users": dict(
                    successful_users
                ),

                "events": successful_logins[-50:]
            },

            "failed_logins": {

                "total": failed_count,

                "users": dict(
                    failed_users
                ),

                "events": (
                    failed_passwords
                    + failed_public_keys
                )[-100:]
            },

            "invalid_users": {

                "total": len(
                    invalid_users
                ),

                "users": dict(
                    invalid_user_counter
                ),

                "events": invalid_users[-50:]
            },

            "root_attempts": {

                "total": len(
                    root_attempts
                ),

                "events": root_attempts[-50:]
            },

            "failed_public_keys": {

                "total": len(
                    failed_public_keys
                ),

                "events": failed_public_keys[-50:]
            },

            "pam_repeated_failures": {

                "total_events": len(
                    pam_repeated_failures
                ),

                "additional_failures": sum(
                    event.get(
                        "additional_failures",
                        0
                    )
                    for event in pam_repeated_failures
                )
            },

            "current_connections": {

                "total": len(
                    current_connections
                ),

                "connections": current_connections
            }
        },

        "attackers": {

            "unique_ips": len(
                attackers
            ),

            "top": attackers[:50]
        },

        "security_analysis": {

            "status": (
                "critical"
                if risk_level == "critical"
                else "warning"
                if risk_level in ("high", "medium")
                else "safe"
            ),

            "risk": risk_level,

            "failed_attempts": failed_count,

            "unique_attackers": len(
                attackers
            ),

            "root_attempts": len(
                root_attempts
            ),

            "active_ssh_connections": len(
                current_connections
            ),

            "problems": problems
        }
    }

    return result


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 60)
    print("SERVERGUARD SSH MONITOR")
    print("=" * 60)
    print()

    result = analyze_ssh()

    print(
        json.dumps(
            result,
            indent=4,
            ensure_ascii=False
        )
    )

    print()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()

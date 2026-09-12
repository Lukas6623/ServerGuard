#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
import sys
from datetime import datetime


SSH_CONFIG = "/etc/ssh/sshd_config"
BACKUP_DIR = "/opt/serverguard/backups"


RECOMMENDED = {
    "PermitEmptyPasswords": "no",
    "MaxAuthTries": "3",
    "LoginGraceTime": "30",
    "X11Forwarding": "no",
}


def run(command):
    result = subprocess.run(
        command,
        shell=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )

    return result.returncode, result.stdout.strip()


def ensure_root():
    if os.geteuid() != 0:
        print("ERROR: this script must be run as root.")
        sys.exit(1)


def ensure_backup_dir():
    os.makedirs(BACKUP_DIR, exist_ok=True)


def create_backup():
    ensure_backup_dir()

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    backup = os.path.join(
        BACKUP_DIR,
        f"sshd_config_{timestamp}"
    )

    shutil.copy2(
        SSH_CONFIG,
        backup
    )

    return backup


def read_config():
    try:
        with open(
            SSH_CONFIG,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as f:
            return f.read()

    except Exception as e:
        print(f"ERROR: cannot read SSH configuration: {e}")
        return ""


def get_setting(config, name):
    pattern = re.compile(
        rf"^\s*{re.escape(name)}\s+(.+?)\s*$",
        re.MULTILINE | re.IGNORECASE
    )

    matches = pattern.findall(config)

    if not matches:
        return "not set"

    return matches[-1].strip()


def print_report():
    config = read_config()

    if not config:
        return False

    print()
    print("============================================")
    print("           SSH HARDENING REPORT")
    print("============================================")
    print()

    for name in RECOMMENDED:
        value = get_setting(config, name)

        recommended = RECOMMENDED[name]

        if value.lower() == recommended.lower():
            status = "OK"
        else:
            status = "WARNING"

        print(
            f"{name:<24} {value:<15} [{status}]"
        )

    print()

    # Important authentication settings are displayed,
    # but are NOT automatically changed.
    root_login = get_setting(
        config,
        "PermitRootLogin"
    )

    password_auth = get_setting(
        config,
        "PasswordAuthentication"
    )

    print(
        f"{'PermitRootLogin':<24} "
        f"{root_login}"
    )

    print(
        f"{'PasswordAuthentication':<24} "
        f"{password_auth}"
    )

    print()

    return True


def set_setting(config, name, value):
    pattern = re.compile(
        rf"^(\s*)#?\s*{re.escape(name)}\s+.*$",
        re.MULTILINE | re.IGNORECASE
    )

    replacement = f"{name} {value}"

    if pattern.search(config):
        return pattern.sub(
            replacement,
            config
        )

    if not config.endswith("\n"):
        config += "\n"

    config += replacement + "\n"

    return config


def apply_hardening():
    print()
    print("============================================")
    print("          APPLYING SSH HARDENING")
    print("============================================")
    print()

    original = read_config()

    if not original:
        return False

    print("[1/5] Creating backup...")

    try:
        backup = create_backup()
    except Exception as e:
        print(f"ERROR: backup failed: {e}")
        return False

    print(f"Backup: {backup}")

    print()
    print("[2/5] Updating SSH configuration...")

    new_config = original

    for name, value in RECOMMENDED.items():
        new_config = set_setting(
            new_config,
            name,
            value
        )

    temporary = SSH_CONFIG + ".serverguard.tmp"

    try:
        with open(
            temporary,
            "w",
            encoding="utf-8"
        ) as f:
            f.write(new_config)

        os.chmod(
            temporary,
            0o644
        )

    except Exception as e:
        print(f"ERROR: cannot write configuration: {e}")

        try:
            os.remove(temporary)
        except OSError:
            pass

        return False

    print("Configuration prepared.")

    print()
    print("[3/5] Testing SSH configuration...")

    code, output = run(
        "sshd -t -f " +
        repr(temporary)
    )

    if code != 0:
        print()
        print("ERROR: sshd configuration test FAILED.")

        if output:
            print(output)

        try:
            os.remove(temporary)
        except OSError:
            pass

        print()
        print("Original configuration was not changed.")

        return False

    print("SSH configuration test: OK")

    print()
    print("[4/5] Installing configuration...")

    try:
        shutil.copy2(
            temporary,
            SSH_CONFIG
        )

        os.remove(
            temporary
        )

    except Exception as e:
        print(f"ERROR: installation failed: {e}")

        try:
            shutil.copy2(
                backup,
                SSH_CONFIG
            )
        except Exception:
            pass

        return False

    print("Configuration installed.")

    print()
    print("[5/5] Reloading SSH service...")

    code, output = run(
        "systemctl reload ssh"
    )

    if code != 0:
        print()
        print("ERROR: SSH reload failed.")

        if output:
            print(output)

        print()
        print("Restoring backup...")

        try:
            shutil.copy2(
                backup,
                SSH_CONFIG
            )

            run(
                "systemctl reload ssh"
            )

            print("Previous configuration restored.")

        except Exception as e:
            print(
                f"CRITICAL: rollback failed: {e}"
            )

        return False

    print("SSH service reloaded.")

    print()
    print("============================================")
    print("        SSH HARDENING COMPLETE")
    print("============================================")
    print()

    return True


def main():
    ensure_root()

    if len(sys.argv) < 2:
        print(
            "Usage: ssh_hardening.py "
            "[check|apply]"
        )
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "check":
        if not print_report():
            sys.exit(1)

    elif command == "apply":
        if not apply_hardening():
            sys.exit(1)

    else:
        print(
            "Unknown command."
        )

        print(
            "Use: check or apply"
        )

        sys.exit(1)


if __name__ == "__main__":
    main()

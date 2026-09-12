#!/usr/bin/env python3

import sys
import os
import shutil
import subprocess
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

SERVERGUARD_DIR = "/opt/serverguard"
BACKUP_DIR = os.path.join(SERVERGUARD_DIR, "backups")

HARDENING_CONFIG = "/etc/ssh/sshd_config.d/99-serverguard-hardening.conf"
MAIN_SSH_CONFIG = "/etc/ssh/sshd_config"

SSH_SERVICE_NAMES = [
    "ssh",
    "sshd"
]


# ============================================================
# COLORS
# ============================================================

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


# ============================================================
# COMMAND EXECUTION
# ============================================================

def run_command(command, check=False):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=check
        )

        return result.returncode, result.stdout, result.stderr

    except Exception as e:
        return 1, "", str(e)


# ============================================================
# ROOT CHECK
# ============================================================

def check_root():
    if os.geteuid() != 0:
        print(
            f"{RED}ERROR: This script must be run as root.{RESET}"
        )
        return False

    return True


# ============================================================
# CREATE DIRECTORIES
# ============================================================

def create_directories():
    try:
        os.makedirs(
            SERVERGUARD_DIR,
            exist_ok=True
        )

        os.makedirs(
            BACKUP_DIR,
            exist_ok=True
        )

        return True

    except Exception as e:
        print(
            f"{RED}Cannot create ServerGuard directories:{RESET}"
        )
        print(e)

        return False


# ============================================================
# SSH SERVICE
# ============================================================

def get_ssh_service():
    for service in SSH_SERVICE_NAMES:

        code, _, _ = run_command(
            [
                "systemctl",
                "is-enabled",
                service
            ]
        )

        if code == 0:
            return service

        code, _, _ = run_command(
            [
                "systemctl",
                "cat",
                service
            ]
        )

        if code == 0:
            return service

    return None


# ============================================================
# CHECK SSH SERVICE
# ============================================================

def check_ssh_service():
    service = get_ssh_service()

    if service is None:
        print(
            f"{RED}SSH service not found.{RESET}"
        )
        return False

    code, stdout, _ = run_command(
        [
            "systemctl",
            "is-active",
            service
        ]
    )

    status = stdout.strip()

    if status == "active":
        print(
            f"{GREEN}SSH service: ACTIVE{RESET}"
        )
        return True

    print(
        f"{YELLOW}SSH service: "
        f"{status or 'UNKNOWN'}{RESET}"
    )

    return False


# ============================================================
# BACKUP MAIN CONFIGURATION
# ============================================================

def backup_main_config():

    if not os.path.exists(MAIN_SSH_CONFIG):

        print(
            f"{RED}Main SSH configuration does not exist:{RESET} "
            f"{MAIN_SSH_CONFIG}"
        )

        return None

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    backup_file = os.path.join(
        BACKUP_DIR,
        f"sshd_config_{timestamp}.backup"
    )

    try:

        shutil.copy2(
            MAIN_SSH_CONFIG,
            backup_file
        )

        print(
            f"{GREEN}Main SSH configuration backed up:{RESET}"
        )

        print(backup_file)

        return backup_file

    except Exception as e:

        print(
            f"{RED}Cannot create SSH configuration backup:{RESET}"
        )

        print(e)

        return None


# ============================================================
# BACKUP SERVERGUARD HARDENING CONFIG
# ============================================================

def backup_hardening_config():

    if not os.path.exists(HARDENING_CONFIG):
        return None

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    backup_file = os.path.join(
        BACKUP_DIR,
        f"99-serverguard-hardening_{timestamp}.backup"
    )

    try:

        shutil.copy2(
            HARDENING_CONFIG,
            backup_file
        )

        print(
            f"{GREEN}Current ServerGuard hardening "
            f"configuration backed up:{RESET}"
        )

        print(backup_file)

        return backup_file

    except Exception as e:

        print(
            f"{RED}Cannot backup hardening configuration:{RESET}"
        )

        print(e)

        return None


# ============================================================
# CREATE HARDENING CONFIG
# ============================================================

def create_hardening_config():

    print()
    print(
        "Creating ServerGuard SSH hardening configuration..."
    )
    print()

    config = """# ============================================================
# ServerGuard SSH Hardening
# ============================================================
#
# This file is managed by ServerGuard.
#
# Generated automatically.
# ============================================================

# Do not allow empty passwords
PermitEmptyPasswords no

# Disable X11 forwarding
X11Forwarding no

# Disable TCP forwarding
AllowTcpForwarding no

# Disable SSH agent forwarding
AllowAgentForwarding no

# Limit authentication attempts
MaxAuthTries 3

# Give clients limited time to authenticate
LoginGraceTime 30

# Disable SSH compression
Compression no

# Do not allow root password login
# Root SSH keys remain available.
PermitRootLogin prohibit-password
"""

    try:

        os.makedirs(
            os.path.dirname(HARDENING_CONFIG),
            exist_ok=True
        )

        with open(
            HARDENING_CONFIG,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(config)

        os.chmod(
            HARDENING_CONFIG,
            0o644
        )

        print(
            f"{GREEN}Hardening configuration created:{RESET}"
        )

        print(HARDENING_CONFIG)

        return True

    except Exception as e:

        print(
            f"{RED}Cannot create hardening configuration:{RESET}"
        )

        print(e)

        return False


# ============================================================
# SSH CONFIGURATION TEST
# ============================================================

def validate_ssh_config():

    print()
    print(
        "Validating SSH configuration..."
    )
    print()

    code, stdout, stderr = run_command(
        [
            "sshd",
            "-t"
        ]
    )

    if code == 0:

        print(
            f"{GREEN}SSH configuration is VALID.{RESET}"
        )

        return True

    print(
        f"{RED}SSH configuration is INVALID!{RESET}"
    )

    if stderr:
        print(stderr)

    if stdout:
        print(stdout)

    return False


# ============================================================
# RELOAD SSH
# ============================================================

def reload_ssh():

    service = get_ssh_service()

    if service is None:

        print(
            f"{RED}Cannot find SSH service.{RESET}"
        )

        return False

    print()
    print(
        f"Reloading SSH service: {service}"
    )

    code, stdout, stderr = run_command(
        [
            "systemctl",
            "reload",
            service
        ]
    )

    if code == 0:

        print(
            f"{GREEN}SSH service reloaded successfully.{RESET}"
        )

        return True

    print(
        f"{RED}Failed to reload SSH service.{RESET}"
    )

    if stderr:
        print(stderr)

    if stdout:
        print(stdout)

    return False


# ============================================================
# SHOW CURRENT SSH CONFIG
# ============================================================

def get_effective_config():

    code, stdout, stderr = run_command(
        [
            "sshd",
            "-T"
        ]
    )

    if code != 0:

        print(
            f"{RED}Cannot read effective SSH configuration.{RESET}"
        )

        if stderr:
            print(stderr)

        return None

    return stdout


# ============================================================
# GET SPECIFIC SSH VALUE
# ============================================================

def get_config_value(config, name):

    name = name.lower()

    for line in config.splitlines():

        line = line.strip()

        if not line:
            continue

        parts = line.split(None, 1)

        if len(parts) != 2:
            continue

        key = parts[0].lower()

        if key == name:
            return parts[1].strip()

    return "unknown"


# ============================================================
# CHECK WHETHER VALUE MATCHES
# ============================================================

def value_matches(actual, expected):

    actual = actual.strip().lower()
    expected = expected.strip().lower()

    # OpenSSH may report:
    #
    # without-password
    #
    # instead of:
    #
    # prohibit-password
    #
    # They have the same security meaning for root:
    # root password authentication is disabled,
    # but public-key authentication remains possible.

    if expected == "prohibit-password":

        return actual in [
            "prohibit-password",
            "without-password"
        ]

    return actual == expected


# ============================================================
# CHECK HARDENING
# ============================================================

def check_hardening():

    print()
    print("============================================")
    print("       SERVERGUARD SSH CONFIGURATION")
    print("============================================")
    print()

    if not os.path.exists(HARDENING_CONFIG):

        print(
            f"{YELLOW}"
            f"ServerGuard hardening: NOT INSTALLED"
            f"{RESET}"
        )

        return False

    config = get_effective_config()

    if config is None:
        return False

    settings = [
        ("PermitRootLogin", "prohibit-password"),
        ("PasswordAuthentication", None),
        ("PubkeyAuthentication", None),
        ("PermitEmptyPasswords", "no"),
        ("MaxAuthTries", "3"),
        ("LoginGraceTime", "30"),
        ("X11Forwarding", "no"),
        ("AllowTcpForwarding", "no"),
        ("AllowAgentForwarding", "no"),
        ("Compression", "no")
    ]

    all_good = True

    for name, expected in settings:

        value = get_config_value(
            config,
            name
        )

        if expected is not None:

            if value_matches(
                value,
                expected
            ):

                print(
                    f"{GREEN}[OK]{RESET} "
                    f"{name}: {value}"
                )

            else:

                print(
                    f"{RED}[FAIL]{RESET} "
                    f"{name}: {value} "
                    f"(expected {expected})"
                )

                all_good = False

        else:

            print(
                f"{CYAN}[INFO]{RESET} "
                f"{name}: {value}"
            )

    print()

    if all_good:

        print(
            f"{GREEN}"
            f"ServerGuard hardening: ENABLED"
            f"{RESET}"
        )

    else:

        print(
            f"{YELLOW}"
            f"ServerGuard hardening: PARTIALLY APPLIED"
            f"{RESET}"
        )

    return all_good


# ============================================================
# REMOVE SERVERGUARD HARDENING CONFIGURATION
# ============================================================

def remove_hardening_config():

    if not os.path.exists(HARDENING_CONFIG):
        return True

    try:

        os.remove(
            HARDENING_CONFIG
        )

        return True

    except Exception as e:

        print(
            f"{RED}"
            f"Cannot remove ServerGuard hardening configuration:"
            f"{RESET}"
        )

        print(e)

        return False


# ============================================================
# APPLY HARDENING
# ============================================================

def apply_hardening():

    print()
    print("============================================")
    print("          APPLYING SSH HARDENING")
    print("============================================")
    print()

    if not check_root():
        return False

    if not create_directories():
        return False

    # --------------------------------------------------------
    # Backup main SSH configuration
    # --------------------------------------------------------

    backup = backup_main_config()

    if backup is None:

        print(
            f"{RED}"
            f"Hardening cancelled because backup failed."
            f"{RESET}"
        )

        return False

    # --------------------------------------------------------
    # Backup previous ServerGuard configuration
    # --------------------------------------------------------

    backup_hardening_config()

    # --------------------------------------------------------
    # Create configuration
    # --------------------------------------------------------

    if not create_hardening_config():
        return False

    # --------------------------------------------------------
    # Validate SSH configuration
    # --------------------------------------------------------

    if not validate_ssh_config():

        print()
        print(
            f"{RED}"
            f"SSH configuration became invalid."
            f"{RESET}"
        )

        print(
            "Removing ServerGuard hardening configuration..."
        )

        remove_hardening_config()

        print(
            f"{YELLOW}"
            f"Hardening was rolled back."
            f"{RESET}"
        )

        return False

    # --------------------------------------------------------
    # Reload SSH
    # --------------------------------------------------------

    if not reload_ssh():

        print()
        print(
            f"{RED}"
            f"SSH reload failed."
            f"{RESET}"
        )

        print(
            "Removing ServerGuard hardening configuration..."
        )

        remove_hardening_config()

        return False

    # --------------------------------------------------------
    # Final check
    # --------------------------------------------------------

    print()
    print(
        "Checking effective SSH configuration..."
    )

    success = check_hardening()

    if not success:

        print()
        print(
            f"{YELLOW}"
            f"Warning: not all hardening settings "
            f"are active."
            f"{RESET}"
        )

        print()
        print(
            "ServerGuard hardening was not fully applied."
        )

        return False

    print()
    print(
        f"{GREEN}"
        f"============================================"
        f"{RESET}"
    )

    print(
        f"{GREEN}"
        f"      SSH HARDENING APPLIED SUCCESSFULLY"
        f"{RESET}"
    )

    print(
        f"{GREEN}"
        f"============================================"
        f"{RESET}"
    )

    print()

    return True


# ============================================================
# LIST BACKUPS
# ============================================================

def list_backups():

    print()
    print("============================================")
    print("           SSH CONFIGURATION BACKUPS")
    print("============================================")
    print()

    if not os.path.exists(BACKUP_DIR):

        print(
            f"{YELLOW}"
            f"Backup directory does not exist."
            f"{RESET}"
        )

        return

    files = []

    try:

        for filename in os.listdir(BACKUP_DIR):

            path = os.path.join(
                BACKUP_DIR,
                filename
            )

            if os.path.isfile(path):
                files.append(filename)

    except Exception as e:

        print(
            f"{RED}"
            f"Cannot read backup directory:"
            f"{RESET}"
        )

        print(e)

        return

    files.sort(reverse=True)

    if not files:

        print("No backups found.")

        return

    for index, filename in enumerate(
        files,
        1
    ):

        print(
            f"{index}. {filename}"
        )

    print()


# ============================================================
# RESTORE FROM MENU
# ============================================================

def restore_configuration():

    print()
    print("============================================")
    print("          RESTORE SSH CONFIGURATION")
    print("============================================")
    print()

    if not check_root():
        return False

    if not os.path.exists(BACKUP_DIR):

        print(
            f"{YELLOW}"
            f"No backup directory found."
            f"{RESET}"
        )

        return False

    files = []

    for filename in os.listdir(BACKUP_DIR):

        path = os.path.join(
            BACKUP_DIR,
            filename
        )

        if os.path.isfile(path):
            files.append(filename)

    files.sort(reverse=True)

    if not files:

        print(
            f"{YELLOW}"
            f"No backups found."
            f"{RESET}"
        )

        return False

    for index, filename in enumerate(
        files,
        1
    ):

        print(
            f"{index}. {filename}"
        )

    print()
    print(
        "Enter backup number or 0 to cancel:"
    )

    choice = input("> ").strip()

    if choice == "0":
        return False

    try:

        index = int(choice) - 1

        if index < 0 or index >= len(files):

            print(
                f"{RED}"
                f"Invalid backup number."
                f"{RESET}"
            )

            return False

    except ValueError:

        print(
            f"{RED}"
            f"Invalid input."
            f"{RESET}"
        )

        return False

    selected = files[index]

    backup_path = os.path.join(
        BACKUP_DIR,
        selected
    )

    print()
    print(
        f"Selected backup: {selected}"
    )

    # --------------------------------------------------------
    # Only restore main sshd_config backups
    # --------------------------------------------------------

    if not selected.startswith(
        "sshd_config_"
    ):

        print(
            f"{RED}"
            f"This backup is not a main sshd_config backup."
            f"{RESET}"
        )

        print(
            "ServerGuard hardening configuration is stored "
            "separately in:"
        )

        print(
            HARDENING_CONFIG
        )

        return False

    # --------------------------------------------------------
    # Emergency backup
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    emergency_backup = os.path.join(
        BACKUP_DIR,
        f"before_restore_{timestamp}.backup"
    )

    try:

        shutil.copy2(
            MAIN_SSH_CONFIG,
            emergency_backup
        )

    except Exception as e:

        print(
            f"{RED}"
            f"Cannot create emergency backup:"
            f"{RESET}"
        )

        print(e)

        return False

    # --------------------------------------------------------
    # Restore
    # --------------------------------------------------------

    try:

        shutil.copy2(
            backup_path,
            MAIN_SSH_CONFIG
        )

    except Exception as e:

        print(
            f"{RED}"
            f"Restore failed:"
            f"{RESET}"
        )

        print(e)

        return False

    # --------------------------------------------------------
    # Validate restored configuration
    # --------------------------------------------------------

    if not validate_ssh_config():

        print()
        print(
            f"{RED}"
            f"Restored configuration is INVALID."
            f"{RESET}"
        )

        print(
            "Returning previous configuration..."
        )

        try:

            shutil.copy2(
                emergency_backup,
                MAIN_SSH_CONFIG
            )

        except Exception as e:

            print(
                f"{RED}"
                f"Emergency rollback failed:"
                f"{RESET}"
            )

            print(e)

        return False

    # --------------------------------------------------------
    # Reload SSH
    # --------------------------------------------------------

    if not reload_ssh():

        print(
            f"{RED}"
            f"SSH reload failed."
            f"{RESET}"
        )

        return False

    print()
    print(
        f"{GREEN}"
        f"Configuration restored successfully."
        f"{RESET}"
    )

    return True


# ============================================================
# COMMAND: CHECK
# ============================================================

def command_check():

    check_ssh_service()

    check_hardening()


# ============================================================
# COMMAND: APPLY
# ============================================================

def command_apply():

    return apply_hardening()


# ============================================================
# COMMAND: RESTORE
# ============================================================

def command_restore():

    if len(sys.argv) < 3:

        print(
            "Usage: ssh_hardening.py restore <backup_file>"
        )

        return False

    backup_name = sys.argv[2]

    # --------------------------------------------------------
    # Security: prevent path traversal
    # --------------------------------------------------------

    if "/" in backup_name or "\\" in backup_name:

        print(
            f"{RED}"
            f"Invalid backup filename."
            f"{RESET}"
        )

        return False

    if ".." in backup_name:

        print(
            f"{RED}"
            f"Invalid backup filename."
            f"{RESET}"
        )

        return False

    backup_path = os.path.join(
        BACKUP_DIR,
        backup_name
    )

    if not os.path.isfile(backup_path):

        print(
            f"{RED}"
            f"Backup file not found:"
            f"{RESET}"
        )

        print(backup_path)

        return False

    # --------------------------------------------------------
    # Only allow known ServerGuard backup types
    # --------------------------------------------------------

    if not (
        backup_name.startswith("sshd_config_")
        or
        backup_name.startswith("before_restore_")
    ):

        print(
            f"{RED}"
            f"Unsupported backup type."
            f"{RESET}"
        )

        return False

    # --------------------------------------------------------
    # Emergency backup before restore
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    emergency_backup = os.path.join(
        BACKUP_DIR,
        f"before_restore_{timestamp}.backup"
    )

    try:

        shutil.copy2(
            MAIN_SSH_CONFIG,
            emergency_backup
        )

    except Exception as e:

        print(
            f"{RED}"
            f"Cannot create emergency backup:"
            f"{RESET}"
        )

        print(e)

        return False

    # --------------------------------------------------------
    # Restore
    # --------------------------------------------------------

    try:

        shutil.copy2(
            backup_path,
            MAIN_SSH_CONFIG
        )

    except Exception as e:

        print(
            f"{RED}"
            f"Restore failed:"
            f"{RESET}"
        )

        print(e)

        return False

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    if not validate_ssh_config():

        print(
            f"{RED}"
            f"Restored configuration is invalid."
            f"{RESET}"
        )

        print(
            "Rolling back to previous configuration..."
        )

        try:

            shutil.copy2(
                emergency_backup,
                MAIN_SSH_CONFIG
            )

        except Exception as e:

            print(
                f"{RED}"
                f"Emergency rollback failed:"
                f"{RESET}"
            )

            print(e)

        return False

    # --------------------------------------------------------
    # Reload
    # --------------------------------------------------------

    if not reload_ssh():

        print(
            f"{RED}"
            f"SSH reload failed."
            f"{RESET}"
        )

        return False

    print(
        f"{GREEN}"
        f"Backup restored successfully."
        f"{RESET}"
    )

    return True


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) < 2:

        print()
        print(
            "Usage: ssh_hardening.py "
            "[check|apply|restore]"
        )
        print()

        return 1

    command = sys.argv[1].lower()

    if command == "check":

        command_check()

        return 0

    if command == "apply":

        success = command_apply()

        return 0 if success else 1

    if command == "restore":

        success = command_restore()

        return 0 if success else 1

    print(
        f"{RED}"
        f"Unknown command: {command}"
        f"{RESET}"
    )

    print()
    print(
        "Usage: ssh_hardening.py "
        "[check|apply|restore]"
    )

    return 1


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    sys.exit(main())

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
        print(f"{RED}ERROR: This script must be run as root.{RESET}")
        return False

    return True


# ============================================================
# CREATE DIRECTORIES
# ============================================================

def create_directories():
    try:
        os.makedirs(SERVERGUARD_DIR, exist_ok=True)
        os.makedirs(BACKUP_DIR, exist_ok=True)

        return True

    except Exception as e:
        print(f"{RED}Cannot create ServerGuard directories:{RESET}")
        print(e)

        return False


# ============================================================
# SSH SERVICE
# ============================================================

def get_ssh_service():
    for service in SSH_SERVICE_NAMES:

        code, _, _ = run_command(
            ["systemctl", "status", service]
        )

        if code == 0:
            return service

        code, _, _ = run_command(
            ["systemctl", "cat", service]
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
        print(f"{RED}SSH service not found.{RESET}")
        return False

    code, stdout, _ = run_command(
        ["systemctl", "is-active", service]
    )

    status = stdout.strip()

    if status == "active":
        print(f"{GREEN}SSH service: ACTIVE{RESET}")
        return True

    print(
        f"{YELLOW}SSH service: {status or 'UNKNOWN'}{RESET}"
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

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

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

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

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
            f"{GREEN}Current ServerGuard hardening configuration "
            f"backed up:{RESET}"
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
    print("Creating ServerGuard SSH hardening configuration...")
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
    print("Validating SSH configuration...")
    print()

    code, stdout, stderr = run_command(
        ["sshd", "-t"]
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
        ["systemctl", "reload", service]
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
        ["sshd", "-T"]
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
            f"{YELLOW}ServerGuard hardening: NOT INSTALLED{RESET}"
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

            if value.lower() == expected.lower():

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
            f"{GREEN}ServerGuard hardening: ENABLED{RESET}"
        )

    else:

        print(
            f"{YELLOW}ServerGuard hardening: "
            f"PARTIALLY APPLIED{RESET}"
        )

    return all_good


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
            f"{RED}Hardening cancelled because backup failed.{RESET}"
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
    # Validate
    # --------------------------------------------------------

    if not validate_ssh_config():

        print()
        print(
            f"{RED}SSH configuration became invalid.{RESET}"
        )

        print(
            "Removing ServerGuard hardening configuration..."
        )

        try:
            if os.path.exists(HARDENING_CONFIG):
                os.remove(HARDENING_CONFIG)

        except Exception:
            pass

        print(
            f"{YELLOW}Hardening was rolled back.{RESET}"
        )

        return False

    # --------------------------------------------------------
    # Reload SSH
    # --------------------------------------------------------

    if not reload_ssh():

        print()
        print(
            f"{RED}SSH reload failed.{RESET}"
        )

        print(
            "Removing ServerGuard hardening configuration..."
        )

        try:
            if os.path.exists(HARDENING_CONFIG):
                os.remove(HARDENING_CONFIG)

        except Exception:
            pass

        return False

    # --------------------------------------------------------
    # Final check
    # --------------------------------------------------------

    print()
    print("Checking effective SSH configuration...")

    if not check_hardening():

        print()
        print(
            f"{YELLOW}Warning: not all hardening settings "
            f"are active.{RESET}"
        )

        return False

    print()
    print(
        f"{GREEN}============================================{RESET}"
    )

    print(
        f"{GREEN}      SSH HARDENING APPLIED SUCCESSFULLY{RESET}"
    )

    print(
        f"{GREEN}============================================{RESET}"
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
            f"{YELLOW}Backup directory does not exist.{RESET}"
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
            f"{RED}Cannot read backup directory:{RESET}"
        )

        print(e)

        return

    files.sort(reverse=True)

    if not files:

        print("No backups found.")

        return

    for index, filename in enumerate(files, 1):

        print(
            f"{index}. {filename}"
        )

    print()


# ============================================================
# RESTORE
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
            f"{YELLOW}No backup directory found.{RESET}"
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
            f"{YELLOW}No backups found.{RESET}"
        )

        return False

    for index, filename in enumerate(files, 1):

        print(
            f"{index}. {filename}"
        )

    print()
    print("Enter backup number or 0 to cancel:")

    choice = input("> ").strip()

    if choice == "0":
        return False

    try:
        index = int(choice) - 1

        if index < 0 or index >= len(files):
            print(
                f"{RED}Invalid backup number.{RESET}"
            )

            return False

    except ValueError:

        print(
            f"{RED}Invalid input.{RESET}"
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
    # Only restore main sshd_config backups here.
    # --------------------------------------------------------

    if not selected.startswith("sshd_config_"):

        print(
            f"{RED}This backup is not a main sshd_config backup.{RESET}"
        )

        print(
            "Use the ServerGuard hardening configuration "
            "management for its own drop-in file."
        )

        return False

    # --------------------------------------------------------
    # Create temporary backup of current config
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
            f"{RED}Cannot create emergency backup:{RESET}"
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
            f"{RED}Restore failed:{RESET}"
        )

        print(e)

        return False

    # --------------------------------------------------------
    # Validate restored configuration
    # --------------------------------------------------------

    if not validate_ssh_config():

        print()
        print(
            f"{RED}Restored configuration is INVALID.{RESET}"
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
                f"{RED}Emergency rollback failed:{RESET}"
            )

            print(e)

        return False

    # --------------------------------------------------------
    # Reload SSH
    # --------------------------------------------------------

    if not reload_ssh():

        print(
            f"{RED}SSH reload failed.{RESET}"
        )

        return False

    print()
    print(
        f"{GREEN}Configuration restored successfully.{RESET}"
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

    # Security: don't allow path traversal
    if "/" in backup_name or "\\" in backup_name:
        print(
            f"{RED}Invalid backup filename.{RESET}"
        )

        return False

    if ".." in backup_name:
        print(
            f"{RED}Invalid backup filename.{RESET}"
        )

        return False

    backup_path = os.path.join(
        BACKUP_DIR,
        backup_name
    )

    if not os.path.isfile(backup_path):

        print(
            f"{RED}Backup file not found:{RESET}"
        )

        print(backup_path)

        return False

    try:

        shutil.copy2(
            backup_path,
            MAIN_SSH_CONFIG
        )

    except Exception as e:

        print(
            f"{RED}Restore failed:{RESET}"
        )

        print(e)

        return False

    if not validate_ssh_config():

        print(
            f"{RED}Restored configuration is invalid.{RESET}"
        )

        return False

    if not reload_ssh():

        return False

    print(
        f"{GREEN}Backup restored successfully.{RESET}"
    )

    return True


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) < 2:

        print()
        print(
            "Usage: ssh_hardening.py [check|apply|restore]"
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
        f"{RED}Unknown command: {command}{RESET}"
    )

    print()
    print(
        "Usage: ssh_hardening.py [check|apply|restore]"
    )

    return 1


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    sys.exit(main())

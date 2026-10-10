#!/usr/bin/env python3
"""
ServerGuard SSH Hardening - Advanced
Compatible with Ubuntu and Debian. Requires Python 3.8+.

Commands:
  check                    Read-only SSH/Fail2ban/key audit
  apply                    Apply conservative SSH hardening (keeps password auth unchanged)
  disable                  Remove the ServerGuard SSH drop-in (with backup and validation)
  restore [BACKUP_NAME]    Restore a pre-hardening backup; interactive if omitted
  keys                     Audit authorized_keys files without changing them
  fail2ban                 Report Fail2ban SSH jail status
  fail2ban-setup           Install and configure Fail2ban SSH protection
  audit                    Compare current SSH config files with last audit baseline
  audit-install            Install a periodic systemd audit timer (optional Telegram alerts)

Telegram notifications are configured via:
  /etc/serverguard/telegram.env  (root-owned, mode 600)
  TELEGRAM_BOT_TOKEN=...
  TELEGRAM_CHAT_ID=...

Safety notes:
- Does not change SSH port, firewall, AllowUsers, root-login policy, or password auth.
- Never deletes keys.
- Backups include SSH config files, metadata, and a manifest; restore is validated before reload.
- Audit is best-effort: root can tamper with local files; use remote logging for stronger assurance.
"""

import sys

if sys.version_info < (3, 8):
    sys.stderr.write("ERROR: ServerGuard SSH Hardening requires Python 3.8 or newer.\n")
    sys.exit(1)

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SERVERGUARD_DIR = Path("/opt/serverguard")
BACKUP_DIR = SERVERGUARD_DIR / "backups"
STATE_DIR = SERVERGUARD_DIR / "ssh-hardening"
BASELINE_FILE = STATE_DIR / "ssh-config-baseline.json"
LAST_ALERT_FILE = STATE_DIR / "last-alert-hash.txt"
AUDIT_LOG = STATE_DIR / "audit.log"
HARDENING_CONFIG = Path("/etc/ssh/sshd_config.d/99-serverguard-hardening.conf")
MAIN_SSH_CONFIG = Path("/etc/ssh/sshd_config")
SSH_DIR = Path("/etc/ssh")
TELEGRAM_ENV = Path("/etc/serverguard/telegram.env")
SYSTEMD_DIR = Path("/etc/systemd/system")
AUDIT_SERVICE = SYSTEMD_DIR / "serverguard-ssh-audit.service"
AUDIT_TIMER = SYSTEMD_DIR / "serverguard-ssh-audit.timer"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Conservative hardening only. PasswordAuthentication and root access are
# intentionally left unchanged to avoid locking out existing administrators.
HARDENING_SETTINGS = {
    "PermitEmptyPasswords": "no",
    "X11Forwarding": "no",
    "AllowAgentForwarding": "no",
    "MaxAuthTries": "3",
    "LoginGraceTime": "30",
    "Compression": "no",
}

SSH_SERVICE_NAMES = ("ssh", "sshd")


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def log(message, color=None):
    prefix = f"{color}" if color else ""
    suffix = RESET if color else ""
    print(f"{prefix}{message}{suffix}")


def run_command(command, timeout=20, env=None):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"Command not found: {command[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out: {' '.join(command)}"
    except Exception as exc:
        return 1, "", str(exc)


def require_root():
    if os.geteuid() != 0:
        log("ERROR: run this command as root (sudo).", RED)
        return False
    return True


def ensure_dirs():
    # /opt/serverguard stays traversable (755) so the ServerGuard client can
    # test for the script as a normal user; backups and state remain root-only.
    try:
        for directory, mode in (
            (SERVERGUARD_DIR, 0o755),
            (BACKUP_DIR, 0o700),
            (STATE_DIR, 0o700),
        ):
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, mode)
        return True
    except OSError as exc:
        log(f"Cannot create ServerGuard directories: {exc}", RED)
        return False


def get_sshd_binary():
    for candidate in ("/usr/sbin/sshd", "/sbin/sshd"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("sshd")


def get_ssh_service():
    for service in SSH_SERVICE_NAMES:
        code, out, _err = run_command(["systemctl", "show", "-p", "LoadState", "--value", service])
        if code == 0 and out.strip() == "loaded":
            return service
        code, _, _ = run_command(["systemctl", "cat", service])
        if code == 0:
            return service
    return None


def ssh_service_status():
    service = get_ssh_service()
    if not service:
        return None, "not-found"
    code, out, err = run_command(["systemctl", "is-active", service])
    return service, out or err or "unknown"


def list_ssh_config_files():
    paths = []
    if MAIN_SSH_CONFIG.exists():
        paths.append(MAIN_SSH_CONFIG)
    config_dir = SSH_DIR / "sshd_config.d"
    if config_dir.is_dir():
        try:
            paths.extend(sorted(p for p in config_dir.glob("*.conf") if p.is_file()))
        except OSError:
            pass
    # Only files directly referenced by the conventional Debian/Ubuntu include
    # directory are snapshotted. sshd -T validates the effective configuration.
    return paths


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_config():
    snapshot = {}
    for path in list_ssh_config_files():
        try:
            info = path.stat()
            snapshot[str(path)] = {
                "sha256": sha256_file(path),
                "mode": stat.S_IMODE(info.st_mode),
                "uid": info.st_uid,
                "gid": info.st_gid,
                "size": info.st_size,
            }
        except OSError as exc:
            snapshot[str(path)] = {"error": str(exc)}
    return snapshot


def write_json_atomic(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2, sort_keys=True)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def append_audit_log(event, details=None):
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        record = {"time": now_iso(), "event": event, "details": details or {}}
        fd = os.open(str(AUDIT_LOG), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as file:
            file.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError as exc:
        log(f"Warning: could not write audit log: {exc}", YELLOW)


def backup_configs(label="pre-change"):
    if not ensure_dirs():
        return None
    files = list_ssh_config_files()
    if not files:
        log("No SSH configuration files found; refusing to make a backup.", RED)
        return None

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"{label}_{stamp}.tar.gz"
    backup_path = BACKUP_DIR / backup_name
    manifest = {
        "created_at": now_iso(),
        "label": label,
        "files": [],
    }

    try:
        with tarfile.open(backup_path, "w:gz") as archive:
            for path in files:
                if not path.exists() or not path.is_file():
                    continue
                archive.add(path, arcname=str(path).lstrip("/"), recursive=False)
                info = path.stat()
                manifest["files"].append({
                    "path": str(path),
                    "archive_name": str(path).lstrip("/"),
                    "sha256": sha256_file(path),
                    "mode": stat.S_IMODE(info.st_mode),
                    "uid": info.st_uid,
                    "gid": info.st_gid,
                })
        manifest_path = BACKUP_DIR / f"{backup_name}.json"
        write_json_atomic(manifest_path, manifest)
        os.chmod(backup_path, 0o600)
        log(f"Backup created: {backup_path}", GREEN)
        return backup_name
    except Exception as exc:
        try:
            backup_path.unlink(missing_ok=True)
        except OSError:
            pass
        log(f"Backup failed; changes cancelled: {exc}", RED)
        return None


def validate_sshd_config():
    binary = get_sshd_binary()
    if not binary:
        log("sshd binary not found. Install openssh-server before applying hardening.", RED)
        return False
    code, out, err = run_command([binary, "-t"])
    if code == 0:
        log("sshd -t: configuration syntax is valid.", GREEN)
        return True
    log("sshd -t: configuration is INVALID.", RED)
    if err:
        log(err, RED)
    if out:
        log(out, RED)
    return False


def effective_config():
    binary = get_sshd_binary()
    if not binary:
        return None
    code, out, err = run_command([binary, "-T"])
    if code != 0:
        log(f"Cannot read effective sshd configuration: {err or out}", RED)
        return None
    values = {}
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            values[parts[0].lower()] = parts[1].strip()
    return values


def check_effective_settings():
    values = effective_config()
    if values is None:
        return False
    all_good = True
    log("\nEffective SSH security settings:")
    for key, expected in HARDENING_SETTINGS.items():
        actual = values.get(key.lower(), "unknown")
        good = actual.lower() == expected.lower()
        log(f"[{'OK' if good else 'FAIL'}] {key}: {actual} (expected {expected})",
            GREEN if good else RED)
        all_good &= good

    if not all_good and HARDENING_CONFIG.exists():
        log("Hint: make sure /etc/ssh/sshd_config contains "
            "'Include /etc/ssh/sshd_config.d/*.conf' and that no earlier "
            "file overrides these keys (sshd uses the first value it reads).", YELLOW)

    # Informational only: the module intentionally does not disable password
    # authentication in the default apply mode.
    for key in ("passwordauthentication", "kbdinteractiveauthentication",
                "pubkeyauthentication", "permitrootlogin", "port"):
        log(f"[INFO] {key}: {values.get(key, 'unknown')}", CYAN)

    return bool(all_good)


def check_hardening_file():
    if not HARDENING_CONFIG.exists():
        log("ServerGuard drop-in: NOT INSTALLED", YELLOW)
        return False
    try:
        text = HARDENING_CONFIG.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log(f"Cannot read {HARDENING_CONFIG}: {exc}", RED)
        return False
    parsed = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            parsed[parts[0].lower()] = parts[1].strip()
    missing = []
    for key, expected in HARDENING_SETTINGS.items():
        if parsed.get(key.lower(), "").lower() != expected.lower():
            missing.append(f"{key}={expected}")
    if missing:
        log("ServerGuard drop-in: PRESENT BUT SETTINGS MISMATCH: " + ", ".join(missing), YELLOW)
        return False
    log("ServerGuard drop-in: present with expected directives.", GREEN)
    return True


def authorized_keys_audit():
    log("\nSSH authorized_keys audit:")
    try:
        import pwd
    except ImportError:
        log("Cannot import pwd; key audit unavailable.", YELLOW)
        return False

    found_any = False
    issues = []
    for account in pwd.getpwall():
        if account.pw_uid != 0 and account.pw_uid < 1000:
            continue
        home = Path(account.pw_dir) if account.pw_dir else None
        try:
            if not home or not home.is_absolute() or not home.is_dir():
                continue
            key_file = home / ".ssh" / "authorized_keys"
            if not key_file.is_file():
                continue
        except OSError:
            continue
        found_any = True
        try:
            info = key_file.stat()
            mode = stat.S_IMODE(info.st_mode)
            log(f"- {account.pw_name}: {key_file} (mode {mode:04o}, owner uid {info.st_uid})")
            if info.st_uid != account.pw_uid:
                issues.append(f"{key_file}: owner uid {info.st_uid}, expected {account.pw_uid}")
            if mode & 0o022:
                issues.append(f"{key_file}: group/other writable permissions")
            seen = set()
            with key_file.open("r", encoding="utf-8", errors="replace") as file:
                for line_no, line in enumerate(file, 1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    match = re.search(
                        r"\b(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+|"
                        r"sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)"
                        r"\s+([A-Za-z0-9+/=]+)", stripped)
                    if not match:
                        issues.append(f"{key_file}:{line_no}: unrecognized key format; inspect manually")
                        continue
                    identity = (match.group(1), match.group(2))
                    if identity in seen:
                        issues.append(f"{key_file}:{line_no}: duplicate public key")
                    seen.add(identity)
                    if match.group(1) == "ssh-rsa":
                        log(f"  [REVIEW] line {line_no}: RSA key; confirm key length and policy.", YELLOW)
        except OSError as exc:
            issues.append(f"{key_file}: cannot inspect: {exc}")
    if not found_any:
        log("No authorized_keys files found for inspected accounts.", YELLOW)
    if issues:
        for issue in issues:
            log(f"[WARN] {issue}", YELLOW)
        return False
    log("No basic ownership/permission/duplicate issues detected.", GREEN)
    log("Note: this does not cryptographically prove that a key works for SSH login.", CYAN)
    return True


def get_fail2ban_status():
    if not shutil.which("fail2ban-client"):
        log("Fail2ban: NOT INSTALLED", YELLOW)
        return False
    code, out, err = run_command(["fail2ban-client", "status"])
    if code != 0:
        log(f"Fail2ban is installed but unavailable/not running: {err or out}", YELLOW)
        return False
    log("Fail2ban daemon status:", GREEN)
    log(out)
    code, jail_out, jail_err = run_command(["fail2ban-client", "status", "sshd"])
    if code == 0:
        log("SSH jail status:", GREEN)
        log(jail_out)
        return True
    log(f"SSH jail 'sshd' is not active or not configured: {jail_err or jail_out}", YELLOW)
    return False


def read_telegram_env():
    if not TELEGRAM_ENV.is_file():
        return None, None
    try:
        info = TELEGRAM_ENV.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
            log(f"Telegram env file must be root-owned and mode 600: {TELEGRAM_ENV}", YELLOW)
            return None, None
        values = {}
        for line in TELEGRAM_ENV.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
        return values.get("TELEGRAM_BOT_TOKEN"), values.get("TELEGRAM_CHAT_ID")
    except OSError as exc:
        log(f"Cannot read Telegram env file: {exc}", YELLOW)
        return None, None


def telegram_send(message):
    token, chat_id = read_telegram_env()
    if not token or not chat_id:
        return False
    # Use HTTPS API through urllib; no token is logged.
    try:
        from urllib.request import Request, urlopen
        from urllib.parse import urlencode
        data = urlencode({"chat_id": chat_id, "text": message[:3900]}).encode()
        request = Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urlopen(request, timeout=8) as response:
            result = json.loads(response.read().decode("utf-8", errors="replace"))
        return bool(result.get("ok"))
    except Exception as exc:
        log(f"Telegram notification failed: {exc}", YELLOW)
        return False


def make_baseline():
    data = {
        "created_at": now_iso(),
        "snapshot": snapshot_config(),
    }
    write_json_atomic(BASELINE_FILE, data)
    return data


def audit_changes(notify=True):
    if not ensure_dirs():
        return False
    current = snapshot_config()
    if not BASELINE_FILE.exists():
        write_json_atomic(BASELINE_FILE, {"created_at": now_iso(), "snapshot": current})
        log("No audit baseline existed; created a baseline from current SSH config.", YELLOW)
        append_audit_log("baseline_created", {"files": len(current)})
        return True
    try:
        previous = json.loads(BASELINE_FILE.read_text(encoding="utf-8")).get("snapshot", {})
    except Exception as exc:
        log(f"Audit baseline is unreadable: {exc}", RED)
        return False

    changes = []
    all_paths = sorted(set(previous) | set(current))
    for path in all_paths:
        old = previous.get(path)
        new = current.get(path)
        if old is None:
            changes.append({"path": path, "change": "added", "new": new})
        elif new is None:
            changes.append({"path": path, "change": "removed", "old": old})
        elif old.get("sha256") != new.get("sha256"):
            changes.append({"path": path, "change": "modified",
                            "old_sha256": old.get("sha256"), "new_sha256": new.get("sha256")})

    if not changes:
        log("SSH configuration audit: no content changes detected.", GREEN)
        return True

    log(f"SSH configuration audit: {len(changes)} change(s) detected.", RED)
    for item in changes:
        log(f"[CHANGE] {item['change']}: {item['path']}", RED)
    append_audit_log("ssh_config_changed", {"changes": changes})
    if notify:
        alert_payload = json.dumps(changes, sort_keys=True)
        alert_hash = hashlib.sha256(alert_payload.encode("utf-8")).hexdigest()
        previous_alert_hash = None
        try:
            previous_alert_hash = LAST_ALERT_FILE.read_text(encoding="utf-8").strip()
        except OSError:
            pass
        if alert_hash != previous_alert_hash:
            summary = "\n".join(f"- {x['change']}: {x['path']}" for x in changes)
            if telegram_send("⚠️ ServerGuard SSH audit detected configuration changes:\n" + summary):
                try:
                    LAST_ALERT_FILE.write_text(alert_hash + "\n", encoding="utf-8")
                    os.chmod(LAST_ALERT_FILE, 0o600)
                except OSError:
                    pass
    # Deliberately do NOT auto-update the baseline after a change. A human must
    # inspect and explicitly re-baseline after legitimate maintenance.
    return False


def write_hardening_dropin():
    HARDENING_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    content = (
        "# Managed by ServerGuard SSH Hardening. Do not edit manually.\n"
        "# Conservative settings: authentication method and SSH port are preserved.\n"
        + "".join(f"{key} {value}\n" for key, value in HARDENING_SETTINGS.items())
    )
    fd, temp_name = tempfile.mkstemp(prefix=".99-serverguard.", dir=str(HARDENING_CONFIG.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, HARDENING_CONFIG)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def reload_ssh():
    service = get_ssh_service()
    if not service:
        log("Cannot find SSH systemd service.", RED)
        return False
    # Validate before asking systemd to reload.
    if not validate_sshd_config():
        return False
    code, out, err = run_command(["systemctl", "reload", service], timeout=25)
    if code != 0:
        log(f"SSH reload failed: {err or out}", RED)
        return False
    code, status, err = run_command(["systemctl", "is-active", service])
    if code == 0 and status == "active":
        log(f"SSH service {service}: active after reload.", GREEN)
        return True
    log(f"SSH service status after reload is not active: {status or err}", RED)
    return False


def restore_dropin_from_backup(backup_name):
    manifest_path = BACKUP_DIR / f"{backup_name}.json"
    archive_path = BACKUP_DIR / backup_name
    if not archive_path.is_file() or not manifest_path.is_file():
        log("Backup archive or manifest is missing.", RED)
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        files = manifest.get("files", [])
        backed_up_paths = {str(Path(entry.get("path", ""))) for entry in files}
        with tarfile.open(archive_path, "r:gz") as archive:
            # Never extract arbitrary archive paths. Restore only known absolute
            # paths from the manifest, with an exact matching archive member.
            for entry in files:
                target = Path(entry["path"])
                arcname = entry["archive_name"]
                if not str(target).startswith("/etc/ssh/"):
                    raise ValueError(f"Refusing unexpected restore path: {target}")
                member = archive.getmember(arcname)
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"Missing file content for {target}")
                target.parent.mkdir(parents=True, exist_ok=True)
                data = source.read()
                fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.restore.", dir=str(target.parent))
                with os.fdopen(fd, "wb") as output:
                    output.write(data)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(tmp, int(entry.get("mode", 0o644)))
                try:
                    os.chown(tmp, int(entry.get("uid", 0)), int(entry.get("gid", 0)))
                except PermissionError:
                    pass
                os.replace(tmp, target)
        # The ServerGuard drop-in is part of the managed state. If it did not
        # exist in the selected snapshot, remove the current one on restore.
        if str(HARDENING_CONFIG) not in backed_up_paths:
            HARDENING_CONFIG.unlink(missing_ok=True)
        return True
    except Exception as exc:
        log(f"Restore failed: {exc}", RED)
        return False


def command_apply(args):
    if not require_root():
        return 1
    if not ensure_dirs():
        return 1
    service, status = ssh_service_status()
    if not service:
        log("SSH service not found; install openssh-server first.", RED)
        return 1
    if status != "active":
        log(f"SSH service is not active ({status}); refusing to change SSH configuration.", RED)
        return 1
    if not MAIN_SSH_CONFIG.is_file():
        log(f"Missing {MAIN_SSH_CONFIG}; refusing to proceed.", RED)
        return 1
    if not validate_sshd_config():
        log("Existing SSH config is invalid; fix it before applying hardening.", RED)
        return 1

    backup_name = backup_configs("pre-hardening")
    if not backup_name:
        return 1

    original_dropin_existed = HARDENING_CONFIG.exists()
    original_dropin_bytes = HARDENING_CONFIG.read_bytes() if original_dropin_existed else None
    try:
        write_hardening_dropin()
        if not validate_sshd_config():
            raise RuntimeError("sshd -t failed after writing hardening config")
        if not reload_ssh():
            raise RuntimeError("SSH reload or post-reload service check failed")
        if not check_effective_settings():
            raise RuntimeError("Effective settings do not match the requested hardening policy")
    except Exception as exc:
        log(f"Apply failed; rolling back ServerGuard drop-in: {exc}", RED)
        try:
            if original_dropin_existed:
                fd, tmp = tempfile.mkstemp(prefix=".serverguard.rollback.", dir=str(HARDENING_CONFIG.parent))
                with os.fdopen(fd, "wb") as file:
                    file.write(original_dropin_bytes)
                os.chmod(tmp, 0o644)
                os.replace(tmp, HARDENING_CONFIG)
            else:
                HARDENING_CONFIG.unlink(missing_ok=True)
            validate_sshd_config()
            reload_ssh()
        except Exception as rollback_exc:
            log(f"CRITICAL: rollback attempt failed: {rollback_exc}", RED)
        append_audit_log("apply_failed", {"error": str(exc), "backup": backup_name})
        telegram_send(f"🚨 ServerGuard SSH hardening apply failed on {os.uname().nodename}. "
                      f"Backup: {backup_name}. Error: {exc}")
        return 1

    make_baseline()
    append_audit_log("hardening_applied", {"backup": backup_name})
    telegram_send(f"✅ ServerGuard SSH hardening applied on {os.uname().nodename}. "
                  f"Password authentication and SSH port were preserved. Backup: {backup_name}")
    log(f"\nServerGuard hardening applied. Backup: {backup_name}", GREEN)
    log("PasswordAuthentication, PermitRootLogin, SSH port, and firewall rules were not changed.", CYAN)
    return 0


def command_disable(args):
    if not require_root():
        return 1
    if not ensure_dirs():
        return 1
    if not HARDENING_CONFIG.exists():
        log("ServerGuard drop-in is not installed; nothing to disable.", YELLOW)
        return 0

    backup_name = backup_configs("pre-disable")
    if not backup_name:
        return 1

    original = HARDENING_CONFIG.read_bytes()
    try:
        HARDENING_CONFIG.unlink()
        ok = validate_sshd_config() and reload_ssh()
    except Exception as exc:
        log(f"Disable failed: {exc}", RED)
        ok = False

    if not ok:
        log("Disable failed; restoring ServerGuard drop-in.", RED)
        try:
            HARDENING_CONFIG.write_bytes(original)
            os.chmod(HARDENING_CONFIG, 0o644)
            validate_sshd_config()
            reload_ssh()
        except Exception as exc:
            log(f"CRITICAL: could not restore drop-in: {exc}", RED)
        return 1

    make_baseline()
    append_audit_log("hardening_disabled", {"backup": backup_name})
    telegram_send(f"ℹ️ ServerGuard SSH hardening disabled on {os.uname().nodename}. Backup: {backup_name}")
    log(f"ServerGuard SSH hardening disabled. Backup: {backup_name}", GREEN)
    return 0


def command_check(args):
    service, status = ssh_service_status()
    if service:
        log(f"SSH service ({service}): {status}", GREEN if status == "active" else YELLOW)
    else:
        log("SSH service: NOT FOUND", RED)
    syntax_ok = validate_sshd_config()
    dropin_ok = check_hardening_file()
    settings_ok = check_effective_settings() if syntax_ok else False
    keys_ok = authorized_keys_audit()
    fail2ban_ok = get_fail2ban_status()
    log("\nSummary:")
    log(f"  SSH service active: {'YES' if status == 'active' else 'NO'}")
    log(f"  SSH syntax valid: {'YES' if syntax_ok else 'NO'}")
    log(f"  ServerGuard drop-in correct: {'YES' if dropin_ok else 'NO'}")
    log(f"  Effective conservative settings correct: {'YES' if settings_ok else 'NO'}")
    log(f"  Basic authorized_keys audit clean: {'YES' if keys_ok else 'NO/REVIEW'}")
    log(f"  Fail2ban SSH jail active: {'YES' if fail2ban_ok else 'NO/REVIEW'}")
    # ENABLED requires core controls only; optional Fail2ban/key audit are shown
    # separately and never falsely presented as part of SSH config status.
    enabled = bool(status == "active" and syntax_ok and dropin_ok and settings_ok)
    log(f"\nServerGuard SSH hardening: {'ENABLED' if enabled else 'NOT FULLY ENABLED'}",
        GREEN if enabled else RED)
    return 0 if enabled else 1


def command_keys(args):
    if not require_root():
        return 1
    return 0 if authorized_keys_audit() else 2


def command_fail2ban(args):
    if not require_root():
        return 1
    return 0 if get_fail2ban_status() else 2


def setup_fail2ban():
    """Install Fail2ban and enable a conservative SSH jail."""
    if not require_root():
        return 1
    if not shutil.which("apt-get"):
        log("Automatic Fail2ban setup currently supports apt-based Ubuntu/Debian systems only.", RED)
        return 1
    # Avoid silently replacing an administrator's existing ServerGuard jail.
    jail_dir = Path("/etc/fail2ban/jail.d")
    jail_file = jail_dir / "serverguard-sshd.local"
    if jail_file.exists():
        backup = BACKUP_DIR / f"serverguard-fail2ban-{datetime.now().strftime('%Y%m%d_%H%M%S')}.backup"
        try:
            ensure_dirs()
            shutil.copy2(jail_file, backup)
            os.chmod(backup, 0o600)
            log(f"Existing ServerGuard Fail2ban jail backed up to {backup}", GREEN)
        except OSError as exc:
            log(f"Cannot back up existing Fail2ban jail: {exc}", RED)
            return 1

    log("Installing Fail2ban via apt-get...")
    code, out, err = run_command(["apt-get", "update"], timeout=180)
    if code != 0:
        log(f"apt-get update failed: {err or out}", RED)
        return 1
    code, out, err = run_command(["apt-get", "install", "-y", "fail2ban"], timeout=300)
    if code != 0:
        log(f"Fail2ban installation failed: {err or out}", RED)
        return 1

    try:
        jail_dir.mkdir(parents=True, exist_ok=True)
        content = ("# Managed by ServerGuard. Review before modifying.\n"
                   "[sshd]\n"
                   "enabled = true\n"
                   "backend = systemd\n"
                   "findtime = 10m\n"
                   "maxretry = 5\n"
                   "bantime = 1h\n")
        fd, tmp = tempfile.mkstemp(prefix=".serverguard-sshd.", dir=str(jail_dir))
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, jail_file)
    except OSError as exc:
        log(f"Cannot write Fail2ban SSH jail: {exc}", RED)
        return 1

    code, out, err = run_command(["systemctl", "enable", "--now", "fail2ban"], timeout=30)
    if code != 0:
        log(f"Could not enable/start Fail2ban: {err or out}", RED)
        return 1
    code, out, err = run_command(["fail2ban-client", "-t"], timeout=30)
    if code != 0:
        log(f"Fail2ban config validation failed: {err or out}", RED)
        return 1
    code, out, err = run_command(["fail2ban-client", "reload"], timeout=30)
    if code != 0:
        log(f"Fail2ban reload failed: {err or out}", RED)
        return 1
    code, out, err = run_command(["fail2ban-client", "status", "sshd"], timeout=20)
    if code != 0:
        log(f"Fail2ban started but SSH jail could not be verified: {err or out}", YELLOW)
        return 1
    log("Fail2ban is active and the SSH jail is verified.", GREEN)
    log("Policy: ban after 5 failures in 10 minutes; ban duration 1 hour.", CYAN)
    telegram_send(f"🛡️ ServerGuard enabled Fail2ban SSH protection on {os.uname().nodename}.")
    append_audit_log("fail2ban_configured", {"jail": str(jail_file)})
    return 0


def command_audit(args):
    if not require_root():
        return 1
    return 0 if audit_changes(notify=True) else 2


def command_restore(args):
    if not require_root():
        return 1
    if not ensure_dirs():
        return 1

    backup_name = args.backup
    if not backup_name:
        if not sys.stdin.isatty():
            log("Backup name is required when not running in an interactive terminal.", RED)
            return 1
        choices = sorted(
            (p.name for p in BACKUP_DIR.glob("pre-hardening_*.tar.gz")),
            reverse=True
        )
        if not choices:
            log("No pre-hardening backups found.", YELLOW)
            return 1
        for index, name in enumerate(choices, 1):
            print(f"{index}. {name}")
        raw = input("Backup number (0 to cancel): ").strip()
        if raw == "0":
            return 1
        try:
            backup_name = choices[int(raw) - 1]
        except (ValueError, IndexError):
            log("Invalid selection.", RED)
            return 1

    if "/" in backup_name or "\\" in backup_name or ".." in backup_name:
        log("Invalid backup filename.", RED)
        return 1
    if not backup_name.endswith(".tar.gz") or not backup_name.startswith("pre-hardening_"):
        log("Unsupported backup type; expected a pre-hardening_*.tar.gz archive.", RED)
        return 1

    # Emergency backup before restore.
    emergency = backup_configs("before-restore")
    if not emergency:
        return 1
    if not restore_dropin_from_backup(backup_name):
        log(f"Restore failed. Emergency backup retained: {emergency}", RED)
        return 1
    if not validate_sshd_config():
        log("Restored configuration is invalid. Attempting to restore pre-restore snapshot.", RED)
        restore_dropin_from_backup(emergency)
        validate_sshd_config()
        return 1
    if not reload_ssh():
        log("Reload failed after restore. Emergency backup retained for manual recovery.", RED)
        return 1
    make_baseline()
    append_audit_log("configuration_restored", {"backup": backup_name, "emergency_backup": emergency})
    telegram_send(f"ℹ️ ServerGuard SSH configuration restored on {os.uname().nodename}. Backup: {backup_name}")
    log(f"Restored SSH configuration from {backup_name}.", GREEN)
    return 0


def install_audit_timer():
    if not require_root():
        return 1
    if not ensure_dirs():
        return 1
    script_path = Path(__file__).resolve()
    service_text = f"""[Unit]
Description=ServerGuard SSH configuration audit

[Service]
Type=oneshot
ExecStart={script_path} audit
User=root
Group=root
"""
    timer_text = """[Unit]
Description=Run ServerGuard SSH audit periodically

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
Persistent=true
Unit=serverguard-ssh-audit.service

[Install]
WantedBy=timers.target
"""
    try:
        AUDIT_SERVICE.write_text(service_text, encoding="utf-8")
        AUDIT_TIMER.write_text(timer_text, encoding="utf-8")
        os.chmod(AUDIT_SERVICE, 0o644)
        os.chmod(AUDIT_TIMER, 0o644)
        code, out, err = run_command(["systemctl", "daemon-reload"])
        if code != 0:
            raise RuntimeError(err or out)
        code, out, err = run_command(["systemctl", "enable", "--now", "serverguard-ssh-audit.timer"])
        if code != 0:
            raise RuntimeError(err or out)
        log("Periodic SSH audit timer installed (every 5 minutes).", GREEN)
        log(f"Telegram credentials, if used, must be in {TELEGRAM_ENV} with root:root ownership and mode 600.", CYAN)
        return 0
    except Exception as exc:
        log(f"Could not install audit timer: {exc}", RED)
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="ServerGuard Advanced SSH Hardening for Ubuntu/Debian"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="Read-only SSH hardening audit")
    apply_parser = sub.add_parser("apply", help="Apply conservative SSH hardening")
    apply_parser.add_argument(
        "--auth-method", choices=("publickey", "password"), default=None,
        help="Accepted for ServerGuard client compatibility; does not change behavior")
    sub.add_parser("disable", help="Remove the ServerGuard SSH drop-in")
    restore_parser = sub.add_parser("restore", help="Restore a pre-hardening backup")
    restore_parser.add_argument("backup", nargs="?", help="Backup archive filename")
    sub.add_parser("keys", help="Audit authorized_keys without changing files")
    sub.add_parser("fail2ban", help="Check Fail2ban and SSH jail status")
    sub.add_parser("fail2ban-setup", help="Install and configure Fail2ban SSH protection")
    sub.add_parser("audit", help="Compare current SSH config to audit baseline")
    sub.add_parser("audit-install", help="Install periodic systemd audit timer")
    args = parser.parse_args()

    handlers = {
        "check": command_check,
        "apply": command_apply,
        "disable": command_disable,
        "restore": command_restore,
        "keys": command_keys,
        "fail2ban": command_fail2ban,
        "fail2ban-setup": lambda a: setup_fail2ban(),
        "audit": command_audit,
        "audit-install": lambda a: install_audit_timer(),
    }
    handler = handlers.get(args.command)
    return handler(args) if handler else 2


if __name__ == "__main__":
    sys.exit(main())

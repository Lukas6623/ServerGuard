#!/usr/bin/env python3
"""ServerGuard SSH Hardening for Ubuntu/Debian. Python 3.8+.

Commands: check, apply, disable, restore [BACKUP_NAME], keys, fail2ban,
fail2ban-setup, audit, audit-install.

Conservative policy: does not change SSH port, firewall, root-login policy,
PasswordAuthentication, AllowUsers, or public keys.
"""
import sys
if sys.version_info < (3, 8):
    sys.stderr.write("ERROR: Python 3.8 or newer is required.\n")
    raise SystemExit(1)

import argparse
import glob
import hashlib
import json
import os
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SERVERGUARD_DIR = Path('/opt/serverguard')
BACKUP_DIR = SERVERGUARD_DIR / 'backups'
STATE_DIR = SERVERGUARD_DIR / 'ssh-hardening'
BASELINE_FILE = STATE_DIR / 'ssh-config-baseline.json'
LAST_ALERT_FILE = STATE_DIR / 'last-alert-hash.txt'
AUDIT_LOG = STATE_DIR / 'audit.log'
SSH_DIR = Path('/etc/ssh')
MAIN_SSH_CONFIG = SSH_DIR / 'sshd_config'
HARDENING_CONFIG = SSH_DIR / 'sshd_config.d' / '99-serverguard-hardening.conf'
TELEGRAM_ENV = Path('/etc/serverguard/telegram.env')
SYSTEMD_DIR = Path('/etc/systemd/system')
AUDIT_SERVICE = SYSTEMD_DIR / 'serverguard-ssh-audit.service'
AUDIT_TIMER = SYSTEMD_DIR / 'serverguard-ssh-audit.timer'
RED, GREEN, YELLOW, CYAN, RESET = '\033[91m', '\033[92m', '\033[93m', '\033[96m', '\033[0m'
HARDENING_SETTINGS = {
    'PermitEmptyPasswords': 'no', 'X11Forwarding': 'no',
    'AllowAgentForwarding': 'no', 'MaxAuthTries': '3',
    'LoginGraceTime': '30', 'Compression': 'no',
}
SSH_SERVICE_NAMES = ('ssh', 'sshd')


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')


def log(message, color=None):
    print(f"{color or ''}{message}{RESET if color else ''}")


def run_command(command, timeout=20):
    try:
        p = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, '', f'Command not found: {command[0]}'
    except subprocess.TimeoutExpired:
        return 124, '', f"Command timed out: {' '.join(command)}"
    except Exception as exc:
        return 1, '', str(exc)


def require_root():
    if os.geteuid() != 0:
        log('ERROR: run this command as root (sudo).', RED)
        return False
    return True


def ensure_dirs():
    """Create directories safely; never chmod an existing /opt/serverguard."""
    try:
        if not SERVERGUARD_DIR.exists():
            SERVERGUARD_DIR.mkdir(parents=True, mode=0o755)
            os.chmod(SERVERGUARD_DIR, 0o755)
        if not SERVERGUARD_DIR.is_dir():
            raise OSError(f'{SERVERGUARD_DIR} is not a directory')
        info = SERVERGUARD_DIR.stat()
        if info.st_uid != 0 or (stat.S_IMODE(info.st_mode) & 0o022):
            raise OSError(f'{SERVERGUARD_DIR} must be root-owned and not group/other-writable')
        for directory in (BACKUP_DIR, STATE_DIR):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not directory.is_dir():
                raise OSError(f'{directory} is not a directory')
            os.chmod(directory, 0o700)
            os.chown(directory, 0, 0)
        return True
    except OSError as exc:
        log(f'Cannot prepare ServerGuard directories: {exc}', RED)
        return False


def get_sshd_binary():
    for candidate in ('/usr/sbin/sshd', '/sbin/sshd'):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which('sshd')


def get_ssh_service():
    for service in SSH_SERVICE_NAMES:
        code, out, _ = run_command(['systemctl', 'show', '-p', 'LoadState', '--value', service])
        if code == 0 and out == 'loaded':
            return service
        code, _, _ = run_command(['systemctl', 'cat', service])
        if code == 0:
            return service
    return None


def ssh_service_status():
    service = get_ssh_service()
    if not service:
        return None, 'not-found'
    code, out, err = run_command(['systemctl', 'is-active', service])
    return service, out or err or 'unknown'


def _include_args(line):
    try:
        parts = shlex.split(line, comments=True, posix=True)
    except ValueError:
        return []
    if len(parts) >= 2 and parts[0].lower() == 'include':
        return parts[1:]
    return []


def list_ssh_config_files():
    """Resolve sshd Include directives recursively, restricted to /etc/ssh."""
    found, pending = [], [MAIN_SSH_CONFIG]
    ssh_root = str(SSH_DIR.resolve())
    while pending:
        path = pending.pop(0)
        try:
            resolved = path.resolve(strict=True)
            if os.path.commonpath([ssh_root, str(resolved)]) != ssh_root:
                continue
            if not resolved.is_file() or resolved in found:
                continue
            found.append(resolved)
            try:
                lines = resolved.read_text(encoding='utf-8', errors='replace').splitlines()
            except OSError:
                continue
            for line in lines:
                for pattern in _include_args(line):
                    candidate = Path(pattern)
                    if not candidate.is_absolute():
                        candidate = resolved.parent / candidate
                    # OpenSSH permits glob patterns in Include directives.
                    for match in sorted(glob.glob(str(candidate))):
                        child = Path(match)
                        try:
                            child_resolved = child.resolve(strict=True)
                            if os.path.commonpath([ssh_root, str(child_resolved)]) == ssh_root:
                                if child_resolved not in found and child_resolved not in pending:
                                    pending.append(child_resolved)
                        except (OSError, ValueError):
                            continue
        except (OSError, ValueError):
            continue
    return sorted(found, key=lambda p: str(p))


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def snapshot_config():
    result = {}
    for path in list_ssh_config_files():
        try:
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                result[str(path)] = {'error': 'not a regular file'}
                continue
            result[str(path)] = {'sha256': sha256_file(path),
                                 'mode': stat.S_IMODE(info.st_mode),
                                 'uid': info.st_uid, 'gid': info.st_gid,
                                 'size': info.st_size}
        except OSError as exc:
            result[str(path)] = {'error': str(exc)}
    return result


def write_bytes_atomic(path, data, mode=0o600, uid=0, gid=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f'.{path.name}.', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        try:
            os.chown(tmp, uid, gid)
        except PermissionError:
            pass
        os.replace(tmp, path)
        dfd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json_atomic(path, data, mode=0o600):
    payload = (json.dumps(data, indent=2, sort_keys=True) + '\n').encode('utf-8')
    write_bytes_atomic(path, payload, mode=mode)


def append_audit_log(event, details=None):
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(AUDIT_LOG), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, 'a', encoding='utf-8') as f:
            f.write(json.dumps({'time': now_iso(), 'event': event, 'details': details or {}},
                               sort_keys=True) + '\n')
    except OSError as exc:
        log(f'Warning: could not write audit log: {exc}', YELLOW)


def backup_configs(label='pre-change'):
    if not ensure_dirs():
        return None
    paths = list_ssh_config_files()
    if not paths:
        log('No SSH configuration files found; refusing to make a backup.', RED)
        return None
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    name = f'{label}_{stamp}.tar.gz'
    archive_path = BACKUP_DIR / name
    manifest = {'created_at': now_iso(), 'label': label, 'files': []}
    try:
        with tarfile.open(archive_path, 'w:gz') as archive:
            for path in paths:
                # Refuse symlinks and special files instead of making an unsafe backup.
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError(f'Refusing non-regular SSH config file: {path}')
                arcname = str(path).lstrip('/')
                archive.add(str(path), arcname=arcname, recursive=False)
                manifest['files'].append({'path': str(path), 'archive_name': arcname,
                                          'sha256': sha256_file(path),
                                          'mode': stat.S_IMODE(info.st_mode),
                                          'uid': info.st_uid, 'gid': info.st_gid})
        os.chmod(archive_path, 0o600)
        write_json_atomic(BACKUP_DIR / f'{name}.json', manifest)
        log(f'Backup created: {archive_path}', GREEN)
        return name
    except Exception as exc:
        for p in (archive_path, BACKUP_DIR / f'{name}.json'):
            try:
                p.unlink()
            except OSError:
                pass
        log(f'Backup failed; changes cancelled: {exc}', RED)
        return None


def validate_sshd_config():
    binary = get_sshd_binary()
    if not binary:
        log('sshd binary not found. Install openssh-server first.', RED)
        return False
    code, out, err = run_command([binary, '-t'])
    if code == 0:
        log('sshd -t: configuration syntax is valid.', GREEN)
        return True
    log('sshd -t: configuration is INVALID.', RED)
    if err:
        log(err, RED)
    if out:
        log(out, RED)
    return False


def effective_config():
    binary = get_sshd_binary()
    if not binary:
        return None
    code, out, err = run_command([binary, '-T'])
    if code:
        log(f'Cannot read effective sshd configuration: {err or out}', RED)
        return None
    result = {}
    for line in out.splitlines():
        pair = line.split(None, 1)
        if len(pair) == 2:
            result[pair[0].lower()] = pair[1].strip()
    return result


def check_effective_settings():
    values = effective_config()
    if values is None:
        return False
    ok_all = True
    log('\nEffective SSH security settings:')
    for key, expected in HARDENING_SETTINGS.items():
        actual = values.get(key.lower(), 'unknown')
        ok = actual.lower() == expected.lower()
        log(f"[{'OK' if ok else 'FAIL'}] {key}: {actual} (expected {expected})", GREEN if ok else RED)
        ok_all = ok_all and ok
    if not ok_all and HARDENING_CONFIG.exists():
        log('Hint: sshd uses the first value it reads. An earlier setting in sshd_config or an included file may override the ServerGuard drop-in.', YELLOW)
    for key in ('passwordauthentication', 'kbdinteractiveauthentication', 'pubkeyauthentication', 'permitrootlogin', 'port'):
        log(f'[INFO] {key}: {values.get(key, "unknown")}', CYAN)
    return ok_all


def check_hardening_file():
    if not HARDENING_CONFIG.exists():
        log('ServerGuard drop-in: NOT INSTALLED', YELLOW)
        return False
    try:
        lines = HARDENING_CONFIG.read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError as exc:
        log(f'Cannot read {HARDENING_CONFIG}: {exc}', RED)
        return False
    parsed = {}
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#'):
            parts = line.split(None, 1)
            if len(parts) == 2:
                parsed[parts[0].lower()] = parts[1].strip()
    missing = [f'{k}={v}' for k, v in HARDENING_SETTINGS.items()
               if parsed.get(k.lower(), '').lower() != v.lower()]
    if missing:
        log('ServerGuard drop-in: PRESENT BUT SETTINGS MISMATCH: ' + ', '.join(missing), YELLOW)
        return False
    log('ServerGuard drop-in: present with expected directives.', GREEN)
    return True


def authorized_keys_audit():
    log('\nSSH authorized_keys audit:')
    found = False
    issues = []
    for account in pwd.getpwall():
        if account.pw_uid != 0 and account.pw_uid < 1000:
            continue
        home = Path(account.pw_dir) if account.pw_dir else None
        if not home or not home.is_absolute() or not home.is_dir():
            continue
        ssh_dir, key_file = home / '.ssh', home / '.ssh' / 'authorized_keys'
        try:
            if not key_file.is_file():
                continue
            found = True
            d_info, info = ssh_dir.stat(), key_file.stat()
            mode = stat.S_IMODE(info.st_mode)
            log(f'- {account.pw_name}: {key_file} (mode {mode:04o}, owner uid {info.st_uid})')
            if d_info.st_uid not in (0, account.pw_uid):
                issues.append(f'{ssh_dir}: unexpected owner uid {d_info.st_uid}')
            if stat.S_IMODE(d_info.st_mode) & 0o022:
                issues.append(f'{ssh_dir}: group/other writable directory permissions')
            if info.st_uid != account.pw_uid:
                issues.append(f'{key_file}: owner uid {info.st_uid}, expected {account.pw_uid}')
            if mode & 0o022:
                issues.append(f'{key_file}: group/other writable permissions')
            seen = set()
            with key_file.open('r', encoding='utf-8', errors='replace') as f:
                for line_no, line in enumerate(f, 1):
                    value = line.strip()
                    if not value or value.startswith('#'):
                        continue
                    m = re.search(r'\b(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+([A-Za-z0-9+/=]+)', value)
                    if not m:
                        issues.append(f'{key_file}:{line_no}: unrecognized key format; inspect manually')
                        continue
                    identity = (m.group(1), m.group(2))
                    if identity in seen:
                        issues.append(f'{key_file}:{line_no}: duplicate public key')
                    seen.add(identity)
                    if m.group(1) == 'ssh-rsa':
                        log(f'  [REVIEW] line {line_no}: RSA key; verify key length and policy.', YELLOW)
        except OSError as exc:
            issues.append(f'{key_file}: cannot inspect: {exc}')
    if not found:
        log('No authorized_keys files found for inspected accounts.', YELLOW)
    if issues:
        for issue in issues:
            log(f'[WARN] {issue}', YELLOW)
        return False
    log('No basic ownership/permission/duplicate issues detected.', GREEN)
    log('Note: this is a format check, not full cryptographic validation.', CYAN)
    return True


def get_fail2ban_status():
    if not shutil.which('fail2ban-client'):
        log('Fail2ban: NOT INSTALLED', YELLOW)
        return False
    code, out, err = run_command(['fail2ban-client', 'status'])
    if code:
        log(f'Fail2ban is installed but unavailable/not running: {err or out}', YELLOW)
        return False
    log('Fail2ban daemon status:', GREEN)
    log(out)
    code, out, err = run_command(['fail2ban-client', 'status', 'sshd'])
    if code == 0:
        log('SSH jail status:', GREEN)
        log(out)
        return True
    log(f"SSH jail 'sshd' is not active or configured: {err or out}", YELLOW)
    return False


def read_telegram_env():
    if not TELEGRAM_ENV.is_file():
        return None, None
    try:
        info = TELEGRAM_ENV.stat()
        if info.st_uid != 0 or (stat.S_IMODE(info.st_mode) & 0o077):
            log(f'Telegram env must be root-owned and mode 600 or stricter: {TELEGRAM_ENV}', YELLOW)
            return None, None
        values = {}
        for line in TELEGRAM_ENV.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
        return values.get('TELEGRAM_BOT_TOKEN'), values.get('TELEGRAM_CHAT_ID')
    except OSError as exc:
        log(f'Cannot read Telegram env file: {exc}', YELLOW)
        return None, None


def telegram_send(message):
    token, chat_id = read_telegram_env()
    if not token or not chat_id:
        return False
    try:
        from urllib.request import Request, urlopen
        from urllib.parse import urlencode
        payload = urlencode({'chat_id': chat_id, 'text': message[:3900]}).encode()
        req = Request(f'https://api.telegram.org/bot{token}/sendMessage', data=payload,
                      headers={'Content-Type': 'application/x-www-form-urlencoded'}, method='POST')
        with urlopen(req, timeout=8) as response:
            result = json.loads(response.read().decode('utf-8', errors='replace'))
        return bool(result.get('ok'))
    except Exception:
        # Do not print exception text: URL-related errors could contain secrets.
        log('Telegram notification failed.', YELLOW)
        return False


def make_baseline():
    data = {'created_at': now_iso(), 'snapshot': snapshot_config()}
    write_json_atomic(BASELINE_FILE, data)
    return data


def audit_changes(notify=True):
    if not ensure_dirs():
        return False
    current = snapshot_config()
    if not BASELINE_FILE.exists():
        write_json_atomic(BASELINE_FILE, {'created_at': now_iso(), 'snapshot': current})
        log('No audit baseline existed; created baseline from current SSH config.', YELLOW)
        append_audit_log('baseline_created', {'files': len(current)})
        return True
    try:
        previous = json.loads(BASELINE_FILE.read_text(encoding='utf-8')).get('snapshot', {})
        if not isinstance(previous, dict):
            raise ValueError('snapshot is not an object')
    except Exception as exc:
        log(f'Audit baseline is unreadable: {exc}', RED)
        return False
    changes = []
    for path in sorted(set(previous) | set(current)):
        old, new = previous.get(path), current.get(path)
        if old is None:
            changes.append({'path': path, 'change': 'added', 'new': new})
        elif new is None:
            changes.append({'path': path, 'change': 'removed', 'old': old})
        elif 'error' in old or 'error' in new:
            if old != new:
                changes.append({'path': path, 'change': 'read-error', 'old': old, 'new': new})
        elif any(old.get(k) != new.get(k) for k in ('sha256', 'mode', 'uid', 'gid', 'size')):
            changes.append({'path': path, 'change': 'modified', 'old': old, 'new': new})
    if not changes:
        log('SSH configuration audit: no content or metadata changes detected.', GREEN)
        return True
    log(f'SSH configuration audit: {len(changes)} change(s) detected.', RED)
    for item in changes:
        log(f"[CHANGE] {item['change']}: {item['path']}", RED)
    append_audit_log('ssh_config_changed', {'changes': changes})
    if notify:
        payload = json.dumps(changes, sort_keys=True)
        alert_hash = hashlib.sha256(payload.encode()).hexdigest()
        try:
            previous_hash = LAST_ALERT_FILE.read_text(encoding='utf-8').strip()
        except OSError:
            previous_hash = None
        if alert_hash != previous_hash:
            summary = '\n'.join(f"- {x['change']}: {x['path']}" for x in changes)
            if telegram_send('⚠️ ServerGuard SSH audit detected configuration changes:\n' + summary):
                try:
                    write_bytes_atomic(LAST_ALERT_FILE, (alert_hash + '\n').encode(), 0o600)
                except OSError:
                    pass
    # Baseline is deliberately not updated automatically after a change.
    return False


def write_hardening_dropin():
    content = ('# Managed by ServerGuard SSH Hardening. Do not edit manually.\n'
               '# Authentication method and SSH port are preserved.\n' +
               ''.join(f'{key} {value}\n' for key, value in HARDENING_SETTINGS.items()))
    write_bytes_atomic(HARDENING_CONFIG, content.encode(), 0o644)


def reload_ssh():
    service = get_ssh_service()
    if not service:
        log('Cannot find SSH systemd service.', RED)
        return False
    if not validate_sshd_config():
        return False
    code, out, err = run_command(['systemctl', 'reload', service], timeout=25)
    if code:
        log(f'SSH reload failed: {err or out}', RED)
        return False
    code, status, err = run_command(['systemctl', 'is-active', service])
    if code == 0 and status == 'active':
        log(f'SSH service {service}: active after reload.', GREEN)
        return True
    log(f'SSH service status after reload is not active: {status or err}', RED)
    return False


def safe_backup_name(name):
    return bool(name and re.fullmatch(r'(?:pre-hardening|before-restore)_[A-Za-z0-9_-]+\.tar\.gz', name))


def restore_dropin_from_backup(backup_name):
    if not safe_backup_name(backup_name):
        log('Invalid backup filename.', RED)
        return False
    manifest_path, archive_path = BACKUP_DIR / f'{backup_name}.json', BACKUP_DIR / backup_name
    try:
        if not manifest_path.is_file() or not archive_path.is_file():
            raise ValueError('backup archive or manifest is missing')
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        entries = manifest.get('files')
        if not isinstance(entries, list) or not entries:
            raise ValueError('manifest contains no files')
        ssh_root = str(SSH_DIR.resolve())
        restore_items = []
        with tarfile.open(archive_path, 'r:gz') as archive:
            members = {m.name: m for m in archive.getmembers()}
            seen_targets = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError('invalid manifest entry')
                target = Path(entry['path'])
                arcname = entry['archive_name']
                if not target.is_absolute() or os.path.commonpath([ssh_root, str(target.resolve(strict=False))]) != ssh_root:
                    raise ValueError(f'refusing unexpected restore path: {target}')
                expected_arcname = str(target).lstrip('/')
                if arcname != expected_arcname or arcname not in members:
                    raise ValueError(f'archive member does not match target: {target}')
                if str(target) in seen_targets:
                    raise ValueError(f'duplicate target in manifest: {target}')
                seen_targets.add(str(target))
                member = members[arcname]
                if not member.isfile():
                    raise ValueError(f'archive member is not a regular file: {arcname}')
                src = archive.extractfile(member)
                if src is None:
                    raise ValueError(f'missing content for {target}')
                data = src.read()
                if sha256_bytes(data) != entry.get('sha256'):
                    raise ValueError(f'SHA-256 mismatch for {target}')
                mode = int(entry.get('mode', 0o644))
                uid, gid = int(entry.get('uid', 0)), int(entry.get('gid', 0))
                if mode < 0 or mode > 0o7777 or uid < 0 or gid < 0:
                    raise ValueError(f'invalid metadata for {target}')
                restore_items.append((target, data, mode, uid, gid))
        # Validate the entire backup before touching any live configuration.
        for target, data, mode, uid, gid in restore_items:
            write_bytes_atomic(target, data, mode, uid, gid)
        # Remove our managed drop-in only when it was absent from the snapshot.
        backed_up = {str(x[0]) for x in restore_items}
        if str(HARDENING_CONFIG) not in backed_up and HARDENING_CONFIG.exists():
            HARDENING_CONFIG.unlink()
        log('Backup files restored. Any SSH config files created after the snapshot were left untouched.', YELLOW)
        return True
    except Exception as exc:
        log(f'Restore failed: {exc}', RED)
        return False


def _restore_dropin_bytes(original, metadata=None):
    if original is None:
        HARDENING_CONFIG.unlink(missing_ok=True)
        return
    metadata = metadata or {'mode': 0o644, 'uid': 0, 'gid': 0}
    write_bytes_atomic(HARDENING_CONFIG, original, metadata['mode'], metadata['uid'], metadata['gid'])


def command_apply(args):
    if not require_root() or not ensure_dirs():
        return 1
    service, status = ssh_service_status()
    if not service or status != 'active':
        log(f'SSH service is unavailable or not active ({status}); refusing to apply.', RED)
        return 1
    if not MAIN_SSH_CONFIG.is_file() or not validate_sshd_config():
        log('Existing SSH configuration is missing or invalid; fix it first.', RED)
        return 1
    backup = backup_configs('pre-hardening')
    if not backup:
        return 1
    existed = HARDENING_CONFIG.exists()
    original = HARDENING_CONFIG.read_bytes() if existed else None
    meta = None
    if existed:
        i = HARDENING_CONFIG.stat()
        meta = {'mode': stat.S_IMODE(i.st_mode), 'uid': i.st_uid, 'gid': i.st_gid}
    try:
        write_hardening_dropin()
        if not validate_sshd_config():
            raise RuntimeError('sshd -t failed after writing the drop-in')
        if not reload_ssh():
            raise RuntimeError('SSH reload failed')
        if not check_effective_settings():
            raise RuntimeError('effective SSH settings do not match the requested policy')
    except Exception as exc:
        log(f'Apply failed; rolling back ServerGuard drop-in: {exc}', RED)
        try:
            _restore_dropin_bytes(original, meta)
            if validate_sshd_config():
                reload_ssh()
        except Exception as rollback_exc:
            log(f'CRITICAL: rollback failed: {rollback_exc}', RED)
        append_audit_log('apply_failed', {'error': str(exc), 'backup': backup})
        telegram_send(f'🚨 ServerGuard SSH hardening apply failed on {os.uname().nodename}. Backup: {backup}.')
        return 1
    make_baseline()
    append_audit_log('hardening_applied', {'backup': backup})
    telegram_send(f'✅ ServerGuard SSH hardening applied on {os.uname().nodename}. Password authentication and SSH port were preserved. Backup: {backup}')
    log(f'\nServerGuard hardening applied. Backup: {backup}', GREEN)
    log('PasswordAuthentication, PermitRootLogin, SSH port, and firewall rules were not changed.', CYAN)
    return 0


def command_disable(args):
    if not require_root() or not ensure_dirs():
        return 1
    if not HARDENING_CONFIG.exists():
        log('ServerGuard drop-in is not installed; nothing to disable.', YELLOW)
        return 0
    backup = backup_configs('pre-disable')
    if not backup:
        return 1
    original = HARDENING_CONFIG.read_bytes()
    info = HARDENING_CONFIG.stat()
    meta = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
    try:
        HARDENING_CONFIG.unlink()
        ok = validate_sshd_config() and reload_ssh()
    except Exception as exc:
        log(f'Disable failed: {exc}', RED)
        ok = False
    if not ok:
        log('Disable failed; restoring ServerGuard drop-in.', RED)
        try:
            _restore_dropin_bytes(original, meta)
            if validate_sshd_config():
                reload_ssh()
        except Exception as exc:
            log(f'CRITICAL: could not restore drop-in: {exc}', RED)
        return 1
    make_baseline()
    append_audit_log('hardening_disabled', {'backup': backup})
    telegram_send(f'ℹ️ ServerGuard SSH hardening disabled on {os.uname().nodename}. Backup: {backup}')
    log(f'ServerGuard SSH hardening disabled. Backup: {backup}', GREEN)
    return 0


def command_check(args):
    service, status = ssh_service_status()
    log(f'SSH service ({service}): {status}' if service else 'SSH service: NOT FOUND', GREEN if status == 'active' else YELLOW)
    syntax_ok = validate_sshd_config()
    dropin_ok = check_hardening_file()
    settings_ok = check_effective_settings() if syntax_ok else False
    keys_ok = authorized_keys_audit()
    fail2ban_ok = get_fail2ban_status()
    log('\nSummary:')
    log(f"  SSH service active: {'YES' if status == 'active' else 'NO'}")
    log(f"  SSH syntax valid: {'YES' if syntax_ok else 'NO'}")
    log(f"  ServerGuard drop-in correct: {'YES' if dropin_ok else 'NO'}")
    log(f"  Effective conservative settings correct: {'YES' if settings_ok else 'NO'}")
    log(f"  Basic authorized_keys audit clean: {'YES' if keys_ok else 'NO/REVIEW'}")
    log(f"  Fail2ban SSH jail active: {'YES' if fail2ban_ok else 'NO/REVIEW'}")
    enabled = status == 'active' and syntax_ok and dropin_ok and settings_ok
    log(f"\nServerGuard SSH hardening: {'ENABLED' if enabled else 'NOT FULLY ENABLED'}", GREEN if enabled else RED)
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
    if not require_root():
        return 1
    if not shutil.which('apt-get'):
        log('Automatic Fail2ban setup supports apt-based Ubuntu/Debian only.', RED)
        return 1
    if not ensure_dirs():
        return 1
    jail_dir = Path('/etc/fail2ban/jail.d')
    jail_file = jail_dir / 'serverguard-sshd.local'
    original = jail_file.read_bytes() if jail_file.exists() else None
    original_meta = None
    if jail_file.exists():
        i = jail_file.stat()
        original_meta = {'mode': stat.S_IMODE(i.st_mode), 'uid': i.st_uid, 'gid': i.st_gid}
        backup = BACKUP_DIR / f'fail2ban-jail-{datetime.now().strftime("%Y%m%d_%H%M%S")}.backup'
        try:
            shutil.copy2(jail_file, backup)
            os.chmod(backup, 0o600)
            log(f'Existing jail backed up to {backup}', GREEN)
        except OSError as exc:
            log(f'Cannot back up existing Fail2ban jail: {exc}', RED)
            return 1
    log('Installing Fail2ban via apt-get...')
    code, out, err = run_command(['apt-get', 'update'], timeout=180)
    if code:
        log(f'apt-get update failed: {err or out}', RED)
        return 1
    code, out, err = run_command(['apt-get', 'install', '-y', 'fail2ban'], timeout=300)
    if code:
        log(f'Fail2ban installation failed: {err or out}', RED)
        return 1
    content = ('# Managed by ServerGuard. Review before modifying.\n[sshd]\nenabled = true\n'
               'backend = systemd\nfindtime = 10m\nmaxretry = 5\nbantime = 1h\n')
    try:
        jail_dir.mkdir(parents=True, exist_ok=True)
        write_bytes_atomic(jail_file, content.encode(), 0o644)
        # Validate the new configuration before enabling/reloading the daemon.
        code, out, err = run_command(['fail2ban-client', '-t'], timeout=30)
        if code:
            raise RuntimeError(f'Fail2ban config validation failed: {err or out}')
        code, out, err = run_command(['systemctl', 'enable', '--now', 'fail2ban'], timeout=30)
        if code:
            raise RuntimeError(f'Could not enable/start Fail2ban: {err or out}')
        code, out, err = run_command(['fail2ban-client', 'reload'], timeout=30)
        if code:
            raise RuntimeError(f'Fail2ban reload failed: {err or out}')
        code, out, err = run_command(['fail2ban-client', 'status', 'sshd'], timeout=20)
        if code:
            raise RuntimeError(f'SSH jail could not be verified: {err or out}')
    except Exception as exc:
        log(str(exc), RED)
        try:
            if original is None:
                jail_file.unlink(missing_ok=True)
            else:
                write_bytes_atomic(jail_file, original, original_meta['mode'], original_meta['uid'], original_meta['gid'])
            if shutil.which('fail2ban-client'):
                run_command(['fail2ban-client', 'reload'], timeout=30)
        except Exception as rollback_exc:
            log(f'CRITICAL: Fail2ban jail rollback failed: {rollback_exc}', RED)
        return 1
    log('Fail2ban is active and the SSH jail is verified.', GREEN)
    log('Policy: ban after 5 failures in 10 minutes; ban duration 1 hour.', CYAN)
    telegram_send(f'🛡️ ServerGuard enabled Fail2ban SSH protection on {os.uname().nodename}.')
    append_audit_log('fail2ban_configured', {'jail': str(jail_file)})
    return 0


def command_audit(args):
    if not require_root():
        return 1
    return 0 if audit_changes(notify=True) else 2


def command_restore(args):
    if not require_root() or not ensure_dirs():
        return 1
    name = args.backup
    if not name:
        if not sys.stdin.isatty():
            log('Backup name is required when not running in an interactive terminal.', RED)
            return 1
        choices = sorted((p.name for p in BACKUP_DIR.glob('pre-hardening_*.tar.gz')), reverse=True)
        if not choices:
            log('No pre-hardening backups found.', YELLOW)
            return 1
        for i, item in enumerate(choices, 1):
            print(f'{i}. {item}')
        raw = input('Backup number (0 to cancel): ').strip()
        if raw == '0':
            return 1
        try:
            name = choices[int(raw) - 1]
        except (ValueError, IndexError):
            log('Invalid selection.', RED)
            return 1
    if not name or not re.fullmatch(r'pre-hardening_[A-Za-z0-9_-]+\.tar\.gz', name):
        log('Unsupported/invalid backup filename; expected pre-hardening_*.tar.gz.', RED)
        return 1
    emergency = backup_configs('before-restore')
    if not emergency:
        return 1
    if not restore_dropin_from_backup(name):
        log(f'Restore failed. Emergency backup retained: {emergency}', RED)
        return 1
    if not validate_sshd_config():
        log('Restored configuration is invalid. Restoring emergency snapshot.', RED)
        if restore_dropin_from_backup(emergency):
            validate_sshd_config()
        return 1
    if not reload_ssh():
        log(f'Reload failed after restore. Emergency backup retained: {emergency}', RED)
        return 1
    make_baseline()
    append_audit_log('configuration_restored', {'backup': name, 'emergency_backup': emergency})
    telegram_send(f'ℹ️ ServerGuard SSH configuration restored on {os.uname().nodename}. Backup: {name}')
    log(f'Restored SSH configuration from {name}.', GREEN)
    return 0


def install_audit_timer():
    if not require_root() or not ensure_dirs():
        return 1
    script = Path(__file__).resolve()
    service_text = ('[Unit]\nDescription=ServerGuard SSH configuration audit\n\n[Service]\n'
                    'Type=oneshot\nExecStart=' + shlex.quote(str(script)) + ' audit\nUser=root\nGroup=root\n')
    timer_text = ('[Unit]\nDescription=Run ServerGuard SSH audit periodically\n\n[Timer]\n'
                  'OnBootSec=3min\nOnUnitActiveSec=5min\nPersistent=true\n'
                  'Unit=serverguard-ssh-audit.service\n\n[Install]\nWantedBy=timers.target\n')
    originals = {}
    for path in (AUDIT_SERVICE, AUDIT_TIMER):
        if path.exists():
            i = path.stat()
            originals[path] = (path.read_bytes(), stat.S_IMODE(i.st_mode), i.st_uid, i.st_gid)
        else:
            originals[path] = None
    try:
        write_bytes_atomic(AUDIT_SERVICE, service_text.encode(), 0o644)
        write_bytes_atomic(AUDIT_TIMER, timer_text.encode(), 0o644)
        code, out, err = run_command(['systemctl', 'daemon-reload'])
        if code:
            raise RuntimeError(err or out)
        code, out, err = run_command(['systemctl', 'enable', '--now', 'serverguard-ssh-audit.timer'], timeout=30)
        if code:
            raise RuntimeError(err or out)
        log('Periodic SSH audit timer installed (every 5 minutes).', GREEN)
        log(f'Telegram credentials must be in {TELEGRAM_ENV}, root-owned, mode 600 or stricter.', CYAN)
        return 0
    except Exception as exc:
        log(f'Could not install audit timer: {exc}; restoring previous unit files.', RED)
        for path, old in originals.items():
            try:
                if old is None:
                    path.unlink(missing_ok=True)
                else:
                    write_bytes_atomic(path, old[0], old[1], old[2], old[3])
            except OSError as rollback_exc:
                log(f'Could not restore {path}: {rollback_exc}', RED)
        run_command(['systemctl', 'daemon-reload'])
        return 1


def main():
    parser = argparse.ArgumentParser(description='ServerGuard Advanced SSH Hardening for Ubuntu/Debian')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('check', help='Read-only SSH hardening audit')
    ap = sub.add_parser('apply', help='Apply conservative SSH hardening')
    ap.add_argument('--auth-method', choices=('publickey', 'password'), default=None,
                    help='Accepted for ServerGuard client compatibility; does not change authentication settings')
    sub.add_parser('disable', help='Remove the ServerGuard SSH drop-in')
    rp = sub.add_parser('restore', help='Restore a pre-hardening backup')
    rp.add_argument('backup', nargs='?', help='Backup archive filename')
    sub.add_parser('keys', help='Audit authorized_keys without changing files')
    sub.add_parser('fail2ban', help='Check Fail2ban and SSH jail status')
    sub.add_parser('fail2ban-setup', help='Install and configure Fail2ban SSH protection')
    sub.add_parser('audit', help='Compare current SSH config to audit baseline')
    sub.add_parser('audit-install', help='Install periodic systemd audit timer')
    args = parser.parse_args()
    handlers = {'check': command_check, 'apply': command_apply, 'disable': command_disable,
                'restore': command_restore, 'keys': command_keys, 'fail2ban': command_fail2ban,
                'fail2ban-setup': lambda a: setup_fail2ban(), 'audit': command_audit,
                'audit-install': lambda a: install_audit_timer()}
    return handlers[args.command](args)


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import pwd
import re
import shlex
import socket
import subprocess
import time

from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# SERVERGUARD SSH KEY GUARD
# ============================================================

VERSION = "1.0.0"

BASE_DIR = Path("/opt/serverguard")
DATA_DIR = BASE_DIR / "data"

EVENTS_FILE = DATA_DIR / "ssh_key_events.json"
STATE_FILE = DATA_DIR / "ssh_key_state.json"

AUTHORIZED_KEYS_NAME = "authorized_keys"

DEFAULT_INTERVAL = 5

MAX_EVENTS = 5000


# ============================================================
# DIRECTORIES
# ============================================================

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# TIME
# ============================================================

def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


def local_now():
    return datetime.now().astimezone().isoformat()


# ============================================================
# COMMAND
# ============================================================

def run_command(
    command,
    timeout=5
):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )

        return (
            result.returncode,
            result.stdout.strip(),
            result.stderr.strip()
        )

    except Exception:
        return (
            -1,
            "",
            ""
        )


# ============================================================
# JSON
# ============================================================

def load_json(
    path,
    default
):
    try:
        if not path.exists():
            return default

        with path.open(
            "r",
            encoding="utf-8"
        ) as file:
            return json.load(file)

    except Exception:
        return default


def save_json(
    path,
    data
):
    temporary = path.with_suffix(
        path.suffix + ".tmp"
    )

    try:
        with temporary.open(
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
            temporary,
            path
        )

    except Exception:
        try:
            if temporary.exists():
                temporary.unlink()
        except Exception:
            pass


# ============================================================
# EVENTS
# ============================================================

def load_events():
    data = load_json(
        EVENTS_FILE,
        []
    )

    if not isinstance(
        data,
        list
    ):
        return []

    return data


def save_event(event):
    events = load_events()

    events.append(event)

    if len(events) > MAX_EVENTS:
        events = events[
            -MAX_EVENTS:
        ]

    save_json(
        EVENTS_FILE,
        events
    )


# ============================================================
# HASH
# ============================================================

def sha256_bytes(data):
    return hashlib.sha256(
        data
    ).hexdigest()


def sha256_file(path):
    try:
        data = path.read_bytes()

        return sha256_bytes(
            data
        )

    except Exception:
        return ""


# ============================================================
# USER
# ============================================================

def uid_to_username(uid):
    try:
        return pwd.getpwuid(
            int(uid)
        ).pw_name

    except Exception:
        return str(uid)


def get_file_owner(path):
    try:
        stat = path.stat()

        return {
            "uid": stat.st_uid,
            "user": uid_to_username(
                stat.st_uid
            ),
            "gid": stat.st_gid,
            "mode": oct(
                stat.st_mode & 0o777
            )
        }

    except Exception:
        return {
            "uid": None,
            "user": "",
            "gid": None,
            "mode": ""
        }


# ============================================================
# HOME DIRECTORIES
# ============================================================

def get_home_directories():
    result = []

    try:
        with open(
            "/etc/passwd",
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            for line in file:

                parts = line.rstrip(
                    "\n"
                ).split(":")

                if len(parts) < 7:
                    continue

                username = parts[0]
                uid = parts[2]
                home = parts[5]
                shell = parts[6]

                try:
                    uid_int = int(uid)
                except Exception:
                    continue

                if uid_int < 0:
                    continue

                if not home:
                    continue

                if home == "/nonexistent":
                    continue

                if not os.path.isdir(home):
                    continue

                ssh_dir = Path(home) / ".ssh"

                authorized_keys = (
                    ssh_dir /
                    AUTHORIZED_KEYS_NAME
                )

                result.append({
                    "username": username,
                    "uid": uid_int,
                    "home": home,
                    "shell": shell,
                    "ssh_dir": str(ssh_dir),
                    "authorized_keys": str(
                        authorized_keys
                    )
                })

    except Exception:
        pass

    return result


# ============================================================
# AUTHORIZED KEYS
# ============================================================

KEY_TYPES = (
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "rsa-sha2-256",
    "rsa-sha2-512"
)


def parse_authorized_key_line(
    line,
    line_number
):
    original = line.rstrip("\n")

    stripped = original.strip()

    if not stripped:
        return None

    if stripped.startswith("#"):
        return None

    parts = stripped.split()

    if len(parts) < 2:
        return None

    key_type = parts[0]

    if key_type not in KEY_TYPES:
        return None

    key_data = parts[1]

    comment = ""

    if len(parts) >= 3:
        comment = " ".join(
            parts[2:]
        )

    fingerprint = ""

    try:
        key_bytes = __import__(
            "base64"
        ).b64decode(
            key_data + "=" * (
                -len(key_data) % 4
            )
        )

        digest = hashlib.sha256(
            key_bytes
        ).digest()

        import base64

        fingerprint = (
            "SHA256:"
            +
            base64.b64encode(
                digest
            )
            .decode(
                "ascii"
            )
            .rstrip("=")
        )

    except Exception:
        fingerprint = ""

    return {
        "line": line_number,
        "type": key_type,
        "key": key_data,
        "fingerprint": fingerprint,
        "comment": comment
    }


def read_authorized_keys(
    path
):
    result = []

    try:
        if not path.exists():
            return result

        with path.open(
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            for line_number, line in enumerate(
                file,
                start=1
            ):

                key = parse_authorized_key_line(
                    line,
                    line_number
                )

                if key is not None:
                    result.append(
                        key
                    )

    except Exception:
        pass

    return result


# ============================================================
# KEY IDENTITY
# ============================================================

def key_identity(key):
    return (
        key.get("fingerprint")
        or
        (
            key.get("type", "")
            + ":"
            + key.get("key", "")
        )
    )


# ============================================================
# STATE
# ============================================================

def load_state():
    data = load_json(
        STATE_FILE,
        {}
    )

    if not isinstance(
        data,
        dict
    ):
        return {}

    return data


def save_state(state):
    save_json(
        STATE_FILE,
        state
    )


# ============================================================
# FILE SNAPSHOT
# ============================================================

def build_snapshot():
    snapshot = {}

    for account in get_home_directories():

        path = Path(
            account["authorized_keys"]
        )

        keys = read_authorized_keys(
            path
        )

        snapshot[str(path)] = {
            "username": account["username"],
            "uid": account["uid"],
            "home": account["home"],
            "shell": account["shell"],
            "exists": path.exists(),
            "sha256": sha256_file(path),
            "owner": get_file_owner(path),
            "keys": keys
        }

    return snapshot


# ============================================================
# PROCESS INFORMATION
# ============================================================

def process_info(
    pid
):
    result = {
        "pid": pid,
        "process": "",
        "command": "",
        "exe": "",
        "user": "",
        "ppid": None,
        "parent_process": ""
    }

    if not pid:
        return result

    try:
        pid_int = int(pid)
    except Exception:
        return result

    proc = Path(
        "/proc"
    ) / str(pid_int)

    if not proc.exists():
        return result

    try:
        result["process"] = (
            proc / "comm"
        ).read_text(
            encoding="utf-8",
            errors="ignore"
        ).strip()
    except Exception:
        pass

    try:
        result["command"] = (
            proc / "cmdline"
        ).read_bytes().replace(
            b"\x00",
            b" "
        ).decode(
            "utf-8",
            errors="ignore"
        ).strip()
    except Exception:
        pass

    try:
        result["exe"] = os.readlink(
            str(
                proc / "exe"
            )
        )
    except Exception:
        pass

    try:
        status = (
            proc / "status"
        ).read_text(
            encoding="utf-8",
            errors="ignore"
        )

        for line in status.splitlines():

            if line.startswith(
                "Uid:"
            ):

                parts = line.split()

                if len(parts) >= 2:
                    result["user"] = uid_to_username(
                        parts[1]
                    )

            elif line.startswith(
                "PPid:"
            ):

                parts = line.split()

                if len(parts) >= 2:
                    result["ppid"] = int(
                        parts[1]
                    )

    except Exception:
        pass

    if result["ppid"]:
        try:
            parent_comm = (
                Path("/proc")
                / str(result["ppid"])
                / "comm"
            )

            result["parent_process"] = (
                parent_comm.read_text(
                    encoding="utf-8",
                    errors="ignore"
                ).strip()
            )

        except Exception:
            pass

    return result


# ============================================================
# AUDITD
# ============================================================

AUDIT_RULE_FILE = (
    "/etc/audit/rules.d/"
    "serverguard-ssh-key.rules"
)


def auditd_available():
    return (
        subprocess.run(
            [
                "sh",
                "-c",
                "command -v auditctl >/dev/null 2>&1"
            ]
        ).returncode == 0
    )


def ensure_audit_rules():
    if os.geteuid() != 0:
        return False

    if not auditd_available():
        return False

    rules = """
-w /root/.ssh/authorized_keys -p wa -k serverguard_ssh_keys
-w /home -p wa -k serverguard_ssh_keys
""".strip() + "\n"

    try:
        Path(
            AUDIT_RULE_FILE
        ).parent.mkdir(
            parents=True,
            exist_ok=True
        )

        Path(
            AUDIT_RULE_FILE
        ).write_text(
            rules,
            encoding="utf-8"
        )

    except Exception:
        return False

    run_command(
        [
            "auditctl",
            "-R",
            AUDIT_RULE_FILE
        ],
        timeout=10
    )

    return True


# ============================================================
# AUDIT LOG
# ============================================================

def parse_audit_timestamp(line):
    match = re.search(
        r"msg=audit\((\d+)\.(\d+):(\d+)\)",
        line
    )

    if not match:
        return ""

    try:
        timestamp = float(
            match.group(1)
            + "."
            + match.group(2)
        )

        return datetime.fromtimestamp(
            timestamp,
            tz=timezone.utc
        ).astimezone().isoformat()

    except Exception:
        return ""


def audit_recent_events(
    path
):
    events = []

    if not auditd_available():
        return events

    safe_path = str(
        path
    ).replace(
        "'",
        "'\\''"
    )

    command = (
        "ausearch "
        "-k serverguard_ssh_keys "
        "-ts recent "
        "--raw "
        "2>/dev/null"
    )

    code, stdout, stderr = run_command(
        [
            "sh",
            "-c",
            command
        ],
        timeout=10
    )

    if code != 0:
        return events

    current = {}

    for line in stdout.splitlines():

        line = line.strip()

        if not line:
            if current:
                events.append(
                    current
                )
                current = {}

            continue

        timestamp = parse_audit_timestamp(
            line
        )

        if timestamp:
            current[
                "timestamp"
            ] = timestamp

        for key in (
            "type",
            "pid",
            "ppid",
            "uid",
            "auid",
            "ses",
            "comm",
            "exe",
            "name",
            "cwd",
            "syscall",
            "success",
            "exit",
            "addr",
            "terminal"
        ):

            pattern = (
                r"\b"
                + re.escape(key)
                + r"=([^\s]+)"
            )

            match = re.search(
                pattern,
                line
            )

            if match:
                value = (
                    match.group(1)
                    .strip('"')
                )

                current[key] = value

    if current:
        events.append(
            current
        )

    return events


def find_audit_context(
    path,
    before_events=None
):
    events = audit_recent_events(
        path
    )

    if not events:
        return {}

    if before_events is None:
        before_events = []

    old_signatures = set()

    for event in before_events:

        signature = json.dumps(
            event,
            sort_keys=True
        )

        old_signatures.add(
            signature
        )

    for event in reversed(events):

        signature = json.dumps(
            event,
            sort_keys=True
        )

        if signature in old_signatures:
            continue

        return normalize_audit_event(
            event
        )

    if events:
        return normalize_audit_event(
            events[-1]
        )

    return {}


def normalize_audit_event(
    event
):
    uid = event.get(
        "uid",
        ""
    )

    auid = event.get(
        "auid",
        ""
    )

    result = {
        "timestamp": event.get(
            "timestamp",
            ""
        ),
        "pid": event.get(
            "pid",
            ""
        ),
        "ppid": event.get(
            "ppid",
            ""
        ),
        "uid": uid,
        "user": uid_to_username(
            uid
        ) if str(uid).isdigit()
        else "",
        "auid": auid,
        "audit_user": (
            uid_to_username(auid)
            if str(auid).isdigit()
            and auid != "4294967295"
            else ""
        ),
        "session": event.get(
            "ses",
            ""
        ),
        "process": event.get(
            "comm",
            ""
        ),
        "exe": event.get(
            "exe",
            ""
        ),
        "command": "",
        "cwd": event.get(
            "cwd",
            ""
        ),
        "source_ip": event.get(
            "addr",
            ""
        ),
        "terminal": event.get(
            "terminal",
            ""
        ),
        "success": event.get(
            "success",
            ""
        )
    }

    pid = result["pid"]

    if pid:
        proc = process_info(
            pid
        )

        if proc.get("command"):
            result["command"] = proc[
                "command"
            ]

        if not result["process"]:
            result["process"] = proc.get(
                "process",
                ""
            )

        if not result["exe"]:
            result["exe"] = proc.get(
                "exe",
                ""
            )

        if not result["ppid"]:
            result["ppid"] = proc.get(
                "ppid",
                ""
            )

    return result


# ============================================================
# SSH CONNECTION
# ============================================================

def get_current_ssh_sessions():
    sessions = []

    code, stdout, stderr = run_command(
        [
            "ss",
            "-tnp"
        ],
        timeout=5
    )

    if code != 0:
        return sessions

    for line in stdout.splitlines():

        if ":22" not in line:
            continue

        if "ESTAB" not in line:
            continue

        parts = line.split()

        if len(parts) < 5:
            continue

        local_address = parts[3]
        remote_address = parts[4]

        process_text = ""

        if len(parts) >= 6:
            process_text = " ".join(
                parts[5:]
            )

        sessions.append({
            "local": local_address,
            "remote": remote_address,
            "process": process_text
        })

    return sessions


def find_ssh_source_ip():
    sessions = get_current_ssh_sessions()

    for session in sessions:

        remote = session.get(
            "remote",
            ""
        )

        if remote:
            return remote

    return ""


# ============================================================
# GEOIP
# ============================================================

def geoip(ip):
    if not ip:
        return {}

    if ip in (
        "127.0.0.1",
        "::1",
        "localhost"
    ):
        return {}

    try:
        code, stdout, stderr = run_command(
            [
                "curl",
                "-L",
                "--max-time",
                "4",
                "-s",
                f"https://ipinfo.io/{ip}/json"
            ],
            timeout=6
        )

        if code != 0:
            return {}

        data = json.loads(
            stdout
        )

        return {
            "country": data.get(
                "country",
                ""
            ),
            "region": data.get(
                "region",
                ""
            ),
            "city": data.get(
                "city",
                ""
            ),
            "organization": data.get(
                "org",
                ""
            ),
            "hostname": data.get(
                "hostname",
                ""
            )
        }

    except Exception:
        return {}


# ============================================================
# FILE DIFFERENCE
# ============================================================

def map_keys(keys):
    result = {}

    for key in keys:

        identity = key_identity(
            key
        )

        result[identity] = key

    return result


def compare_keys(
    old_keys,
    new_keys
):
    old_map = map_keys(
        old_keys
    )

    new_map = map_keys(
        new_keys
    )

    added = []

    removed = []

    for identity, key in new_map.items():

        if identity not in old_map:
            added.append(
                key
            )

    for identity, key in old_map.items():

        if identity not in new_map:
            removed.append(
                key
            )

    return (
        added,
        removed
    )


# ============================================================
# EVENT CREATION
# ============================================================

def create_event(
    action,
    path,
    account,
    key,
    old_key=None,
    audit_context=None
):
    if audit_context is None:
        audit_context = {}

    source_ip = (
        audit_context.get(
            "source_ip"
        )
        or
        find_ssh_source_ip()
    )

    geo = geoip(
        source_ip
    )

    owner = get_file_owner(
        Path(path)
    )

    event = {
        "id": (
            f"{int(time.time())}-"
            f"{os.getpid()}-"
            f"{abs(hash("
            f"action + path + "
            f"str(key)"
            f"))}"
        ),

        "version": VERSION,

        "timestamp": local_now(),

        "timestamp_utc": utc_now(),

        "action": action,

        "account": {
            "username": account.get(
                "username",
                ""
            ),
            "uid": account.get(
                "uid"
            ),
            "home": account.get(
                "home",
                ""
            ),
            "shell": account.get(
                "shell",
                ""
            )
        },

        "file": {
            "path": path,
            "sha256": sha256_file(
                Path(path)
            ),
            "owner": owner
        },

        "key": {},

        "old_key": {},

        "modifier": audit_context,

        "network": {
            "source_ip": source_ip,
            "geo": geo
        },

        "server": {
            "hostname": socket.gethostname(),
            "kernel": os.uname().release
            if hasattr(os, "uname")
            else ""
        }
    }

    if key:
        event["key"] = {
            "type": key.get(
                "type",
                ""
            ),
            "fingerprint": key.get(
                "fingerprint",
                ""
            ),
            "comment": key.get(
                "comment",
                ""
            ),
            "line": key.get(
                "line"
            )
        }

    if old_key:
        event["old_key"] = {
            "type": old_key.get(
                "type",
                ""
            ),
            "fingerprint": old_key.get(
                "fingerprint",
                ""
            ),
            "comment": old_key.get(
                "comment",
                ""
            ),
            "line": old_key.get(
                "line"
            )
        }

    return event


# ============================================================
# INITIALIZATION
# ============================================================

def initialize():
    snapshot = build_snapshot()

    state = {
        "version": VERSION,
        "created": local_now(),
        "last_scan": local_now(),
        "files": snapshot
    }

    save_state(
        state
    )

    print(
        "SSH Key Guard baseline created."
    )

    print(
        f"Tracked files: {len(snapshot)}"
    )


# ============================================================
# SCAN
# ============================================================

def scan_once(
    initialize_if_missing=True
):
    state = load_state()

    if not state.get(
        "files"
    ):

        if initialize_if_missing:
            initialize()
            return []

    old_snapshot = state.get(
        "files",
        {}
    )

    new_snapshot = build_snapshot()

    generated_events = []

    for path, new_data in new_snapshot.items():

        old_data = old_snapshot.get(
            path
        )

        if old_data is None:
            old_data = {
                "username": new_data.get(
                    "username",
                    ""
                ),
                "uid": new_data.get(
                    "uid"
                ),
                "home": new_data.get(
                    "home",
                    ""
                ),
                "shell": new_data.get(
                    "shell",
                    ""
                ),
                "exists": False,
                "sha256": "",
                "owner": {},
                "keys": []
            }

        old_keys = old_data.get(
            "keys",
            []
        )

        new_keys = new_data.get(
            "keys",
            []
        )

        added, removed = compare_keys(
            old_keys,
            new_keys
        )

        if not added and not removed:
            continue

        account = {
            "username": new_data.get(
                "username",
                ""
            ),
            "uid": new_data.get(
                "uid"
            ),
            "home": new_data.get(
                "home",
                ""
            ),
            "shell": new_data.get(
                "shell",
                ""
            )
        }

        audit_context = {}

        for key in added:

            event = create_event(
                "key_added",
                path,
                account,
                key,
                audit_context=audit_context
            )

            save_event(
                event
            )

            generated_events.append(
                event
            )

        for key in removed:

            event = create_event(
                "key_removed",
                path,
                account,
                key=None,
                old_key=key,
                audit_context=audit_context
            )

            save_event(
                event
            )

            generated_events.append(
                event
            )

    state = {
        "version": VERSION,
        "last_scan": local_now(),
        "files": new_snapshot
    }

    save_state(
        state
    )

    return generated_events


# ============================================================
# MONITOR
# ============================================================

def monitor(
    interval=DEFAULT_INTERVAL
):
    print(
        "========================================"
    )
    print(
        "       SERVERGUARD SSH KEY GUARD"
    )
    print(
        "========================================"
    )
    print(
        f"Version: {VERSION}"
    )
    print(
        f"Interval: {interval}s"
    )
    print(
        f"Events: {EVENTS_FILE}"
    )
    print(
        f"State: {STATE_FILE}"
    )
    print(
        "========================================"
    )

    if os.geteuid() != 0:
        print(
            "WARNING: SSH Key Guard should run as root."
        )

    if auditd_available():
        if ensure_audit_rules():
            print(
                "auditd: enabled"
            )
        else:
            print(
                "auditd: rule installation failed"
            )
    else:
        print(
            "auditd: not available"
        )

    state = load_state()

    if not state.get(
        "files"
    ):
        initialize()

    while True:

        try:
            events = scan_once(
                initialize_if_missing=False
            )

            for event in events:

                print(
                    json.dumps(
                        event,
                        ensure_ascii=False,
                        indent=2
                    )
                )

            time.sleep(
                max(
                    1,
                    interval
                )
            )

        except KeyboardInterrupt:
            print(
                "\nSSH Key Guard stopped."
            )
            break

        except Exception as error:

            print(
                f"Monitor error: {error}"
            )

            time.sleep(
                max(
                    1,
                    interval
                )
            )


# ============================================================
# SHOW EVENTS
# ============================================================

def show_events(
    limit=20
):
    events = load_events()

    if not events:
        print(
            "No SSH key events."
        )
        return

    for event in events[-limit:]:

        print(
            "========================================"
        )

        print(
            f"Time: {event.get('timestamp', '')}"
        )

        print(
            f"Action: {event.get('action', '')}"
        )

        account = event.get(
            "account",
            {}
        )

        print(
            f"User: {account.get('username', '')}"
        )

        key = event.get(
            "key",
            {}
        )

        old_key = event.get(
            "old_key",
            {}
        )

        if key:
            print(
                f"Key type: {key.get('type', '')}"
            )

            print(
                f"Fingerprint: "
                f"{key.get('fingerprint', '')}"
            )

        if old_key:
            print(
                f"Old fingerprint: "
                f"{old_key.get('fingerprint', '')}"
            )

        network = event.get(
            "network",
            {}
        )

        print(
            f"Source IP: "
            f"{network.get('source_ip', '')}"
        )

        geo = network.get(
            "geo",
            {}
        )

        if geo:
            print(
                "Location: "
                f"{geo.get('country', '')}, "
                f"{geo.get('region', '')}, "
                f"{geo.get('city', '')}"
            )

        modifier = event.get(
            "modifier",
            {}
        )

        print(
            f"Modifier: "
            f"{modifier.get('user', '')}"
        )

        print(
            f"Process: "
            f"{modifier.get('process', '')}"
        )

        print(
            f"PID: "
            f"{modifier.get('pid', '')}"
        )

        print(
            f"Executable: "
            f"{modifier.get('exe', '')}"
        )

        print(
            f"Command: "
            f"{modifier.get('command', '')}"
        )

        print(
            f"File: "
            f"{event.get('file', {}).get('path', '')}"
        )


# ============================================================
# VERSION
# ============================================================

def show_version():
    print(
        f"ServerGuard SSH Key Guard {VERSION}"
    )


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "ServerGuard SSH Key Guard"
        )
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL
    )

    parser.add_argument(
        "command",
        nargs="?",
        default=""
    )

    parser.add_argument(
        "value",
        nargs="?"
    )

    args = parser.parse_args()

    command = (
        args.command
        .strip()
        .lower()
    )

    if command == "monitor":
        monitor(
            args.interval
        )

    elif command == "init":
        initialize()

    elif command == "scan":
        events = scan_once()

        print(
            f"New events: {len(events)}"
        )

    elif command == "events":

        try:
            limit = int(
                args.value
                or 20
            )
        except Exception:
            limit = 20

        show_events(
            max(
                1,
                limit
            )
        )

    elif command == "audit":
        if ensure_audit_rules():
            print(
                "ServerGuard audit rules installed."
            )
        else:
            print(
                "Failed to install audit rules."
            )

    elif command == "version":
        show_version()

    else:
        print(
            "ServerGuard SSH Key Guard"
        )
        print()
        print(
            "Commands:"
        )
        print(
            "  init"
        )
        print(
            "  scan"
        )
        print(
            "  monitor"
        )
        print(
            "  events [COUNT]"
        )
        print(
            "  audit"
        )
        print(
            "  version"
        )


if __name__ == "__main__":
    main()

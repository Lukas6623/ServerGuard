#!/usr/bin/env python3

import argparse
import base64
import hashlib
import html
import ipaddress
import json
import os
import pwd
import re
import socket
import subprocess
import time

from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# SERVERGUARD SSH KEY GUARD
# ============================================================

VERSION = "1.0.0"

BASE_DIR = Path(
    "/opt/serverguard"
)

DATA_DIR = (
    BASE_DIR / "data"
)

EVENTS_FILE = (
    DATA_DIR / "ssh_key_events.json"
)

STATE_FILE = (
    DATA_DIR / "ssh_key_state.json"
)

AUTHORIZED_KEYS_NAME = (
    "authorized_keys"
)

DEFAULT_INTERVAL = 5

MAX_EVENTS = 5000


# ============================================================
# AUDIT
# ============================================================

AUDIT_RULE_FILE = (
    "/etc/audit/rules.d/serverguard-ssh-key.rules"
)

AUDIT_KEY = (
    "serverguard_ssh_keys"
)


# ============================================================
# KEY TYPES
# ============================================================

KEY_TYPES = (
    "ssh-rsa",
    "ssh-dss",

    "ssh-ed25519",

    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",

    "sk-ecdsa-sha2-nistp256@openssh.com",
    "sk-ssh-ed25519@openssh.com",

    "ssh-rsa-cert-v01@openssh.com",
    "ssh-ed25519-cert-v01@openssh.com",

    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",

    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
)


# ============================================================
# INITIALIZATION
# ============================================================

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# TIME
# ============================================================

def utc_now():
    return (
        datetime.now(
            timezone.utc
        )
        .isoformat()
    )


def local_now():
    return (
        datetime.now()
        .astimezone()
        .isoformat()
    )


# ============================================================
# COMMAND EXECUTION
# ============================================================

def run_command(
    command,
    timeout=5
):
    try:
        result = subprocess.run(
            command,
            shell=isinstance(
                command,
                str
            ),
            capture_output=True,
            text=True,
            timeout=timeout
        )

        return (
            result.returncode,
            result.stdout,
            result.stderr
        )

    except Exception as exc:
        return (
            -1,
            "",
            str(exc)
        )


# ============================================================
# JSON
# ============================================================

def load_json(
    path,
    default
):
    try:
        path = Path(path)

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
    path = Path(path)

    temporary = Path(
        str(path) + ".tmp"
    )

    try:
        path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

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

        return True

    except Exception as exc:
        print(
            f"Failed to save {path}: {exc}"
        )

        try:
            if temporary.exists():
                temporary.unlink()
        except Exception:
            pass

        return False


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

    events.append(
        event
    )

    if len(events) > MAX_EVENTS:
        events = events[
            -MAX_EVENTS:
        ]

    save_json(
        EVENTS_FILE,
        events
    )


# ============================================================
# HASHING
# ============================================================

def sha256_bytes(data):
    return hashlib.sha256(
        data
    ).hexdigest()


def sha256_file(path):
    try:
        with open(
            path,
            "rb"
        ) as file:
            digest = hashlib.sha256()

            while True:
                chunk = file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                digest.update(
                    chunk
                )

            return digest.hexdigest()

    except Exception:
        return ""


# ============================================================
# USERS
# ============================================================

def uid_to_username(uid):
    try:
        uid = int(uid)

        return pwd.getpwuid(
            uid
        ).pw_name

    except Exception:
        return str(uid)


def get_file_owner(path):
    path = Path(path)

    try:
        stat = path.stat()

        uid = stat.st_uid
        gid = stat.st_gid

        username = uid_to_username(
            uid
        )

        try:
            import grp

            group_name = grp.getgrgid(
                gid
            ).gr_name

        except Exception:
            group_name = str(gid)

        return {
            "uid": uid,
            "gid": gid,
            "username": username,
            "group": group_name
        }

    except Exception:
        return {
            "uid": "",
            "gid": "",
            "username": "",
            "group": ""
        }


# ============================================================
# FILE METADATA
# ============================================================

def get_file_metadata(path):
    path = Path(path)

    if not path.exists():
        return {
            "exists": False,
            "size": 0,
            "inode": 0,
            "mode": "",
            "mtime": "",
            "ctime": "",
            "sha256": ""
        }

    try:
        stat = path.stat()

        try:
            mode = oct(
                stat.st_mode
                & 0o7777
            )

        except Exception:
            mode = ""

        try:
            mtime = (
                datetime.fromtimestamp(
                    stat.st_mtime
                )
                .astimezone()
                .isoformat()
            )

        except Exception:
            mtime = ""

        try:
            ctime = (
                datetime.fromtimestamp(
                    stat.st_ctime
                )
                .astimezone()
                .isoformat()
            )

        except Exception:
            ctime = ""

        return {
            "exists": True,
            "size": stat.st_size,
            "inode": stat.st_ino,
            "mode": mode,
            "mtime": mtime,
            "ctime": ctime,
            "sha256": sha256_file(
                path
            )
        }

    except Exception:
        return {
            "exists": True,
            "size": 0,
            "inode": 0,
            "mode": "",
            "mtime": "",
            "ctime": "",
            "sha256": ""
        }


# ============================================================
# HOME DIRECTORIES
# ============================================================

def get_home_directories():
    accounts = []

    try:
        passwd_entries = pwd.getpwall()

    except Exception:
        return accounts

    for entry in passwd_entries:

        username = entry.pw_name
        uid = entry.pw_uid
        home = entry.pw_dir
        shell = entry.pw_shell

        if not home:
            continue

        if not home.startswith(
            "/home/"
        ) and home != "/root":
            continue

        if uid < 0:
            continue

        home_path = Path(
            home
        )

        ssh_dir = (
            home_path / ".ssh"
        )

        authorized_keys = (
            ssh_dir / AUTHORIZED_KEYS_NAME
        )

        accounts.append(
            {
                "username": username,
                "uid": uid,
                "home": str(home_path),
                "shell": shell,
                "ssh": str(ssh_dir),
                "authorized_keys": str(
                    authorized_keys
                )
            }
        )

    accounts.sort(
        key=lambda item: item[
            "uid"
        ]
    )

    return accounts


# ============================================================
# AUTHORIZED KEYS PARSER
# ============================================================

def parse_authorized_key_line(
    line,
    line_number
):
    original = line.rstrip(
        "\r\n"
    )

    stripped = original.strip()

    if not stripped:
        return None

    if stripped.startswith(
        "#"
    ):
        return None

    parts = stripped.split()

    if len(parts) < 2:
        return None

    key_type_index = -1

    for index, part in enumerate(
        parts
    ):
        if part in KEY_TYPES:
            key_type_index = index
            break

    if key_type_index < 0:
        return None

    if key_type_index + 1 >= len(parts):
        return None

    key_type = parts[
        key_type_index
    ]

    key_data = parts[
        key_type_index + 1
    ]

    comment_parts = parts[
        key_type_index + 2:
    ]

    comment = " ".join(
        comment_parts
    )

    options = " ".join(
        parts[:key_type_index]
    )

    try:
        decoded = base64.b64decode(
            key_data.encode(
                "ascii"
            ),
            validate=True
        )

        fingerprint = (
            "SHA256:"
            + base64.b64encode(
                hashlib.sha256(
                    decoded
                ).digest()
            )
            .decode(
                "ascii"
            )
            .rstrip("=")
        )

        key_hash = hashlib.sha256(
            decoded
        ).hexdigest()

    except Exception:
        fingerprint = ""

        key_hash = ""

    return {
        "type": key_type,
        "data": key_data,
        "fingerprint": fingerprint,
        "sha256": key_hash,
        "comment": comment,
        "options": options,
        "line": line_number,
        "raw": original
    }


def read_authorized_keys(path):
    path = Path(path)

    keys = []

    if not path.exists():
        return keys

    try:
        with path.open(
            "r",
            encoding="utf-8",
            errors="replace"
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
                    keys.append(
                        key
                    )

    except Exception:
        return []

    return keys


# ============================================================
# KEY IDENTITY
# ============================================================

def key_identity(key):
    if not key:
        return ""

    fingerprint = key.get(
        "fingerprint",
        ""
    )

    if fingerprint:
        return fingerprint

    key_hash = key.get(
        "sha256",
        ""
    )

    if key_hash:
        return key_hash

    return (
        key.get(
            "type",
            ""
        )
        + ":"
        + key.get(
            "data",
            ""
        )
    )


# ============================================================
# SNAPSHOT
# ============================================================

def build_snapshot():
    snapshot = {}

    for account in get_home_directories():

        path = Path(
            account[
                "authorized_keys"
            ]
        )

        metadata = get_file_metadata(
            path
        )

        keys = read_authorized_keys(
            path
        )

        snapshot[str(path)] = {
            "username": account[
                "username"
            ],

            "uid": account[
                "uid"
            ],

            "home": account[
                "home"
            ],

            "shell": account[
                "shell"
            ],

            "exists": path.exists(),

            "sha256": (
                metadata.get(
                    "sha256",
                    ""
                )
            ),

            "metadata": metadata,

            "owner": get_file_owner(
                path
            ),

            "keys": keys
        }

    return snapshot


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
# PROCESS INFORMATION
# ============================================================

def process_info(pid):
    result = {
        "pid": "",
        "ppid": "",
        "process": "",
        "parent_process": "",
        "exe": "",
        "command": "",
        "uid": "",
        "username": ""
    }

    if pid in (
        None,
        "",
        0,
        "0"
    ):
        return result

    try:
        pid = int(pid)

    except Exception:
        return result

    result["pid"] = pid

    proc_dir = Path(
        f"/proc/{pid}"
    )

    if not proc_dir.exists():
        return result

    try:
        comm = (
            proc_dir / "comm"
        )

        if comm.exists():
            result[
                "process"
            ] = comm.read_text(
                encoding="utf-8",
                errors="replace"
            ).strip()

    except Exception:
        pass

    try:
        cmdline = (
            proc_dir / "cmdline"
        )

        if cmdline.exists():
            raw = cmdline.read_bytes()

            result[
                "command"
            ] = raw.replace(
                b"\x00",
                b" "
            ).decode(
                "utf-8",
                errors="replace"
            ).strip()

    except Exception:
        pass

    try:
        exe = (
            proc_dir / "exe"
        )

        if exe.exists():
            result[
                "exe"
            ] = os.readlink(
                str(exe)
            )

    except Exception:
        pass

    try:
        status = (
            proc_dir / "status"
        )

        if status.exists():

            text = status.read_text(
                encoding="utf-8",
                errors="replace"
            )

            for line in text.splitlines():

                if line.startswith(
                    "PPid:"
                ):
                    result[
                        "ppid"
                    ] = int(
                        line.split(
                            ":",
                            1
                        )[1].strip()
                    )

                elif line.startswith(
                    "Uid:"
                ):
                    fields = (
                        line.split(
                            ":",
                            1
                        )[1]
                        .split()
                    )

                    if fields:
                        result[
                            "uid"
                        ] = int(
                            fields[0]
                        )

    except Exception:
        pass

    if result[
        "uid"
    ] != "":
        result[
            "username"
        ] = uid_to_username(
            result["uid"]
        )

    try:
        ppid = result[
            "ppid"
        ]

        if ppid:
            parent = process_info(
                ppid
            )

            result[
                "parent_process"
            ] = parent.get(
                "process",
                ""
            )

    except Exception:
        pass

    return result


# ============================================================
# AUDITD AVAILABLE
# ============================================================

def auditd_available():
    code, stdout, stderr = run_command(
        [
            "sh",
            "-c",
            "command -v auditctl"
        ]
    )

    return (
        code == 0
        and bool(
            stdout.strip()
        )
    )


# ============================================================
# AUDIT RULES
# ============================================================

def ensure_audit_rules():
    if os.geteuid() != 0:
        print(
            "Audit configuration requires root."
        )
        return False

    if not auditd_available():
        print(
            "auditctl was not found."
        )
        return False

    rules = []

    root_key = Path(
        "/root/.ssh/authorized_keys"
    )

    if root_key.exists() or root_key.parent.exists():
        rules.append(
            "-w /root/.ssh/authorized_keys "
            "-p wa "
            "-k serverguard_ssh_keys"
        )

    for account in get_home_directories():

        key_path = Path(
            account[
                "authorized_keys"
            ]
        )

        ssh_dir = key_path.parent

        if (
            key_path.exists()
            or ssh_dir.exists()
        ):
            rules.append(
                f"-w {key_path} "
                "-p wa "
                "-k serverguard_ssh_keys"
            )

    unique_rules = []

    for rule in rules:
        if rule not in unique_rules:
            unique_rules.append(
                rule
            )

    if not unique_rules:
        print(
            "No SSH authorized_keys paths found."
        )
        return False

    try:
        Path(
            AUDIT_RULE_FILE
        ).parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(
            AUDIT_RULE_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                "# ServerGuard SSH Key Guard\n"
            )

            file.write(
                "# Generated automatically\n\n"
            )

            for rule in unique_rules:
                file.write(
                    rule
                    + "\n"
                )

    except Exception as exc:
        print(
            f"Failed to write audit rules: {exc}"
        )
        return False

    code, stdout, stderr = run_command(
        [
            "auditctl",
            "-R",
            AUDIT_RULE_FILE
        ],
        timeout=10
    )

    if code != 0:

        print(
            "Failed to load audit rules:"
        )

        if stderr:
            print(
                stderr.strip()
            )

        return False

    print(
        "Audit rules loaded successfully."
    )

    print(
        f"Rules: {len(unique_rules)}"
    )

    return True


# ============================================================
# AUDIT TIMESTAMP
# ============================================================

def parse_audit_timestamp(line):
    match = re.search(
        r"msg=audit\((\d+)\.(\d+):(\d+)\)",
        line
    )

    if not match:
        return (
            "",
            ""
        )

    seconds = int(
        match.group(1)
    )

    fraction = match.group(2)

    serial = match.group(3)

    try:
        timestamp = (
            datetime.fromtimestamp(
                seconds
                + (
                    int(fraction)
                    / (
                        10 ** len(fraction)
                    )
                ),
                tz=timezone.utc
            )
            .astimezone()
            .isoformat()
        )

    except Exception:
        timestamp = ""

    return (
        timestamp,
        serial
    )


# ============================================================
# AUDIT FIELD
# ============================================================

def extract_audit_field(
    line,
    name
):
    pattern = (
        rf'(?:^|\s){re.escape(name)}='
        rf'(?:"([^"]*)"|(\S+))'
    )

    match = re.search(
        pattern,
        line
    )

    if not match:
        return ""

    if match.group(1) is not None:
        return match.group(1)

    return match.group(2)


# ============================================================
# AUDIT RECENT EVENTS
# ============================================================

def audit_recent_events(
    path=None
):
    if not auditd_available():
        return []

    command = [
        "ausearch",
        "-k",
        AUDIT_KEY,
        "-ts",
        "recent",
        "--raw"
    ]

    code, stdout, stderr = run_command(
        command,
        timeout=10
    )

    if code != 0:
        return []

    groups = {}

    for line in stdout.splitlines():

        line = line.strip()

        if not line:
            continue

        timestamp, serial = (
            parse_audit_timestamp(
                line
            )
        )

        if not serial:
            continue

        if serial not in groups:
            groups[serial] = {
                "serial": serial,
                "timestamp": timestamp,
                "raw": []
            }

        groups[
            serial
        ][
            "raw"
        ].append(
            line
        )

    events = []

    target_path = ""

    if path:
        target_path = os.path.realpath(
            str(path)
        )

    for serial, group in groups.items():

        event = {
            "serial": serial,
            "timestamp": group.get(
                "timestamp",
                ""
            ),
            "type": "",
            "pid": "",
            "ppid": "",
            "uid": "",
            "auid": "",
            "ses": "",
            "comm": "",
            "exe": "",
            "name": "",
            "cwd": "",
            "syscall": "",
            "success": "",
            "exit": "",
            "addr": "",
            "terminal": "",
            "raw": group.get(
                "raw",
                []
            )
        }

        names = []

        for line in group[
            "raw"
        ]:

            record_type = (
                extract_audit_field(
                    line,
                    "type"
                )
            )

            if record_type:
                event[
                    "type"
                ] = record_type

            fields = (
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
            )

            for field in fields:

                value = (
                    extract_audit_field(
                        line,
                        field
                    )
                )

                if value:
                    if field == "name":
                        names.append(
                            value
                        )
                    else:
                        event[
                            field
                        ] = value

        if names:
            event[
                "names"
            ] = names

            event[
                "name"
            ] = names[-1]

        if target_path:

            matching = False

            for name in names:

                try:
                    normalized = os.path.realpath(
                        name
                    )

                    if normalized == target_path:
                        matching = True
                        break

                except Exception:
                    pass

                if name == str(path):
                    matching = True
                    break

            if not matching:
                continue

        events.append(
            event
        )

    events.sort(
        key=lambda item: item.get(
            "timestamp",
            ""
        ),
        reverse=True
    )

    return events


# ============================================================
# AUDIT CONTEXT
# ============================================================

def normalize_audit_event(
    event
):
    pid = event.get(
        "pid",
        ""
    )

    process = process_info(
        pid
    )

    uid = event.get(
        "uid",
        ""
    )

    auid = event.get(
        "auid",
        ""
    )

    try:
        uid_int = int(uid)

    except Exception:
        uid_int = ""

    try:
        auid_int = int(auid)

    except Exception:
        auid_int = ""

    username = ""

    if uid_int != "":
        if uid_int not in (
            4294967295,
            4294967294
        ):
            username = uid_to_username(
                uid_int
            )

    auid_username = ""

    if auid_int != "":
        if auid_int not in (
            4294967295,
            4294967294
        ):
            auid_username = uid_to_username(
                auid_int
            )

    if not username:
        username = process.get(
            "username",
            ""
        )

    source_ip = event.get(
        "addr",
        ""
    )

    if source_ip:
        try:
            ipaddress.ip_address(
                source_ip
            )

        except Exception:
            source_ip = ""

    success = event.get(
        "success",
        ""
    )

    command = process.get(
        "command",
        ""
    )

    if not command:
        command = event.get(
            "comm",
            ""
        )

    return {
        "timestamp": event.get(
            "timestamp",
            ""
        ),

        "serial": event.get(
            "serial",
            ""
        ),

        "uid": uid,

        "username": username,

        "auid": auid,

        "auid_username": auid_username,

        "pid": process.get(
            "pid",
            pid
        ),

        "ppid": process.get(
            "ppid",
            event.get(
                "ppid",
                ""
            )
        ),

        "process": (
            process.get(
                "process",
                ""
            )
            or event.get(
                "comm",
                ""
            )
        ),

        "parent_process": process.get(
            "parent_process",
            ""
        ),

        "exe": (
            process.get(
                "exe",
                ""
            )
            or event.get(
                "exe",
                ""
            )
        ),

        "command": command,

        "cwd": event.get(
            "cwd",
            ""
        ),

        "source_ip": source_ip,

        "terminal": event.get(
            "terminal",
            ""
        ),

        "success": success,

        "syscall": event.get(
            "syscall",
            ""
        ),

        "exit": event.get(
            "exit",
            ""
        )
    }


def find_audit_context(
    path,
    before_events=None
):
    if before_events is None:
        events = audit_recent_events(
            path
        )
    else:
        events = before_events

    if not events:
        return {}

    target_path = os.path.realpath(
        str(path)
    )

    candidates = []

    for event in events:

        names = event.get(
            "names",
            []
        )

        matched = False

        for name in names:

            try:
                if os.path.realpath(
                    name
                ) == target_path:
                    matched = True
                    break

            except Exception:
                pass

        if not matched:
            continue

        normalized = normalize_audit_event(
            event
        )

        candidates.append(
            normalized
        )

    if not candidates:
        return {}

    candidates.sort(
        key=lambda item: item.get(
            "timestamp",
            ""
        ),
        reverse=True
    )

    return candidates[0]


# ============================================================
# SSH SESSIONS
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

        if "ESTAB" not in line:
            continue

        if ":22" not in line:
            continue

        parts = line.split()

        if len(parts) < 5:
            continue

        local_address = parts[3]
        remote_address = parts[4]

        remote_ip = remote_address

        if remote_address.startswith(
            "["
        ):
            match = re.match(
                r"\[([^\]]+)\]:\d+$",
                remote_address
            )

            if match:
                remote_ip = match.group(1)

        else:
            if remote_address.count(
                ":"
            ) == 1:
                remote_ip = (
                    remote_address
                    .rsplit(
                        ":",
                        1
                    )[0]
                )

        process = ""

        if "users:(" in line:
            process = line[
                line.find(
                    "users:("
                ):
            ]

        sessions.append(
            {
                "local": local_address,
                "remote": remote_address,
                "remote_ip": remote_ip,
                "process": process
            }
        )

    return sessions


def find_ssh_source_ip():
    sessions = get_current_ssh_sessions()

    for session in sessions:

        ip = session.get(
            "remote_ip",
            ""
        )

        if ip:
            return ip

    return ""


# ============================================================
# GEOIP
# ============================================================

def geoip(ip):
    if not ip:
        return {}

    try:
        address = ipaddress.ip_address(
            ip
        )

        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
        ):
            return {}

    except Exception:
        return {}

    url = (
        "https://ipinfo.io/"
        + ip
        + "/json"
    )

    code, stdout, stderr = run_command(
        [
            "curl",
            "-L",
            "--max-time",
            "4",
            "-s",
            url
        ],
        timeout=6
    )

    if code != 0:
        return {}

    try:
        data = json.loads(
            stdout
        )

    except Exception:
        return {}

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

        "org": data.get(
            "org",
            ""
        ),

        "hostname": data.get(
            "hostname",
            ""
        )
    }


# ============================================================
# KEY COMPARISON
# ============================================================

def map_keys(keys):
    result = {}

    for key in keys:

        identity = key_identity(
            key
        )

        if identity:
            result[
                identity
            ] = key

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
        or find_ssh_source_ip()
        or ""
    )

    if audit_context.get(
        "source_ip"
    ):
        source_ip_source = (
            "auditd"
        )

    elif source_ip:
        source_ip_source = (
            "active_ssh_session"
        )

    else:
        source_ip_source = (
            "unknown"
        )

    location = geoip(
        source_ip
    )

    file_path = Path(
        path
    )

    metadata = get_file_metadata(
        file_path
    )

    owner = get_file_owner(
        file_path
    )

    event_seed = (
        str(action)
        + "|"
        + str(path)
        + "|"
        + json.dumps(
            key,
            sort_keys=True,
            ensure_ascii=False
        )
        + "|"
        + json.dumps(
            old_key,
            sort_keys=True,
            ensure_ascii=False
        )
    )

    event_id = (
        f"{int(time.time())}-"
        f"{os.getpid()}-"
        f"{hashlib.sha256("
        f"event_seed.encode('utf-8')"
        f").hexdigest()[:16]}"
    )

    event = {
        "id": event_id,

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
                "uid",
                ""
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
            "path": str(path),

            "owner": owner,

            "metadata": metadata
        },

        "key": (
            {
                "type": key.get(
                    "type",
                    ""
                ),

                "fingerprint": key.get(
                    "fingerprint",
                    ""
                ),

                "sha256": key.get(
                    "sha256",
                    ""
                ),

                "comment": key.get(
                    "comment",
                    ""
                ),

                "line": key.get(
                    "line",
                    0
                ),

                "options": key.get(
                    "options",
                    ""
                )
            }
            if key
            else None
        ),

        "old_key": (
            {
                "type": old_key.get(
                    "type",
                    ""
                ),

                "fingerprint": old_key.get(
                    "fingerprint",
                    ""
                ),

                "sha256": old_key.get(
                    "sha256",
                    ""
                ),

                "comment": old_key.get(
                    "comment",
                    ""
                ),

                "line": old_key.get(
                    "line",
                    0
                ),

                "options": old_key.get(
                    "options",
                    ""
                )
            }
            if old_key
            else None
        ),

        "modifier": {
            "uid": audit_context.get(
                "uid",
                ""
            ),

            "username": audit_context.get(
                "username",
                ""
            ),

            "auid": audit_context.get(
                "auid",
                ""
            ),

            "auid_username": audit_context.get(
                "auid_username",
                ""
            ),

            "pid": audit_context.get(
                "pid",
                ""
            ),

            "ppid": audit_context.get(
                "ppid",
                ""
            ),

            "process": audit_context.get(
                "process",
                ""
            ),

            "parent_process": audit_context.get(
                "parent_process",
                ""
            ),

            "exe": audit_context.get(
                "exe",
                ""
            ),

            "command": audit_context.get(
                "command",
                ""
            ),

            "cwd": audit_context.get(
                "cwd",
                ""
            ),

            "success": audit_context.get(
                "success",
                ""
            ),

            "syscall": audit_context.get(
                "syscall",
                ""
            ),

            "exit": audit_context.get(
                "exit",
                ""
            ),

            "audit_serial": audit_context.get(
                "serial",
                ""
            )
        },

        "network": {
            "source_ip": source_ip,

            "source_ip_source": source_ip_source,

            "country": location.get(
                "country",
                ""
            ),

            "region": location.get(
                "region",
                ""
            ),

            "city": location.get(
                "city",
                ""
            ),

            "org": location.get(
                "org",
                ""
            ),

            "hostname": location.get(
                "hostname",
                ""
            ),

            "terminal": audit_context.get(
                "terminal",
                ""
            )
        },

        "server": {
            "hostname": socket.gethostname(),

            "os": (
                os.uname().sysname
                if hasattr(
                    os,
                    "uname"
                )
                else ""
            ),

            "kernel": (
                os.uname().release
                if hasattr(
                    os,
                    "uname"
                )
                else ""
            )
        }
    }

    return event


# ============================================================
# INITIALIZE BASELINE
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
        "SSH key baseline created."
    )

    print(
        f"Files monitored: {len(snapshot)}"
    )

    total_keys = 0

    for item in snapshot.values():
        total_keys += len(
            item.get(
                "keys",
                []
            )
        )

    print(
        f"Keys found: {total_keys}"
    )

    return True


# ============================================================
# SCAN
# ============================================================

def scan_once(
    initialize_if_missing=True
):
    state = load_state()

    if not state or "files" not in state:

        if initialize_if_missing:
            initialize()

            return []

        return []

    old_files = state.get(
        "files",
        {}
    )

    new_files = build_snapshot()

    events = []

    for path, new_info in new_files.items():

        old_info = old_files.get(
            path
        )

        if old_info is None:
            old_info = {
                "username": new_info.get(
                    "username",
                    ""
                ),

                "uid": new_info.get(
                    "uid",
                    ""
                ),

                "home": new_info.get(
                    "home",
                    ""
                ),

                "shell": new_info.get(
                    "shell",
                    ""
                ),

                "exists": False,

                "keys": []
            }

        old_keys = old_info.get(
            "keys",
            []
        )

        new_keys = new_info.get(
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
            "username": new_info.get(
                "username",
                ""
            ),

            "uid": new_info.get(
                "uid",
                ""
            ),

            "home": new_info.get(
                "home",
                ""
            ),

            "shell": new_info.get(
                "shell",
                ""
            )
        }

        audit_context = (
            find_audit_context(
                path
            )
        )

        for key in added:

            event = create_event(
                "key_added",
                path,
                account,
                key,
                None,
                audit_context
            )

            save_event(
                event
            )

            events.append(
                event
            )

        for key in removed:

            event = create_event(
                "key_removed",
                path,
                account,
                None,
                key,
                audit_context
            )

            save_event(
                event
            )

            events.append(
                event
            )

    state["version"] = VERSION

    state["last_scan"] = local_now()

    state["files"] = new_files

    save_state(
        state
    )

    return events


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
        "      SERVERGUARD SSH KEY GUARD"
    )

    print(
        "========================================"
    )

    print(
        f"Version: {VERSION}"
    )

    print(
        f"Interval: {interval} seconds"
    )

    print()

    if os.geteuid() != 0:

        print(
            "WARNING: SSH Key Guard is not running as root."
        )

        print(
            "Audit information may be incomplete."
        )

        print()

    else:

        if auditd_available():
            print(
                "auditd: available"
            )

            ensure_audit_rules()

        else:
            print(
                "auditd: not available"
            )

    state = load_state()

    if not state or "files" not in state:

        print(
            "No baseline found."
        )

        print(
            "Creating baseline..."
        )

        initialize()

    print()

    print(
        "SSH Key Guard monitoring started."
    )

    print()

    last_rules_refresh = time.time()

    while True:

        try:

            now = time.time()

            if (
                os.geteuid() == 0
                and auditd_available()
                and now - last_rules_refresh >= 60
            ):
                try:
                    ensure_audit_rules()

                except Exception:
                    pass

                last_rules_refresh = now

            events = scan_once(
                initialize_if_missing=False
            )

            for event in events:

                print(
                    json.dumps(
                        event,
                        indent=2,
                        ensure_ascii=False
                    ),
                    flush=True
                )

            time.sleep(
                interval
            )

        except KeyboardInterrupt:

            print()

            print(
                "SSH Key Guard stopped."
            )

            break

        except Exception as exc:

            print(
                f"Monitor error: {exc}",
                flush=True
            )

            time.sleep(
                interval
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
            "No SSH key events found."
        )

        return

    try:
        limit = int(
            limit
        )

    except Exception:
        limit = 20

    if limit < 1:
        limit = 20

    selected = events[
        -limit:
    ]

    selected.reverse()

    print(
        "========================================"
    )

    print(
        "          SSH KEY EVENTS"
    )

    print(
        "========================================"
    )

    for event in selected:

        print()

        print(
            "----------------------------------------"
        )

        print(
            f"ID: {event.get('id', '')}"
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
            f"Account: {account.get('username', '')}"
        )

        print(
            f"UID: {account.get('uid', '')}"
        )

        print(
            f"Home: {account.get('home', '')}"
        )

        file_info = event.get(
            "file",
            {}
        )

        print(
            f"File: {file_info.get('path', '')}"
        )

        owner = file_info.get(
            "owner",
            {}
        )

        print(
            "File owner: "
            f"{owner.get('username', '')}"
        )

        key = event.get(
            "key"
        )

        old_key = event.get(
            "old_key"
        )

        if key:

            print(
                f"Key type: {key.get('type', '')}"
            )

            print(
                "Fingerprint: "
                f"{key.get('fingerprint', '')}"
            )

            print(
                "Key SHA256: "
                f"{key.get('sha256', '')}"
            )

            print(
                f"Comment: {key.get('comment', '')}"
            )

            print(
                f"Options: {key.get('options', '')}"
            )

            print(
                f"Line: {key.get('line', '')}"
            )

        if old_key:

            print(
                "Old key type: "
                f"{old_key.get('type', '')}"
            )

            print(
                "Old fingerprint: "
                f"{old_key.get('fingerprint', '')}"
            )

            print(
                "Old key SHA256: "
                f"{old_key.get('sha256', '')}"
            )

            print(
                "Old comment: "
                f"{old_key.get('comment', '')}"
            )

            print(
                "Old options: "
                f"{old_key.get('options', '')}"
            )

        modifier = event.get(
            "modifier",
            {}
        )

        print(
            "Modifier:"
        )

        print(
            f"  User: {modifier.get('username', '')}"
        )

        print(
            f"  UID: {modifier.get('uid', '')}"
        )

        print(
            f"  AUID: {modifier.get('auid', '')}"
        )

        print(
            "  AUID user: "
            f"{modifier.get('auid_username', '')}"
        )

        print(
            f"  PID: {modifier.get('pid', '')}"
        )

        print(
            f"  PPID: {modifier.get('ppid', '')}"
        )

        print(
            f"  Process: {modifier.get('process', '')}"
        )

        print(
            "  Parent process: "
            f"{modifier.get('parent_process', '')}"
        )

        print(
            f"  EXE: {modifier.get('exe', '')}"
        )

        print(
            f"  Command: {modifier.get('command', '')}"
        )

        print(
            f"  CWD: {modifier.get('cwd', '')}"
        )

        print(
            f"  Success: {modifier.get('success', '')}"
        )

        print(
            f"  Syscall: {modifier.get('syscall', '')}"
        )

        print(
            f"  Exit: {modifier.get('exit', '')}"
        )

        network = event.get(
            "network",
            {}
        )

        print(
            "Network:"
        )

        print(
            f"  Source IP: {network.get('source_ip', '')}"
        )

        print(
            "  Source: "
            f"{network.get('source_ip_source', '')}"
        )

        print(
            f"  Country: {network.get('country', '')}"
        )

        print(
            f"  Region: {network.get('region', '')}"
        )

        print(
            f"  City: {network.get('city', '')}"
        )

        print(
            f"  Organization: {network.get('org', '')}"
        )

        print(
            f"  Hostname: {network.get('hostname', '')}"
        )

        print(
            f"  Terminal: {network.get('terminal', '')}"
        )

        metadata = file_info.get(
            "metadata",
            {}
        )

        print(
            "File metadata:"
        )

        print(
            f"  Size: {metadata.get('size', '')}"
        )

        print(
            f"  Inode: {metadata.get('inode', '')}"
        )

        print(
            f"  Mode: {metadata.get('mode', '')}"
        )

        print(
            f"  Modified: {metadata.get('mtime', '')}"
        )

        print(
            f"  Changed: {metadata.get('ctime', '')}"
        )

        print(
            f"  SHA256: {metadata.get('sha256', '')}"
        )

        print(
            "----------------------------------------"
        )


# ============================================================
# SHOW VERSION
# ============================================================

def show_version():
    print(
        f"ServerGuard SSH Key Guard {VERSION}"
    )


# ============================================================
# SHOW AUDIT STATUS
# ============================================================

def show_audit_status():
    print(
        "========================================"
    )

    print(
        "          SSH KEY AUDIT"
    )

    print(
        "========================================"
    )

    if auditd_available():
        print(
            "auditctl: available"
        )
    else:
        print(
            "auditctl: unavailable"
        )

    rule_path = Path(
        AUDIT_RULE_FILE
    )

    if rule_path.exists():

        print(
            f"Rules file: {rule_path}"
        )

        try:
            text = rule_path.read_text(
                encoding="utf-8"
            )

            print()
            print(
                text
            )

        except Exception:
            pass

    else:

        print(
            "Rules file: not found"
        )


# ============================================================
# REMOVE AUDIT RULES
# ============================================================

def remove_audit_rules():
    if os.geteuid() != 0:
        print(
            "Root privileges are required."
        )
        return False

    if auditd_available():

        code, stdout, stderr = run_command(
            [
                "auditctl",
                "-l"
            ],
            timeout=10
        )

        if code == 0:

            rules = stdout.splitlines()

            for rule in rules:

                if AUDIT_KEY not in rule:
                    continue

                match = re.search(
                    r"^-w\s+(\S+)",
                    rule
                )

                if not match:
                    continue

                watched_path = match.group(1)

                run_command(
                    [
                        "auditctl",
                        "-W",
                        watched_path,
                        "-p",
                        "wa",
                        "-k",
                        AUDIT_KEY
                    ],
                    timeout=10
                )

    rule_path = Path(
        AUDIT_RULE_FILE
    )

    if rule_path.exists():

        try:
            rule_path.unlink()

        except Exception:
            pass

    print(
        "SSH Key Guard audit rules removed."
    )

    return True


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "ServerGuard SSH Key Guard"
        )
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    monitor_parser = subparsers.add_parser(
        "monitor"
    )

    monitor_parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL
    )

    subparsers.add_parser(
        "init"
    )

    subparsers.add_parser(
        "scan"
    )

    events_parser = subparsers.add_parser(
        "events"
    )

    events_parser.add_argument(
        "count",
        nargs="?",
        type=int,
        default=20
    )

    subparsers.add_parser(
        "audit"
    )

    subparsers.add_parser(
        "audit-remove"
    )

    subparsers.add_parser(
        "version"
    )

    args = parser.parse_args()

    if args.command == "monitor":

        interval = args.interval

        if interval < 1:
            interval = 1

        monitor(
            interval
        )

        return

    if args.command == "init":

        initialize()

        return

    if args.command == "scan":

        events = scan_once(
            initialize_if_missing=True
        )

        if not events:

            print(
                "No SSH key changes detected."
            )

            return

        for event in events:

            print(
                json.dumps(
                    event,
                    indent=2,
                    ensure_ascii=False
                )
            )

        return

    if args.command == "events":

        show_events(
            args.count
        )

        return

    if args.command == "audit":

        if os.geteuid() != 0:

            print(
                "Root privileges are required."
            )

            return

        show_audit_status()

        return

    if args.command == "audit-remove":

        remove_audit_rules()

        return

    if args.command == "version":

        show_version()

        return

    parser.print_help()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()

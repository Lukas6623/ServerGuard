#!/usr/bin/env python3

import argparse
import base64
import hashlib
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


def make_event_id(
    action,
    path,
    key,
    old_key=None
):
    raw = (
        str(time.time_ns())
        + "|"
        + str(os.getpid())
        + "|"
        + action
        + "|"
        + path
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

    digest = hashlib.sha256(
        raw.encode(
            "utf-8",
            errors="ignore"
        )
    ).hexdigest()

    return (
        str(int(time.time()))
        + "-"
        + str(os.getpid())
        + "-"
        + digest[:32]
    )


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
            "group": get_gid_name(
                stat.st_gid
            ),
            "mode": oct(
                stat.st_mode & 0o777
            ),
            "size": stat.st_size,
            "mtime": datetime.fromtimestamp(
                stat.st_mtime,
                tz=timezone.utc
            ).astimezone().isoformat(),
            "ctime": datetime.fromtimestamp(
                stat.st_ctime,
                tz=timezone.utc
            ).astimezone().isoformat()
        }

    except Exception:
        return {
            "uid": None,
            "user": "",
            "gid": None,
            "group": "",
            "mode": "",
            "size": None,
            "mtime": "",
            "ctime": ""
        }


def get_gid_name(gid):
    try:
        import grp

        return grp.getgrgid(
            int(gid)
        ).gr_name

    except Exception:
        return str(gid)


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

                ssh_dir = Path(
                    home
                ) / ".ssh"

                authorized_keys = (
                    ssh_dir
                    / AUTHORIZED_KEYS_NAME
                )

                result.append({
                    "username": username,
                    "uid": uid_int,
                    "home": home,
                    "shell": shell,
                    "ssh_dir": str(
                        ssh_dir
                    ),
                    "authorized_keys": str(
                        authorized_keys
                    )
                })

    except Exception:
        pass

    return result


# ============================================================
# ROOT SSH KEY
# ============================================================

def get_root_account():
    root_home = "/root"

    ssh_dir = Path(
        root_home
    ) / ".ssh"

    authorized_keys = (
        ssh_dir
        / AUTHORIZED_KEYS_NAME
    )

    return {
        "username": "root",
        "uid": 0,
        "home": root_home,
        "shell": get_shell_for_user(
            "root"
        ),
        "ssh_dir": str(
            ssh_dir
        ),
        "authorized_keys": str(
            authorized_keys
        )
    }


def get_shell_for_user(
    username
):
    try:
        return pwd.getpwnam(
            username
        ).pw_shell

    except Exception:
        return ""


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
    original = line.rstrip(
        "\n"
    )

    stripped = original.strip()

    if not stripped:
        return None

    if stripped.startswith("#"):
        return None

    parts = stripped.split()

    if len(parts) < 2:
        return None

    key_type = parts[0]

    # --------------------------------------------------------
    # SSH authorized_keys options
    # --------------------------------------------------------

    options = ""

    key_index = None

    for index, part in enumerate(parts):

        if part in KEY_TYPES:
            key_index = index
            break

    if key_index is None:
        return None

    if key_index > 0:
        options = " ".join(
            parts[:key_index]
        )

    key_type = parts[
        key_index
    ]

    if key_index + 1 >= len(parts):
        return None

    key_data = parts[
        key_index + 1
    ]

    comment = ""

    if len(parts) > key_index + 2:
        comment = " ".join(
            parts[
                key_index + 2:
            ]
        )

    fingerprint = ""

    try:
        key_bytes = base64.b64decode(
            key_data
            + "=" * (
                -len(key_data) % 4
            )
        )

        digest = hashlib.sha256(
            key_bytes
        ).digest()

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

    option_flags = parse_key_options(
        options
    )

    return {
        "line": line_number,
        "type": key_type,
        "key": key_data,
        "fingerprint": fingerprint,
        "comment": comment,
        "options": options,
        "option_flags": option_flags
    }


def parse_key_options(
    options
):
    result = {
        "from": "",
        "command": "",
        "environment": [],
        "expiry_time": "",
        "principals": "",
        "cert_authority": False,
        "no_agent_forwarding": False,
        "no_port_forwarding": False,
        "no_pty": False,
        "no_user_rc": False,
        "no_x11_forwarding": False,
        "restrict": False
    }

    if not options:
        return result

    parts = []

    current = ""

    inside_quotes = False

    escape = False

    for char in options:

        if escape:
            current += char
            escape = False
            continue

        if char == "\\":
            current += char
            escape = True
            continue

        if char == '"':
            inside_quotes = not inside_quotes
            current += char
            continue

        if char == "," and not inside_quotes:
            if current:
                parts.append(
                    current
                )
                current = ""
            continue

        current += char

    if current:
        parts.append(
            current
        )

    for option in parts:

        if option == "cert-authority":
            result[
                "cert_authority"
            ] = True

        elif option == "no-agent-forwarding":
            result[
                "no_agent_forwarding"
            ] = True

        elif option == "no-port-forwarding":
            result[
                "no_port_forwarding"
            ] = True

        elif option == "no-pty":
            result[
                "no_pty"
            ] = True

        elif option == "no-user-rc":
            result[
                "no_user_rc"
            ] = True

        elif option == "no-X11-forwarding":
            result[
                "no_x11_forwarding"
            ] = True

        elif option == "restrict":
            result[
                "restrict"
            ] = True

        elif option.startswith(
            "from="
        ):
            result[
                "from"
            ] = option[
                5:
            ]

        elif option.startswith(
            "command="
        ):
            result[
                "command"
            ] = option[
                8:
            ]

        elif option.startswith(
            "environment="
        ):
            result[
                "environment"
            ].append(
                option[
                    12:
                ]
            )

        elif option.startswith(
            "expiry-time="
        ):
            result[
                "expiry_time"
            ] = option[
                12:
            ]

        elif option.startswith(
            "principals="
        ):
            result[
                "principals"
            ] = option[
                11:
            ]

    return result


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

def key_identity(
    key
):
    return (
        key.get(
            "fingerprint"
        )
        or
        (
            key.get(
                "type",
                ""
            )
            + ":"
            +
            key.get(
                "key",
                ""
            )
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


def save_state(
    state
):
    save_json(
        STATE_FILE,
        state
    )


# ============================================================
# FILE SNAPSHOT
# ============================================================

def build_snapshot():
    snapshot = {}

    accounts = get_home_directories()

    root_account = get_root_account()

    root_exists = False

    for account in accounts:
        if account.get(
            "username"
        ) == "root":
            root_exists = True
            break

    if not root_exists:
        accounts.insert(
            0,
            root_account
        )

    for account in accounts:

        path = Path(
            account[
                "authorized_keys"
            ]
        )

        keys = read_authorized_keys(
            path
        )

        snapshot[
            str(path)
        ] = {
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
            "sha256": sha256_file(
                path
            ),
            "owner": get_file_owner(
                path
            ),
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
        "uid": "",
        "ppid": None,
        "parent_process": "",
        "parent_command": "",
        "start_time": ""
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

    # --------------------------------------------------------
    # Process name
    # --------------------------------------------------------

    try:
        result[
            "process"
        ] = (
            proc / "comm"
        ).read_text(
            encoding="utf-8",
            errors="ignore"
        ).strip()

    except Exception:
        pass

    # --------------------------------------------------------
    # Command line
    # --------------------------------------------------------

    try:
        result[
            "command"
        ] = (
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

    # --------------------------------------------------------
    # Executable
    # --------------------------------------------------------

    try:
        result[
            "exe"
        ] = os.readlink(
            str(
                proc / "exe"
            )
        )

    except Exception:
        pass

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

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

                    result[
                        "uid"
                    ] = parts[1]

                    result[
                        "user"
                    ] = uid_to_username(
                        parts[1]
                    )

            elif line.startswith(
                "PPid:"
            ):

                parts = line.split()

                if len(parts) >= 2:

                    result[
                        "ppid"
                    ] = int(
                        parts[1]
                    )

    except Exception:
        pass

    # --------------------------------------------------------
    # Parent
    # --------------------------------------------------------

    if result[
        "ppid"
    ]:

        try:
            parent_proc = (
                Path("/proc")
                /
                str(
                    result["ppid"]
                )
            )

            result[
                "parent_process"
            ] = (
                parent_proc / "comm"
            ).read_text(
                encoding="utf-8",
                errors="ignore"
            ).strip()

            result[
                "parent_command"
            ] = (
                parent_proc / "cmdline"
            ).read_bytes().replace(
                b"\x00",
                b" "
            ).decode(
                "utf-8",
                errors="ignore"
            ).strip()

        except Exception:
            pass

    # --------------------------------------------------------
    # Process start time
    # --------------------------------------------------------

    try:
        stat = (
            proc / "stat"
        ).read_text(
            encoding="utf-8",
            errors="ignore"
        )

        fields = stat.split()

        if len(fields) > 21:

            ticks = int(
                fields[21]
            )

            clock_ticks = os.sysconf(
                os.sysconf_names[
                    "SC_CLK_TCK"
                ]
            )

            boot_time = time.time()

            with open(
                "/proc/uptime",
                "r",
                encoding="utf-8"
            ) as uptime_file:

                uptime = float(
                    uptime_file.read().split()[0]
                )

            boot_time -= uptime

            process_start = (
                boot_time
                +
                (
                    ticks
                    /
                    clock_ticks
                )
            )

            result[
                "start_time"
            ] = datetime.fromtimestamp(
                process_start,
                tz=timezone.utc
            ).astimezone().isoformat()

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
    try:
        result = subprocess.run(
            [
                "sh",
                "-c",
                "command -v auditctl >/dev/null 2>&1"
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return result.returncode == 0

    except Exception:
        return False


def ensure_audit_rules():
    if os.geteuid() != 0:
        return False

    if not auditd_available():
        return False

    rules = []

    # --------------------------------------------------------
    # Root
    # --------------------------------------------------------

    rules.append(
        "-w /root/.ssh/authorized_keys "
        "-p wa "
        "-k serverguard_ssh_keys"
    )

    # --------------------------------------------------------
    # Existing home directories
    # --------------------------------------------------------

    for account in get_home_directories():

        path = account.get(
            "authorized_keys",
            ""
        )

        if not path:
            continue

        if path == "/root/.ssh/authorized_keys":
            continue

        rules.append(
            "-w "
            + path
            + " "
            "-p wa "
            "-k serverguard_ssh_keys"
        )

    # --------------------------------------------------------
    # Remove duplicates
    # --------------------------------------------------------

    unique_rules = []

    seen = set()

    for rule in rules:

        if rule in seen:
            continue

        seen.add(
            rule
        )

        unique_rules.append(
            rule
        )

    rules_text = (
        "\n".join(
            unique_rules
        )
        + "\n"
    )

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
            rules_text,
            encoding="utf-8"
        )

    except Exception:
        return False

    code, stdout, stderr = run_command(
        [
            "auditctl",
            "-R",
            AUDIT_RULE_FILE
        ],
        timeout=10
    )

    return code == 0


# ============================================================
# AUDIT LOG
# ============================================================

def parse_audit_timestamp(
    line
):
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
    path=None
):
    events = []

    if not auditd_available():
        return events

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

                current[
                    key
                ] = value

    if current:

        events.append(
            current
        )

    # --------------------------------------------------------
    # Optional path filtering
    # --------------------------------------------------------

    if path:

        filtered = []

        path_string = str(
            path
        )

        for event in events:

            name = event.get(
                "name",
                ""
            )

            if not name:
                filtered.append(
                    event
                )
                continue

            if name == path_string:
                filtered.append(
                    event
                )

        if filtered:
            return filtered

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

    for event in reversed(
        events
    ):

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
        "user": (
            uid_to_username(uid)
            if str(uid).isdigit()
            else ""
        ),
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
        ),
        "exit": event.get(
            "exit",
            ""
        ),
        "syscall": event.get(
            "syscall",
            ""
        ),
        "name": event.get(
            "name",
            ""
        )
    }

    pid = result[
        "pid"
    ]

    if pid:

        proc = process_info(
            pid
        )

        if proc.get(
            "command"
        ):
            result[
                "command"
            ] = proc[
                "command"
            ]

        if not result[
            "process"
        ]:
            result[
                "process"
            ] = proc.get(
                "process",
                ""
            )

        if not result[
            "exe"
        ]:
            result[
                "exe"
            ] = proc.get(
                "exe",
                ""
            )

        if not result[
            "ppid"
        ]:
            result[
                "ppid"
            ] = proc.get(
                "ppid",
                ""
            )

        if not result[
            "user"
        ]:
            result[
                "user"
            ] = proc.get(
                "user",
                ""
            )

        result[
            "process_start"
        ] = proc.get(
            "start_time",
            ""
        )

        result[
            "parent_process"
        ] = proc.get(
            "parent_process",
            ""
        )

        result[
            "parent_command"
        ] = proc.get(
            "parent_command",
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

        if "ESTAB" not in line:
            continue

        parts = line.split()

        if len(parts) < 5:
            continue

        local_address = parts[3]
        remote_address = parts[4]

        if (
            ":22" not in local_address
            and
            ":ssh" not in local_address
        ):
            continue

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

        if not remote:
            continue

        # ----------------------------------------------------
        # IPv4
        # ----------------------------------------------------

        if "." in remote:

            remote = remote.rsplit(
                ":",
                1
            )[0]

            return remote

        # ----------------------------------------------------
        # IPv6
        # ----------------------------------------------------

        if remote.startswith(
            "["
        ):

            remote = remote[
                1:
            ]

            if "]" in remote:

                remote = remote.split(
                    "]",
                    1
                )[0]

            return remote

    return ""


# ============================================================
# SSH AUTH LOG
# ============================================================

def get_recent_ssh_auth_events(
    minutes=10
):
    result = []

    commands = [
        [
            "journalctl",
            "-u",
            "ssh",
            "--since",
            f"{minutes} minutes ago",
            "--no-pager",
            "-o",
            "short-iso"
        ],
        [
            "journalctl",
            "-u",
            "sshd",
            "--since",
            f"{minutes} minutes ago",
            "--no-pager",
            "-o",
            "short-iso"
        ]
    ]

    seen = set()

    for command in commands:

        code, stdout, stderr = run_command(
            command,
            timeout=8
        )

        if code != 0:
            continue

        for line in stdout.splitlines():

            if not line:
                continue

            if (
                "Accepted " not in line
                and
                "authentication" not in line.lower()
                and
                "session opened" not in line.lower()
            ):
                continue

            if line in seen:
                continue

            seen.add(
                line
            )

            result.append(
                line
            )

    return result[-20:]


def find_auth_source_ip(
    username=""
):
    lines = get_recent_ssh_auth_events(
        15
    )

    ipv4_pattern = re.compile(
        r"(?:from\s+)(\d{1,3}(?:\.\d{1,3}){3})"
    )

    ipv6_pattern = re.compile(
        r"(?:from\s+)([0-9a-fA-F:]+)"
    )

    for line in reversed(
        lines
    ):

        if username and username not in line:
            continue

        match = ipv4_pattern.search(
            line
        )

        if match:
            return match.group(1)

        match = ipv6_pattern.search(
            line
        )

        if match:
            return match.group(1)

    return ""


# ============================================================
# GEOIP
# ============================================================

def geoip(
    ip
):
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
            ),
            "timezone": data.get(
                "timezone",
                ""
            ),
            "loc": data.get(
                "loc",
                ""
            )
        }

    except Exception:
        return {}


# ============================================================
# FILE DIFFERENCE
# ============================================================

def map_keys(
    keys
):
    result = {}

    for key in keys:

        identity = key_identity(
            key
        )

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
# KEY METADATA
# ============================================================

def get_key_metadata(
    key
):
    if not key:
        return {}

    return {
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
        ),
        "options": key.get(
            "options",
            ""
        ),
        "option_flags": key.get(
            "option_flags",
            {}
        )
    }


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

    # --------------------------------------------------------
    # Source IP
    # --------------------------------------------------------

    source_ip = (
        audit_context.get(
            "source_ip"
        )
        or
        find_auth_source_ip(
            account.get(
                "username",
                ""
            )
        )
        or
        find_ssh_source_ip()
    )

    # --------------------------------------------------------
    # GeoIP
    # --------------------------------------------------------

    geo = geoip(
        source_ip
    )

    # --------------------------------------------------------
    # File metadata
    # --------------------------------------------------------

    file_path = Path(
        path
    )

    owner = get_file_owner(
        file_path
    )

    # --------------------------------------------------------
    # Event
    # --------------------------------------------------------

    event = {
        "id": make_event_id(
            action,
            path,
            key,
            old_key
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
            "exists": file_path.exists(),
            "sha256": sha256_file(
                file_path
            ),
            "owner": owner
        },

        "key": get_key_metadata(
            key
        ),

        "old_key": get_key_metadata(
            old_key
        ),

        "modifier": audit_context,

        "network": {
            "source_ip": source_ip,
            "geo": geo
        },

        "authentication": {
            "recent_ssh_events":
                get_recent_ssh_auth_events(
                    15
                )
        },

        "server": {
            "hostname": socket.gethostname(),
            "kernel": (
                os.uname().release
                if hasattr(
                    os,
                    "uname"
                )
                else ""
            ),
            "python": (
                subprocess.run(
                    [
                        "python3",
                        "--version"
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                ).stdout.strip()
            )
        }
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

    total_keys = 0

    for data in snapshot.values():

        total_keys += len(
            data.get(
                "keys",
                []
            )
        )

    print(
        f"Tracked SSH keys: {total_keys}"
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

    # --------------------------------------------------------
    # Check current files
    # --------------------------------------------------------

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

        # ----------------------------------------------------
        # Audit context
        # ----------------------------------------------------

        audit_context = {}

        try:

            before_audit = (
                audit_recent_events(
                    path
                )
            )

            time.sleep(
                0.1
            )

            audit_context = (
                find_audit_context(
                    path,
                    before_audit
                )
            )

        except Exception:
            audit_context = {}

        # ----------------------------------------------------
        # Added keys
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # Removed keys
        # ----------------------------------------------------

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

    # --------------------------------------------------------
    # Detect new authorized_keys files
    # --------------------------------------------------------

    for path, old_data in old_snapshot.items():

        if path in new_snapshot:
            continue

        if not old_data.get(
            "exists",
            False
        ):
            continue

        account = {
            "username": old_data.get(
                "username",
                ""
            ),
            "uid": old_data.get(
                "uid"
            ),
            "home": old_data.get(
                "home",
                ""
            ),
            "shell": old_data.get(
                "shell",
                ""
            )
        }

        old_keys = old_data.get(
            "keys",
            []
        )

        for key in old_keys:

            event = create_event(
                "authorized_keys_removed",
                path,
                account,
                key=None,
                old_key=key
            )

            save_event(
                event
            )

            generated_events.append(
                event
            )

    # --------------------------------------------------------
    # Save state
    # --------------------------------------------------------

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
# FORMAT EVENT FOR LOG
# ============================================================

def format_event(
    event
):
    lines = []

    lines.append(
        "========================================"
    )

    lines.append(
        "SERVERGUARD SSH KEY EVENT"
    )

    lines.append(
        "========================================"
    )

    lines.append(
        f"Action: {event.get('action', '')}"
    )

    lines.append(
        f"Time: {event.get('timestamp', '')}"
    )

    lines.append(
        f"UTC: {event.get('timestamp_utc', '')}"
    )

    lines.append(
        f"Event ID: {event.get('id', '')}"
    )

    # --------------------------------------------------------
    # Account
    # --------------------------------------------------------

    account = event.get(
        "account",
        {}
    )

    lines.append(
        ""
    )

    lines.append(
        "ACCOUNT"
    )

    lines.append(
        f"User: {account.get('username', '')}"
    )

    lines.append(
        f"UID: {account.get('uid', '')}"
    )

    lines.append(
        f"Home: {account.get('home', '')}"
    )

    lines.append(
        f"Shell: {account.get('shell', '')}"
    )

    # --------------------------------------------------------
    # Key
    # --------------------------------------------------------

    key = event.get(
        "key",
        {}
    )

    old_key = event.get(
        "old_key",
        {}
    )

    lines.append(
        ""
    )

    lines.append(
        "SSH KEY"
    )

    if key:

        lines.append(
            f"Type: {key.get('type', '')}"
        )

        lines.append(
            f"Fingerprint: "
            f"{key.get('fingerprint', '')}"
        )

        lines.append(
            f"Comment: "
            f"{key.get('comment', '')}"
        )

        lines.append(
            f"Line: {key.get('line', '')}"
        )

        lines.append(
            f"Options: "
            f"{key.get('options', '')}"
        )

    if old_key:

        lines.append(
            f"Old type: "
            f"{old_key.get('type', '')}"
        )

        lines.append(
            f"Old fingerprint: "
            f"{old_key.get('fingerprint', '')}"
        )

        lines.append(
            f"Old comment: "
            f"{old_key.get('comment', '')}"
        )

    # --------------------------------------------------------
    # File
    # --------------------------------------------------------

    file_data = event.get(
        "file",
        {}
    )

    owner = file_data.get(
        "owner",
        {}
    )

    lines.append(
        ""
    )

    lines.append(
        "FILE"
    )

    lines.append(
        f"Path: "
        f"{file_data.get('path', '')}"
    )

    lines.append(
        f"SHA256: "
        f"{file_data.get('sha256', '')}"
    )

    lines.append(
        f"Owner: "
        f"{owner.get('user', '')}"
    )

    lines.append(
        f"UID: "
        f"{owner.get('uid', '')}"
    )

    lines.append(
        f"Group: "
        f"{owner.get('group', '')}"
    )

    lines.append(
        f"Mode: "
        f"{owner.get('mode', '')}"
    )

    lines.append(
        f"Size: "
        f"{owner.get('size', '')}"
    )

    lines.append(
        f"Modified: "
        f"{owner.get('mtime', '')}"
    )

    lines.append(
        f"Changed: "
        f"{owner.get('ctime', '')}"
    )

    # --------------------------------------------------------
    # Modifier
    # --------------------------------------------------------

    modifier = event.get(
        "modifier",
        {}
    )

    lines.append(
        ""
    )

    lines.append(
        "MODIFIER / AUDIT"
    )

    lines.append(
        f"User: "
        f"{modifier.get('user', '')}"
    )

    lines.append(
        f"Audit user: "
        f"{modifier.get('audit_user', '')}"
    )

    lines.append(
        f"UID: "
        f"{modifier.get('uid', '')}"
    )

    lines.append(
        f"AUID: "
        f"{modifier.get('auid', '')}"
    )

    lines.append(
        f"Session: "
        f"{modifier.get('session', '')}"
    )

    lines.append(
        f"Process: "
        f"{modifier.get('process', '')}"
    )

    lines.append(
        f"PID: "
        f"{modifier.get('pid', '')}"
    )

    lines.append(
        f"PPID: "
        f"{modifier.get('ppid', '')}"
    )

    lines.append(
        f"Executable: "
        f"{modifier.get('exe', '')}"
    )

    lines.append(
        f"Command: "
        f"{modifier.get('command', '')}"
    )

    lines.append(
        f"Parent process: "
        f"{modifier.get('parent_process', '')}"
    )

    lines.append(
        f"Parent command: "
        f"{modifier.get('parent_command', '')}"
    )

    lines.append(
        f"CWD: "
        f"{modifier.get('cwd', '')}"
    )

    lines.append(
        f"Syscall: "
        f"{modifier.get('syscall', '')}"
    )

    lines.append(
        f"Success: "
        f"{modifier.get('success', '')}"
    )

    lines.append(
        f"Exit: "
        f"{modifier.get('exit', '')}"
    )

    lines.append(
        f"Terminal: "
        f"{modifier.get('terminal', '')}"
    )

    lines.append(
        f"Audit timestamp: "
        f"{modifier.get('timestamp', '')}"
    )

    # --------------------------------------------------------
    # Network
    # --------------------------------------------------------

    network = event.get(
        "network",
        {}
    )

    geo = network.get(
        "geo",
        {}
    )

    lines.append(
        ""
    )

    lines.append(
        "NETWORK"
    )

    lines.append(
        f"Source IP: "
        f"{network.get('source_ip', '')}"
    )

    if geo:

        lines.append(
            f"Country: "
            f"{geo.get('country', '')}"
        )

        lines.append(
            f"Region: "
            f"{geo.get('region', '')}"
        )

        lines.append(
            f"City: "
            f"{geo.get('city', '')}"
        )

        lines.append(
            f"Organization: "
            f"{geo.get('organization', '')}"
        )

        lines.append(
            f"Hostname: "
            f"{geo.get('hostname', '')}"
        )

        lines.append(
            f"Timezone: "
            f"{geo.get('timezone', '')}"
        )

        lines.append(
            f"Coordinates: "
            f"{geo.get('loc', '')}"
        )

    # --------------------------------------------------------
    # Server
    # --------------------------------------------------------

    server = event.get(
        "server",
        {}
    )

    lines.append(
        ""
    )

    lines.append(
        "SERVER"
    )

    lines.append(
        f"Hostname: "
        f"{server.get('hostname', '')}"
    )

    lines.append(
        f"Kernel: "
        f"{server.get('kernel', '')}"
    )

    lines.append(
        f"Python: "
        f"{server.get('python', '')}"
    )

    lines.append(
        "========================================"
    )

    return "\n".join(
        lines
    )


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
                    format_event(
                        event
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

    selected = events[
        -limit:
    ]

    for event in selected:

        print(
            format_event(
                event
            )
        )


# ============================================================
# SHOW AUDIT
# ============================================================

def show_audit(
    limit=20
):
    events = audit_recent_events()

    if not events:

        print(
            "No recent audit events."
        )

        return

    print(
        "========================================"
    )

    print(
        "SERVERGUARD SSH KEY AUDIT"
    )

    print(
        "========================================"
    )

    for event in events[
        -limit:
    ]:

        print(
            ""
        )

        print(
            f"Timestamp: "
            f"{event.get('timestamp', '')}"
        )

        print(
            f"PID: "
            f"{event.get('pid', '')}"
        )

        print(
            f"PPID: "
            f"{event.get('ppid', '')}"
        )

        print(
            f"UID: "
            f"{event.get('uid', '')}"
        )

        print(
            f"AUID: "
            f"{event.get('auid', '')}"
        )

        print(
            f"Process: "
            f"{event.get('comm', '')}"
        )

        print(
            f"Executable: "
            f"{event.get('exe', '')}"
        )

        print(
            f"File: "
            f"{event.get('name', '')}"
        )

        print(
            f"Command/CWD: "
            f"{event.get('cwd', '')}"
        )

        print(
            f"Source IP: "
            f"{event.get('addr', '')}"
        )

        print(
            f"Success: "
            f"{event.get('success', '')}"
        )

        print(
            f"Syscall: "
            f"{event.get('syscall', '')}"
        )

        print(
            "----------------------------------------"
        )


# ============================================================
# SCAN NOW
# ============================================================

def scan_command():
    events = scan_once()

    print(
        f"New events: {len(events)}"
    )

    for event in events:

        print(
            format_event(
                event
            )
        )


# ============================================================
# VERSION
# ============================================================

def show_version():
    print(
        f"ServerGuard SSH Key Guard {VERSION}"
    )


# ============================================================
# STATUS
# ============================================================

def show_status():
    state = load_state()

    print(
        "========================================"
    )

    print(
        "SERVERGUARD SSH KEY GUARD STATUS"
    )

    print(
        "========================================"
    )

    print(
        f"Version: {VERSION}"
    )

    print(
        f"Running as UID: {os.geteuid()}"
    )

    print(
        f"Data directory: {DATA_DIR}"
    )

    print(
        f"Events file: {EVENTS_FILE}"
    )

    print(
        f"State file: {STATE_FILE}"
    )

    print(
        f"Auditd: "
        f"{'available' if auditd_available() else 'not available'}"
    )

    print(
        f"Tracked files: "
        f"{len(state.get('files', {}))}"
    )

    total_keys = 0

    for data in state.get(
        "files",
        {}
    ).values():

        total_keys += len(
            data.get(
                "keys",
                []
            )
        )

    print(
        f"Tracked SSH keys: "
        f"{total_keys}"
    )

    print(
        f"Last scan: "
        f"{state.get('last_scan', '')}"
    )

    print(
        "========================================"
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

    # ========================================================
    # MONITOR
    # ========================================================

    if command == "monitor":

        monitor(
            max(
                1,
                args.interval
            )
        )

    # ========================================================
    # INITIALIZE
    # ========================================================

    elif command == "init":

        initialize()

    # ========================================================
    # SCAN
    # ========================================================

    elif command == "scan":

        scan_command()

    # ========================================================
    # EVENTS
    # ========================================================

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

    # ========================================================
    # AUDIT
    # ========================================================

    elif command == "audit":

        if ensure_audit_rules():

            print(
                "ServerGuard audit rules installed."
            )

        else:

            print(
                "Failed to install audit rules."
            )

    # ========================================================
    # AUDIT EVENTS
    # ========================================================

    elif command == "audit-events":

        try:

            limit = int(
                args.value
                or 20
            )

        except Exception:

            limit = 20

        show_audit(
            max(
                1,
                limit
            )
        )

    # ========================================================
    # STATUS
    # ========================================================

    elif command == "status":

        show_status()

    # ========================================================
    # VERSION
    # ========================================================

    elif command == "version":

        show_version()

    # ========================================================
    # HELP
    # ========================================================

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
            "  audit-events [COUNT]"
        )

        print(
            "  status"
        )

        print(
            "  version"
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()

#!/usr/bin/env python3

import json
import os
import re
import subprocess
import sys
import time

from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(
    "/opt/serverguard"
)

DATA_DIR = BASE_DIR / "data"

PROTECTION_CONFIG_FILE = (
    DATA_DIR / "protection_config.json"
)

EVENTS_FILE = (
    DATA_DIR / "ssh_events.json"
)

BLOCKS_FILE = (
    DATA_DIR / "blocked_ips.json"
)

STATS_FILE = (
    DATA_DIR / "stats.json"
)


MAX_EVENTS = 2000

EVENT_RETENTION_DAYS = 7

CLEANUP_INTERVAL = 60

CONFIG_CHECK_INTERVAL = 5


# ============================================================
# DEFAULT PROTECTION
# ============================================================

DEFAULT_CONFIG = {

    "enabled": True,

    "attempts": 5,

    "duration": 600,

    "permanent": False,

    "mode": "ip",

    "whitelist": []
}


# ============================================================
# RUNTIME
# ============================================================

FAILED_ATTEMPTS = {}

LAST_CONFIG_LOAD = 0

CACHED_CONFIG = dict(
    DEFAULT_CONFIG
)


# ============================================================
# LOG
# ============================================================

def log(
    message
):

    print(
        f"[ServerGuard] {message}",
        flush=True
    )


# ============================================================
# DIRECTORIES
# ============================================================

def ensure_directories():

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


# ============================================================
# JSON LOAD
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

            data = json.load(
                file
            )

        return data

    except Exception as e:

        log(
            f"JSON load error {path}: {e}"
        )

        return default


# ============================================================
# JSON SAVE
# ============================================================

def save_json(
    path,
    data
):

    temp = path.with_suffix(
        ".tmp"
    )

    try:

        path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with temp.open(
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                data,
                file,
                indent=2,
                ensure_ascii=False
            )

            file.write(
                "\n"
            )

        temp.replace(
            path
        )

        return True

    except Exception as e:

        log(
            f"JSON save error {path}: {e}"
        )

        try:

            if temp.exists():

                temp.unlink()

        except Exception:

            pass

        return False


# ============================================================
# LOAD PROTECTION CONFIG
# ============================================================

def load_protection_config():

    global CACHED_CONFIG
    global LAST_CONFIG_LOAD

    now = time.time()

    if (
        now - LAST_CONFIG_LOAD
        < CONFIG_CHECK_INTERVAL
    ):

        return dict(
            CACHED_CONFIG
        )

    LAST_CONFIG_LOAD = now

    data = load_json(
        PROTECTION_CONFIG_FILE,
        dict(DEFAULT_CONFIG)
    )

    if not isinstance(
        data,
        dict
    ):

        data = dict(
            DEFAULT_CONFIG
        )

    config = dict(
        DEFAULT_CONFIG
    )

    config.update(
        data
    )

    # --------------------------------------------------------
    # ENABLED
    # --------------------------------------------------------

    enabled = config.get(
        "enabled",
        True
    )

    if isinstance(
        enabled,
        str
    ):

        enabled = (
            enabled.lower()
            in (
                "1",
                "true",
                "yes",
                "on",
                "enabled"
            )
        )

    config["enabled"] = bool(
        enabled
    )

    # --------------------------------------------------------
    # ATTEMPTS
    # --------------------------------------------------------

    try:

        attempts = int(
            config.get(
                "attempts",
                5
            )
        )

    except Exception:

        attempts = 5

    config["attempts"] = max(
        1,
        min(
            attempts,
            100
        )
    )

    # --------------------------------------------------------
    # DURATION
    # --------------------------------------------------------

    try:

        duration = int(
            config.get(
                "duration",
                600
            )
        )

    except Exception:

        duration = 600

    config["duration"] = max(
        60,
        min(
            duration,
            30 * 24 * 60 * 60
        )
    )

    # --------------------------------------------------------
    # PERMANENT
    # --------------------------------------------------------

    permanent = config.get(
        "permanent",
        False
    )

    if isinstance(
        permanent,
        str
    ):

        permanent = (
            permanent.lower()
            in (
                "1",
                "true",
                "yes",
                "on",
                "enabled"
            )
        )

    config["permanent"] = bool(
        permanent
    )

    # --------------------------------------------------------
    # WHITELIST
    # --------------------------------------------------------

    whitelist = config.get(
        "whitelist",
        []
    )

    if not isinstance(
        whitelist,
        list
    ):

        whitelist = []

    clean = []

    for ip in whitelist:

        ip = str(
            ip
        ).strip()

        if ip and ip not in clean:

            clean.append(
                ip
            )

    config["whitelist"] = clean

    # --------------------------------------------------------
    # MODE
    # --------------------------------------------------------

    config["mode"] = "ip"

    CACHED_CONFIG = config

    return dict(
        config
    )


# ============================================================
# DATETIME
# ============================================================

def utc_iso(
    timestamp=None
):

    if timestamp is None:

        timestamp = time.time()

    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc
    ).isoformat()


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


def save_event(
    event_type,
    ip,
    username="unknown",
    auth_method="",
    raw=""
):

    events = load_events()

    event = {

        "time":
            int(time.time()),

        "time_iso":
            utc_iso(),

        "type":
            event_type,

        "username":
            username,

        "ip":
            ip,

        "auth_method":
            auth_method,

        "raw":
            raw
    }

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
# BLOCKS
# ============================================================

def load_blocks():

    data = load_json(
        BLOCKS_FILE,
        {}
    )

    if not isinstance(
        data,
        dict
    ):

        return {}

    return data


def save_blocks(
    blocks
):

    save_json(
        BLOCKS_FILE,
        blocks
    )


# ============================================================
# STATS
# ============================================================

def load_stats():

    data = load_json(
        STATS_FILE,
        {}
    )

    if not isinstance(
        data,
        dict
    ):

        data = {}

    return data


def update_stat(
    name
):

    stats = load_stats()

    try:

        stats[name] = (
            int(
                stats.get(
                    name,
                    0
                )
            )
            + 1
        )

    except Exception:

        stats[name] = 1

    save_json(
        STATS_FILE,
        stats
    )


# ============================================================
# UFW CHECK
# ============================================================

def ufw_is_blocked(
    ip
):

    try:

        result = subprocess.run(

            [
                "ufw",
                "status"
            ],

            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:

            return False

        return (
            ip in result.stdout
            and
            "DENY" in result.stdout
        )

    except Exception as e:

        log(
            f"UFW status error: {e}"
        )

        return False


# ============================================================
# UFW BLOCK
# ============================================================

def ufw_block(
    ip
):

    try:

        if ufw_is_blocked(
            ip
        ):

            return True

        result = subprocess.run(

            [
                "ufw",
                "insert",
                "1",
                "deny",
                "from",
                ip
            ],

            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode == 0:

            log(
                f"[BLOCK] {ip}"
            )

            return True

        log(
            f"[BLOCK ERROR] {ip}: "
            f"{result.stderr.strip()}"
        )

        return False

    except Exception as e:

        log(
            f"[BLOCK ERROR] {ip}: {e}"
        )

        return False


# ============================================================
# UFW UNBLOCK
# ============================================================

def ufw_unblock(
    ip
):

    try:

        result = subprocess.run(

            [
                "ufw",
                "delete",
                "deny",
                "from",
                ip
            ],

            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode == 0:

            log(
                f"[UNBLOCK] {ip}"
            )

            return True

        output = (
            result.stdout
            + "\n"
            + result.stderr
        ).lower()

        if (
            "could not delete" in output
            or
            "not found" in output
            or
            "no rules found" in output
        ):

            return True

        log(
            f"[UNBLOCK ERROR] {ip}: "
            f"{result.stderr.strip()}"
        )

        return False

    except Exception as e:

        log(
            f"[UNBLOCK ERROR] {ip}: {e}"
        )

        return False


# ============================================================
# WHITELIST
# ============================================================

def is_whitelisted(
    ip,
    config
):

    return ip in config.get(
        "whitelist",
        []
    )


# ============================================================
# CREATE BLOCK RECORD
# ============================================================

def create_block(
    ip,
    failed_attempts,
    config
):

    now = int(
        time.time()
    )

    permanent = bool(
        config.get(
            "permanent",
            False
        )
    )

    duration = int(
        config.get(
            "duration",
            600
        )
    )

    if permanent:

        expires_at = None

    else:

        expires_at = (
            now
            + duration
        )

    blocks = load_blocks()

    blocks[ip] = {

        "ip":
            ip,

        "blocked_at":
            now,

        "blocked_at_iso":
            utc_iso(now),

        "failed_attempts":
            failed_attempts,

        "permanent":
            permanent,

        "duration":
            duration,

        "expires_at":
            expires_at,

        "expires_at_iso":
            (
                None
                if expires_at is None
                else
                utc_iso(expires_at)
            ),

        "reason":
            "SSH brute-force protection"
    }

    save_blocks(
        blocks
    )


# ============================================================
# BLOCK IP
# ============================================================

def block_ip(
    ip,
    failed_attempts,
    config
):

    if is_whitelisted(
        ip,
        config
    ):

        log(
            f"[WHITELIST] "
            f"Skipping block for {ip}"
        )

        return False

    if ip in get_local_ips():

        log(
            f"[SAFETY] "
            f"Skipping local/server IP {ip}"
        )

        return False

    success = ufw_block(
        ip
    )

    if not success:

        return False

    create_block(
        ip,
        failed_attempts,
        config
    )

    update_stat(
        "blocked"
    )

    if config.get(
        "permanent",
        False
    ):

        log(
            f"[BLOCK] {ip} "
            f"PERMANENT "
            f"after {failed_attempts} failed attempts"
        )

    else:

        log(
            f"[BLOCK] {ip} "
            f"for {config['duration']} seconds "
            f"after {failed_attempts} failed attempts"
        )

    return True


# ============================================================
# LOCAL SERVER IPS
# ============================================================

def get_local_ips():

    result = set()

    try:

        output = subprocess.check_output(

            [
                "hostname",
                "-I"
            ],

            text=True,
            timeout=5
        )

        for ip in output.split():

            result.add(
                ip.strip()
            )

    except Exception:
        pass

    result.add(
        "127.0.0.1"
    )

    result.add(
        "::1"
    )

    return result


# ============================================================
# EXPIRE BLOCKS
# ============================================================

def expire_blocks():

    blocks = load_blocks()

    if not blocks:

        return

    now = int(
        time.time()
    )

    changed = False

    for ip in list(
        blocks.keys()
    ):

        block = blocks.get(
            ip
        )

        if not isinstance(
            block,
            dict
        ):

            del blocks[ip]

            changed = True

            continue

        if block.get(
            "permanent",
            False
        ):

            continue

        expires_at = block.get(
            "expires_at"
        )

        if expires_at is None:

            continue

        try:

            expires_at = int(
                expires_at
            )

        except Exception:

            del blocks[ip]

            changed = True

            continue

        if expires_at <= now:

            if ufw_unblock(
                ip
            ):

                del blocks[ip]

                changed = True

                update_stat(
                    "unblocked"
                )

                log(
                    f"[EXPIRED] "
                    f"{ip} temporary block expired"
                )

    if changed:

        save_blocks(
            blocks
        )


# ============================================================
# CLEAN OLD EVENTS
# ============================================================

def cleanup_events():

    events = load_events()

    if not events:

        return

    cutoff = (
        time.time()
        - (
            EVENT_RETENTION_DAYS
            * 86400
        )
    )

    cleaned = []

    for event in events:

        if not isinstance(
            event,
            dict
        ):

            continue

        timestamp = event.get(
            "time"
        )

        try:

            timestamp = int(
                timestamp
            )

        except Exception:

            timestamp = int(
                time.time()
            )

        if timestamp >= cutoff:

            cleaned.append(
                event
            )

    if len(cleaned) > MAX_EVENTS:

        cleaned = cleaned[
            -MAX_EVENTS:
        ]

    if len(cleaned) != len(events):

        save_json(
            EVENTS_FILE,
            cleaned
        )


# ============================================================
# CLEAN RUNTIME COUNTERS
# ============================================================

def cleanup_attempts():

    now = time.time()

    for ip in list(
        FAILED_ATTEMPTS.keys()
    ):

        data = FAILED_ATTEMPTS.get(
            ip
        )

        if not isinstance(
            data,
            dict
        ):

            del FAILED_ATTEMPTS[ip]

            continue

        last = data.get(
            "last"
        )

        if last is None:

            del FAILED_ATTEMPTS[ip]

            continue

        if (
            now - last
            > 3600
        ):

            del FAILED_ATTEMPTS[ip]


# ============================================================
# PARSE FAILED SSH LOGIN
# ============================================================

FAILED_PATTERNS = [

    re.compile(
        r"Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F\.:]+)"
    ),

    re.compile(
        r"Failed publickey for (?:invalid user )?(\S+) from ([0-9a-fA-F\.:]+)"
    ),

    re.compile(
        r"Invalid user (\S+) from ([0-9a-fA-F\.:]+)"
    ),

    re.compile(
        r"authentication failure.*rhost=([0-9a-fA-F\.:]+)"
    )
]


# ============================================================
# PARSE SUCCESSFUL SSH LOGIN
# ============================================================

SUCCESS_PATTERNS = [

    re.compile(
        r"Accepted password for (\S+) from ([0-9a-fA-F\.:]+)"
    ),

    re.compile(
        r"Accepted publickey for (\S+) from ([0-9a-fA-F\.:]+)"
    ),

    re.compile(
        r"Accepted keyboard-interactive/pam for (\S+) from ([0-9a-fA-F\.:]+)"
    )
]


# ============================================================
# HANDLE FAILED LOGIN
# ============================================================

def handle_failed_login(
    username,
    ip,
    raw
):

    config = load_protection_config()

    save_event(
        "failed",
        ip,
        username,
        "",
        raw
    )

    update_stat(
        "failed"
    )

    if not config.get(
        "enabled",
        True
    ):

        return

    if is_whitelisted(
        ip,
        config
    ):

        log(
            f"[WHITELIST] "
            f"Failed SSH from {ip}"
        )

        return

    current = FAILED_ATTEMPTS.get(
        ip,
        {
            "count": 0,
            "last": 0
        }
    )

    current["count"] = (
        int(
            current.get(
                "count",
                0
            )
        )
        + 1
    )

    current["last"] = time.time()

    FAILED_ATTEMPTS[
        ip
    ] = current

    attempts = current[
        "count"
    ]

    threshold = int(
        config.get(
            "attempts",
            5
        )
    )

    log(
        f"[SSH FAILED] "
        f"IP={ip} "
        f"user={username} "
        f"attempt={attempts}/{threshold}"
    )

    if attempts < threshold:

        return

    blocks = load_blocks()

    existing = blocks.get(
        ip
    )

    if isinstance(
        existing,
        dict
    ):

        if existing.get(
            "permanent",
            False
        ):

            return

        expires_at = existing.get(
            "expires_at"
        )

        if expires_at:

            try:

                if int(
                    expires_at
                ) > int(
                    time.time()
                ):

                    return

            except Exception:

                pass

    if block_ip(
        ip,
        attempts,
        config
    ):

        FAILED_ATTEMPTS.pop(
            ip,
            None
        )


# ============================================================
# HANDLE SUCCESSFUL LOGIN
# ============================================================

def handle_success_login(
    username,
    ip,
    auth_method,
    raw
):

    save_event(
        "success",
        ip,
        username,
        auth_method,
        raw
    )

    update_stat(
        "success"
    )

    if ip in FAILED_ATTEMPTS:

        del FAILED_ATTEMPTS[
            ip
        ]

        log(
            f"[SSH SUCCESS] "
            f"{ip} counter reset"
        )

    else:

        log(
            f"[SSH SUCCESS] "
            f"{ip}"
        )


# ============================================================
# PROCESS LINE
# ============================================================

def process_line(
    line
):

    if not line:

        return

    # --------------------------------------------------------
    # SUCCESS
    # --------------------------------------------------------

    for pattern in SUCCESS_PATTERNS:

        match = pattern.search(
            line
        )

        if match:

            username = match.group(
                1
            )

            ip = match.group(
                2
            )

            if "publickey" in line:

                auth_method = "publickey"

            elif "keyboard-interactive" in line:

                auth_method = (
                    "keyboard-interactive"
                )

            else:

                auth_method = "password"

            handle_success_login(

                username,
                ip,
                auth_method,
                line.strip()
            )

            return

    # --------------------------------------------------------
    # FAILED
    # --------------------------------------------------------

    for pattern in FAILED_PATTERNS:

        match = pattern.search(
            line
        )

        if not match:

            continue

        groups = match.groups()

        if len(groups) >= 2:

            username = groups[0]
            ip = groups[1]

        else:

            username = "unknown"
            ip = groups[0]

        handle_failed_login(

            username,
            ip,
            line.strip()
        )

        return


# ============================================================
# JOURNAL PROCESS
# ============================================================

def run_journal():

    command = [

        "journalctl",

        "-f",

        "-n",
        "0",

        "-u",
        "ssh",

        "-u",
        "sshd",

        "-o",
        "cat"
    ]

    log(
        "Starting SSH journal monitor..."
    )

    while True:

        process = None

        try:

            process = subprocess.Popen(

                command,

                stdout=subprocess.PIPE,

                stderr=subprocess.STDOUT,

                text=True,

                bufsize=1
            )

            for line in process.stdout:

                process_line(
                    line
                )

                expire_blocks()

        except KeyboardInterrupt:

            if process:

                process.terminate()

            raise

        except Exception as e:

            log(
                f"Journal error: {e}"
            )

        finally:

            if process:

                try:

                    process.terminate()

                except Exception:

                    pass

        log(
            "SSH journal stopped. "
            "Restarting in 3 seconds..."
        )

        time.sleep(
            3
        )


# ============================================================
# MAIN
# ============================================================

def main():

    ensure_directories()

    log(
        "========================================"
    )

    log(
        "     ServerGuard Brute Force Guard"
    )

    log(
        "========================================"
    )

    config = load_protection_config()

    log(
        f"Protection: "
        f"{'ON' if config['enabled'] else 'OFF'}"
    )

    log(
        f"Block after: "
        f"{config['attempts']} failed attempts"
    )

    if config["permanent"]:

        log(
            "Block type: PERMANENT"
        )

    else:

        log(
            f"Block type: TEMPORARY "
            f"({config['duration']} seconds)"
        )

    log(
        f"Whitelist: "
        f"{len(config['whitelist'])} IP(s)"
    )

    last_cleanup = 0

    while True:

        try:

            now = time.time()

            if (
                now - last_cleanup
                >= CLEANUP_INTERVAL
            ):

                expire_blocks()

                cleanup_events()

                cleanup_attempts()

                last_cleanup = now

            run_journal()

        except KeyboardInterrupt:

            log(
                "Stopped."
            )

            break

        except Exception as e:

            log(
                f"Fatal error: {e}"
            )

            time.sleep(
                5
            )


if __name__ == "__main__":

    main()

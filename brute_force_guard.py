#!/usr/bin/env python3

import json
import re
import subprocess
import time
from pathlib import Path
from datetime import datetime, timezone


# ============================================================
# SERVERGUARD SSH PROTECTION
# ============================================================
#
# Dynamic protection settings:
#
#   /opt/serverguard/data/protection_config.json
#
# Settings can be changed from the Telegram bot without
# restarting this service.
#
# Protection works by CURRENT CONSECUTIVE FAILED SSH ATTEMPTS.
#
# Example:
#
#   attempts = 5
#   duration = 10 minutes
#
# Result:
#
#   1 failed  -> no block
#   2 failed  -> no block
#   ...
#   5 failed  -> IP blocked for 10 minutes
#
# A successful SSH login resets the current failed streak.
#
# If attempts = 1:
#
#   Every failed SSH login causes an IP block.
#
# The firewall mechanism is UFW.
#
# ============================================================


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(
    "/opt/serverguard"
)

DATA_DIR = (
    BASE_DIR / "data"
)

EVENTS_FILE = (
    DATA_DIR / "ssh_events.json"
)

BLOCKS_FILE = (
    DATA_DIR / "blocked_ips.json"
)

STATS_FILE = (
    DATA_DIR / "ip_stats.json"
)

OWNER_CONFIG_FILE = (
    DATA_DIR / "owner_keys.json"
)

PROTECTION_CONFIG_FILE = (
    DATA_DIR / "protection_config.json"
)


# ============================================================
# EVENT STORAGE LIMITS
# ============================================================

MAX_EVENTS = 2000

EVENT_RETENTION_DAYS = 7

CLEANUP_INTERVAL = 60


# ============================================================
# IP STATISTICS
# ============================================================

STATS_RETENTION_DAYS = 30


# ============================================================
# DEFAULT PROTECTION SETTINGS
# ============================================================

DEFAULT_PROTECTION_CONFIG = {

    "enabled": True,

    # Number of consecutive failed attempts before blocking.
    "attempts": 5,

    # Block duration in seconds.
    "duration": 10 * 60,

    # If True, block forever.
    "permanent": False,

    # Current protection mode.
    "mode": "ip",

    # Static emergency whitelist.
    "whitelist": []
}


# ============================================================
# DIRECTORIES
# ============================================================

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# JSON HELPERS
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

            return json.load(
                file
            )

    except Exception as e:

        print(
            f"[ERROR] Cannot load {path}: {e}",
            flush=True
        )

        return default


def save_json(
    path,
    data
):

    temp = path.with_suffix(
        ".tmp"
    )

    try:

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

        print(
            f"[ERROR] Cannot save {path}: {e}",
            flush=True
        )

        try:

            if temp.exists():

                temp.unlink()

        except Exception:

            pass

        return False


# ============================================================
# PROTECTION CONFIGURATION
# ============================================================

def normalize_protection_config(
    config
):

    if not isinstance(
        config,
        dict
    ):

        config = {}

    result = dict(
        DEFAULT_PROTECTION_CONFIG
    )

    result.update(
        config
    )

    # --------------------------------------------------------
    # enabled
    # --------------------------------------------------------

    result["enabled"] = bool(
        result.get(
            "enabled",
            True
        )
    )

    # --------------------------------------------------------
    # attempts
    # --------------------------------------------------------

    try:

        attempts = int(
            result.get(
                "attempts",
                5
            )
        )

    except Exception:

        attempts = 5

    attempts = max(
        1,
        min(
            attempts,
            100
        )
    )

    result["attempts"] = attempts

    # --------------------------------------------------------
    # duration
    # --------------------------------------------------------

    try:

        duration = int(
            result.get(
                "duration",
                600
            )
        )

    except Exception:

        duration = 600

    duration = max(
        60,
        min(
            duration,
            30 * 24 * 60 * 60
        )
    )

    result["duration"] = duration

    # --------------------------------------------------------
    # permanent
    # --------------------------------------------------------

    result["permanent"] = bool(
        result.get(
            "permanent",
            False
        )
    )

    # --------------------------------------------------------
    # mode
    # --------------------------------------------------------

    mode = str(
        result.get(
            "mode",
            "ip"
        )
    ).strip().lower()

    if mode != "ip":

        mode = "ip"

    result["mode"] = mode

    # --------------------------------------------------------
    # whitelist
    # --------------------------------------------------------

    whitelist = result.get(
        "whitelist",
        []
    )

    if not isinstance(
        whitelist,
        list
    ):

        whitelist = []

    clean_whitelist = []

    for ip in whitelist:

        if not isinstance(
            ip,
            str
        ):

            continue

        ip = ip.strip()

        if not ip:

            continue

        if ip not in clean_whitelist:

            clean_whitelist.append(
                ip
            )

    result["whitelist"] = clean_whitelist

    return result


def load_protection_config():

    config = load_json(
        PROTECTION_CONFIG_FILE,
        DEFAULT_PROTECTION_CONFIG
    )

    config = normalize_protection_config(
        config
    )

    # Create or repair configuration.
    save_json(
        PROTECTION_CONFIG_FILE,
        config
    )

    return config


def save_protection_config(
    config
):

    config = normalize_protection_config(
        config
    )

    return save_json(
        PROTECTION_CONFIG_FILE,
        config
    )


# Create configuration file immediately.
protection_config = load_protection_config()


# ============================================================
# CONFIGURATION ACCESS
# ============================================================

def get_protection_config():

    global protection_config

    # IMPORTANT:
    # Reload configuration dynamically.
    #
    # This means Telegram changes take effect without restarting
    # serverguard-security.service.

    protection_config = load_protection_config()

    return dict(
        protection_config
    )


def is_protection_enabled():

    config = get_protection_config()

    return bool(
        config.get(
            "enabled",
            True
        )
    )


def get_protection_attempts():

    config = get_protection_config()

    return int(
        config.get(
            "attempts",
            5
        )
    )


def get_protection_duration():

    config = get_protection_config()

    return int(
        config.get(
            "duration",
            600
        )
    )


def is_permanent_protection():

    config = get_protection_config()

    return bool(
        config.get(
            "permanent",
            False
        )
    )


def get_whitelist():

    config = get_protection_config()

    return set(
        config.get(
            "whitelist",
            []
        )
    )


# ============================================================
# DATA
# ============================================================

events = load_json(
    EVENTS_FILE,
    []
)

blocks = load_json(
    BLOCKS_FILE,
    {}
)

ip_stats = load_json(
    STATS_FILE,
    {}
)

owner_config = load_json(
    OWNER_CONFIG_FILE,
    {
        "usernames": [],
        "fingerprints": []
    }
)


# ============================================================
# DATA VALIDATION
# ============================================================

if not isinstance(
    events,
    list
):

    events = []


if not isinstance(
    blocks,
    dict
):

    blocks = {}


if not isinstance(
    ip_stats,
    dict
):

    ip_stats = {}


if not isinstance(
    owner_config,
    dict
):

    owner_config = {}


if not isinstance(
    owner_config.get(
        "usernames"
    ),
    list
):

    owner_config["usernames"] = []


if not isinstance(
    owner_config.get(
        "fingerprints"
    ),
    list
):

    owner_config["fingerprints"] = []


# ============================================================
# TIME
# ============================================================

def now():

    return int(
        time.time()
    )


def iso_time(
    timestamp=None
):

    if timestamp is None:

        timestamp = now()

    return datetime.fromtimestamp(
        timestamp,
        timezone.utc
    ).isoformat()


# ============================================================
# IP VALIDATION
# ============================================================

IP_REGEX = re.compile(
    r"^(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"[0-9a-fA-F:]+"
    r")$"
)


def valid_ip(
    ip
):

    if not ip:

        return False

    if len(ip) > 45:

        return False

    return bool(
        IP_REGEX.match(
            ip
        )
    )


# ============================================================
# WHITELIST
# ============================================================

def is_whitelisted(
    ip
):

    if not valid_ip(
        ip
    ):

        return False

    return ip in get_whitelist()


# ============================================================
# OWNER CONFIGURATION
# ============================================================

def get_owner_usernames():

    result = set()

    for username in owner_config.get(
        "usernames",
        []
    ):

        if isinstance(
            username,
            str
        ):

            username = username.strip()

            if username:

                result.add(
                    username
                )

    return result


def get_owner_fingerprints():

    result = set()

    for fingerprint in owner_config.get(
        "fingerprints",
        []
    ):

        if isinstance(
            fingerprint,
            str
        ):

            fingerprint = fingerprint.strip()

            if fingerprint:

                result.add(
                    fingerprint
                )

    return result


def is_owner_public_key(
    username,
    fingerprint
):

    if not username:

        return False

    if not fingerprint:

        return False

    usernames = get_owner_usernames()

    fingerprints = get_owner_fingerprints()

    return (
        username in usernames
        and
        fingerprint in fingerprints
    )


def print_owner_config():

    usernames = sorted(
        get_owner_usernames()
    )

    fingerprints = sorted(
        get_owner_fingerprints()
    )

    print(
        f"[OWNER] Config: {OWNER_CONFIG_FILE}",
        flush=True
    )

    print(
        f"[OWNER] Users: "
        f"{', '.join(usernames) if usernames else 'NONE'}",
        flush=True
    )

    print(
        f"[OWNER] SSH fingerprints: "
        f"{len(fingerprints)}",
        flush=True
    )


if not OWNER_CONFIG_FILE.exists():

    save_json(
        OWNER_CONFIG_FILE,
        {
            "usernames": [],
            "fingerprints": []
        }
    )


# ============================================================
# EVENT CLEANUP
# ============================================================

def cleanup_old_events():

    global events

    if not events:

        return False

    current_time = now()

    cutoff = (
        current_time
        -
        EVENT_RETENTION_DAYS * 24 * 60 * 60
    )

    original_count = len(
        events
    )

    cleaned_events = []

    for event in events:

        if not isinstance(
            event,
            dict
        ):

            continue

        event_time = event.get(
            "time"
        )

        if not isinstance(
            event_time,
            (int, float)
        ):

            continue

        if event_time >= cutoff:

            cleaned_events.append(
                event
            )

    events = cleaned_events

    if len(events) > MAX_EVENTS:

        events = events[
            -MAX_EVENTS:
        ]

    changed = (
        len(events)
        != original_count
    )

    if changed:

        save_json(
            EVENTS_FILE,
            events
        )

        print(
            f"[CLEANUP] SSH events: "
            f"{original_count} -> {len(events)}",
            flush=True
        )

    return changed


# ============================================================
# IP STATISTICS
# ============================================================

def create_empty_stats():

    return {

        "failed_attempts": 0,

        "successful_logins": 0,

        "current_failed_streak": 0,

        "first_seen": now(),

        "last_seen": now(),

        "last_failed": None,

        "last_success": None,

        "last_success_method": None,

        "last_success_fingerprint": None,

        "users": []
    }


def normalize_stats():

    global ip_stats

    changed = False

    for ip in list(
        ip_stats.keys()
    ):

        stats = ip_stats[ip]

        if not isinstance(
            stats,
            dict
        ):

            ip_stats[ip] = create_empty_stats()

            changed = True

            continue

        defaults = create_empty_stats()

        for key, value in defaults.items():

            if key not in stats:

                stats[key] = value

                changed = True

        if not isinstance(
            stats.get(
                "users"
            ),
            list
        ):

            stats["users"] = []

            changed = True

        if not isinstance(
            stats.get(
                "current_failed_streak"
            ),
            int
        ):

            stats[
                "current_failed_streak"
            ] = 0

            changed = True

    if changed:

        save_json(
            STATS_FILE,
            ip_stats
        )


# ============================================================
# REBUILD STATISTICS
# ============================================================

def rebuild_stats_from_events():

    global ip_stats

    if ip_stats:

        return

    if not events:

        return

    print(
        "[STATS] Building IP statistics "
        "from existing SSH events...",
        flush=True
    )

    new_stats = {}

    sorted_events = sorted(

        [
            event
            for event in events
            if isinstance(
                event,
                dict
            )
        ],

        key=lambda event: (
            event.get(
                "time",
                0
            )
            if isinstance(
                event.get(
                    "time",
                    0
                ),
                (int, float)
            )
            else 0
        )
    )

    for event in sorted_events:

        ip = event.get(
            "ip"
        )

        if not valid_ip(
            ip
        ):

            continue

        event_type = event.get(
            "type"
        )

        username = event.get(
            "username"
        )

        event_time = event.get(
            "time"
        )

        if not isinstance(
            event_time,
            (int, float)
        ):

            event_time = now()

        if ip not in new_stats:

            new_stats[ip] = {

                "failed_attempts": 0,

                "successful_logins": 0,

                "current_failed_streak": 0,

                "first_seen": event_time,

                "last_seen": event_time,

                "last_failed": None,

                "last_success": None,

                "last_success_method": None,

                "last_success_fingerprint": None,

                "users": []
            }

        stats = new_stats[
            ip
        ]

        if event_time < stats[
            "first_seen"
        ]:

            stats[
                "first_seen"
            ] = event_time

        if event_time > stats[
            "last_seen"
        ]:

            stats[
                "last_seen"
            ] = event_time

        if (
            username
            and
            isinstance(
                username,
                str
            )
            and
            username not in stats[
                "users"
            ]
        ):

            stats[
                "users"
            ].append(
                username
            )

            if len(
                stats["users"]
            ) > 20:

                stats[
                    "users"
                ] = stats[
                    "users"
                ][-20:]

        if event_type == "failed":

            stats[
                "failed_attempts"
            ] += 1

            stats[
                "current_failed_streak"
            ] += 1

            if (
                stats[
                    "last_failed"
                ] is None
                or
                event_time > stats[
                    "last_failed"
                ]
            ):

                stats[
                    "last_failed"
                ] = event_time

        elif event_type == "success":

            stats[
                "successful_logins"
            ] += 1

            stats[
                "current_failed_streak"
            ] = 0

            if (
                stats[
                    "last_success"
                ] is None
                or
                event_time > stats[
                    "last_success"
                ]
            ):

                stats[
                    "last_success"
                ] = event_time

                stats[
                    "last_success_method"
                ] = event.get(
                    "auth_method"
                )

                stats[
                    "last_success_fingerprint"
                ] = event.get(
                    "fingerprint"
                )

    ip_stats = new_stats

    save_json(
        STATS_FILE,
        ip_stats
    )

    print(
        f"[STATS] Created statistics "
        f"for {len(ip_stats)} IPs",
        flush=True
    )


# ============================================================
# OLD IP STATISTICS CLEANUP
# ============================================================

def cleanup_old_stats():

    global ip_stats

    if not ip_stats:

        return False

    current_time = now()

    cutoff = (
        current_time
        -
        STATS_RETENTION_DAYS * 24 * 60 * 60
    )

    changed = False

    removed = 0

    for ip in list(
        ip_stats.keys()
    ):

        stats = ip_stats.get(
            ip
        )

        if not isinstance(
            stats,
            dict
        ):

            del ip_stats[
                ip
            ]

            changed = True

            removed += 1

            continue

        last_seen = stats.get(
            "last_seen"
        )

        if not isinstance(
            last_seen,
            (int, float)
        ):

            last_seen = current_time

        if ip in blocks:

            continue

        if is_whitelisted(
            ip
        ):

            continue

        if last_seen < cutoff:

            del ip_stats[
                ip
            ]

            changed = True

            removed += 1

    if changed:

        save_json(
            STATS_FILE,
            ip_stats
        )

        print(
            f"[CLEANUP] IP statistics removed: "
            f"{removed}",
            flush=True
        )

    return changed


# ============================================================
# CURRENT FAILED STREAK
# ============================================================

def get_failed_count(
    ip
):

    stats = ip_stats.get(
        ip
    )

    if not isinstance(
        stats,
        dict
    ):

        return 0

    streak = stats.get(
        "current_failed_streak",
        0
    )

    if not isinstance(
        streak,
        int
    ):

        return 0

    return max(
        streak,
        0
    )


# ============================================================
# UPDATE IP STATISTICS
# ============================================================

def update_ip_stats(
    username,
    ip,
    event_type,
    auth_method=None,
    fingerprint=None
):

    global ip_stats

    if ip not in ip_stats:

        ip_stats[
            ip
        ] = create_empty_stats()

    stats = ip_stats[
        ip
    ]

    current_time = now()

    stats[
        "last_seen"
    ] = current_time

    if (
        username
        and
        isinstance(
            username,
            str
        )
        and
        username not in stats[
            "users"
        ]
    ):

        stats[
            "users"
        ].append(
            username
        )

        if len(
            stats[
                "users"
            ]
        ) > 20:

            stats[
                "users"
            ] = stats[
                "users"
            ][-20:]

    if event_type == "failed":

        stats[
            "failed_attempts"
        ] = (
            stats.get(
                "failed_attempts",
                0
            )
            + 1
        )

        stats[
            "current_failed_streak"
        ] = (
            stats.get(
                "current_failed_streak",
                0
            )
            + 1
        )

        stats[
            "last_failed"
        ] = current_time

    elif event_type == "success":

        stats[
            "successful_logins"
        ] = (
            stats.get(
                "successful_logins",
                0
            )
            + 1
        )

        stats[
            "current_failed_streak"
        ] = 0

        stats[
            "last_success"
        ] = current_time

        stats[
            "last_success_method"
        ] = auth_method

        stats[
            "last_success_fingerprint"
        ] = fingerprint

    save_json(
        STATS_FILE,
        ip_stats
    )


# ============================================================
# FIREWALL
# ============================================================

def ufw_block(
    ip
):

    if is_whitelisted(
        ip
    ):

        print(
            f"[WHITELIST] Refusing to block {ip}",
            flush=True
        )

        return False

    try:

        result = subprocess.run(

            [
                "ufw",
                "insert",
                "1",
                "deny",
                "from",
                ip
            ],

            stdout=subprocess.DEVNULL,

            stderr=subprocess.DEVNULL,

            timeout=15
        )

        if result.returncode == 0:

            return True

        return False

    except Exception as e:

        print(
            f"[ERROR] UFW block failed "
            f"for {ip}: {e}",
            flush=True
        )

        return False


def ufw_unblock(
    ip
):

    if is_whitelisted(
        ip
    ):

        return

    try:

        subprocess.run(

            [
                "ufw",
                "delete",
                "deny",
                "from",
                ip
            ],

            stdout=subprocess.DEVNULL,

            stderr=subprocess.DEVNULL,

            timeout=15
        )

    except Exception:

        pass


# ============================================================
# REMOVE STORED BLOCK
# ============================================================

def remove_block(
    ip
):

    changed = False

    if ip in blocks:

        del blocks[
            ip
        ]

        changed = True

    ufw_unblock(
        ip
    )

    if changed:

        save_json(
            BLOCKS_FILE,
            blocks
        )


# ============================================================
# BLOCK IP
# ============================================================

def block_ip(
    ip,
    failed_count
):

    if is_whitelisted(
        ip
    ):

        print(
            f"[WHITELIST] {ip} "
            f"will never be blocked",
            flush=True
        )

        return

    config = get_protection_config()

    if not config.get(
        "enabled",
        True
    ):

        return

    # --------------------------------------------------------
    # If IP already has a permanent block.
    # --------------------------------------------------------

    current = blocks.get(
        ip
    )

    if (
        current
        and
        current.get(
            "permanent",
            False
        )
    ):

        return

    # --------------------------------------------------------
    # If temporary block is still active.
    # --------------------------------------------------------

    if current:

        expires = current.get(
            "expires_at"
        )

        if (
            not current.get(
                "permanent",
                False
            )
            and
            expires is not None
            and
            now() < expires
        ):

            return

        ufw_unblock(
            ip
        )

    # --------------------------------------------------------
    # PERMANENT BLOCK
    # --------------------------------------------------------

    if config.get(
        "permanent",
        False
    ):

        if ufw_block(
            ip
        ):

            blocks[
                ip
            ] = {

                "ip": ip,

                "level": "custom",

                "failed_attempts": failed_count,

                "blocked_at": now(),

                "blocked_at_iso": iso_time(),

                "expires_at": None,

                "expires_at_iso": None,

                "permanent": True
            }

            save_json(
                BLOCKS_FILE,
                blocks
            )

            print(
                f"[BLOCK] {ip} permanently blocked "
                f"after {failed_count} consecutive "
                f"failed attempts",
                flush=True
            )

        return

    # --------------------------------------------------------
    # TEMPORARY BLOCK
    # --------------------------------------------------------

    duration = int(
        config.get(
            "duration",
            600
        )
    )

    blocked_at = now()

    expires = (
        blocked_at
        + duration
    )

    if ufw_block(
        ip
    ):

        blocks[
            ip
        ] = {

            "ip": ip,

            "level": "custom",

            "failed_attempts": failed_count,

            "blocked_at": blocked_at,

            "blocked_at_iso": iso_time(
                blocked_at
            ),

            "expires_at": expires,

            "expires_at_iso": iso_time(
                expires
            ),

            "permanent": False
        }

        save_json(
            BLOCKS_FILE,
            blocks
        )

        if duration >= 86400:

            days = duration // 86400

            duration_text = (
                f"{days} days"
            )

        elif duration >= 3600:

            hours = duration // 3600

            duration_text = (
                f"{hours} hours"
            )

        else:

            minutes = max(
                1,
                duration // 60
            )

            duration_text = (
                f"{minutes} minutes"
            )

        print(
            f"[BLOCK] {ip} blocked for "
            f"{duration_text} "
            f"(consecutive failures: "
            f"{failed_count})",
            flush=True
        )


# ============================================================
# EXPIRE BLOCKS
# ============================================================

def cleanup_expired_blocks():

    changed = False

    for ip in list(
        blocks.keys()
    ):

        if is_whitelisted(
            ip
        ):

            ufw_unblock(
                ip
            )

            del blocks[
                ip
            ]

            changed = True

            print(
                f"[WHITELIST] Removed block "
                f"for {ip}",
                flush=True
            )

            continue

        block = blocks[
            ip
        ]

        if not isinstance(
            block,
            dict
        ):

            del blocks[
                ip
            ]

            changed = True

            continue

        if block.get(
            "permanent"
        ):

            continue

        expires = block.get(
            "expires_at"
        )

        if expires is None:

            continue

        if now() >= expires:

            print(
                f"[UNBLOCK] Temporary block expired: "
                f"{ip}",
                flush=True
            )

            ufw_unblock(
                ip
            )

            del blocks[
                ip
            ]

            changed = True

    if changed:

        save_json(
            BLOCKS_FILE,
            blocks
        )


# ============================================================
# GENERAL CLEANUP
# ============================================================

def cleanup():

    cleanup_old_events()

    cleanup_expired_blocks()

    cleanup_old_stats()


# ============================================================
# EVENT STORAGE
# ============================================================

def save_event(
    event_type,
    username,
    ip,
    message,
    auth_method=None,
    fingerprint=None,
    owner_login=False
):

    event = {

        "time": now(),

        "time_iso": iso_time(),

        "type": event_type,

        "username": username,

        "ip": ip,

        "auth_method": auth_method,

        "fingerprint": fingerprint,

        "owner_login": owner_login,

        "message": message
    }

    events.append(
        event
    )

    if len(
        events
    ) > MAX_EVENTS:

        del events[
            :-MAX_EVENTS
        ]

    save_json(
        EVENTS_FILE,
        events
    )


# ============================================================
# SUCCESS
# ============================================================

def handle_success(
    username,
    ip,
    message,
    auth_method,
    fingerprint
):

    owner_login = is_owner_public_key(
        username,
        fingerprint
    )

    update_ip_stats(
        username,
        ip,
        "success",
        auth_method,
        fingerprint
    )

    save_event(
        "success",
        username,
        ip,
        message,
        auth_method,
        fingerprint,
        owner_login
    )

    if owner_login:

        print(
            f"[OWNER LOGIN] "
            f"user={username} "
            f"ip={ip} "
            f"fingerprint={fingerprint}",
            flush=True
        )

        remove_block(
            ip
        )

        return

    print(
        f"[SSH SUCCESS] "
        f"user={username} "
        f"ip={ip} "
        f"method={auth_method or 'unknown'}",
        flush=True
    )


# ============================================================
# FAILED
# ============================================================

def handle_failed(
    username,
    ip,
    message
):

    update_ip_stats(
        username,
        ip,
        "failed"
    )

    save_event(
        "failed",
        username,
        ip,
        message,
        None,
        None,
        False
    )

    failed_streak = get_failed_count(
        ip
    )

    stats = ip_stats.get(
        ip,
        {}
    )

    total_failed = stats.get(
        "failed_attempts",
        0
    )

    print(
        f"[SSH FAILED] "
        f"user={username} "
        f"ip={ip} "
        f"streak={failed_streak} "
        f"total={total_failed}",
        flush=True
    )

    # --------------------------------------------------------
    # WHITELIST
    # --------------------------------------------------------

    if is_whitelisted(
        ip
    ):

        print(
            f"[WHITELIST] {ip} "
            f"will never be blocked",
            flush=True
        )

        return

    # --------------------------------------------------------
    # PROTECTION DISABLED
    # --------------------------------------------------------

    config = get_protection_config()

    if not config.get(
        "enabled",
        True
    ):

        print(
            "[PROTECTION] Automatic blocking "
            "is disabled.",
            flush=True
        )

        return

    # --------------------------------------------------------
    # BLOCKING THRESHOLD
    # --------------------------------------------------------

    threshold = int(
        config.get(
            "attempts",
            5
        )
    )

    if failed_streak >= threshold:

        block_ip(
            ip,
            failed_streak
        )


# ============================================================
# SSH LOG PARSER
# ============================================================

FAILED_REGEX = re.compile(
    r"Failed \S+ for "
    r"(?:invalid user )?"
    r"(\S+) "
    r"from "
    r"([0-9a-fA-F:.]+)"
)


ACCEPTED_PASSWORD_REGEX = re.compile(
    r"Accepted password for "
    r"(\S+) "
    r"from "
    r"([0-9a-fA-F:.]+)"
)


ACCEPTED_PUBLICKEY_REGEX = re.compile(
    r"Accepted publickey for "
    r"(\S+) "
    r"from "
    r"([0-9a-fA-F:.]+)"
    r".*?"
    r"ssh2(?::\s+\S+\s+)?"
    r"(SHA256:[A-Za-z0-9+/=]+)"
)


def process_log_line(
    line
):

    # --------------------------------------------------------
    # SUCCESSFUL PUBLIC KEY LOGIN
    # --------------------------------------------------------

    match = ACCEPTED_PUBLICKEY_REGEX.search(
        line
    )

    if match:

        username = match.group(
            1
        )

        ip = match.group(
            2
        )

        fingerprint = match.group(
            3
        )

        if valid_ip(
            ip
        ):

            handle_success(
                username,
                ip,
                line.strip(),
                "publickey",
                fingerprint
            )

        return

    # --------------------------------------------------------
    # SUCCESSFUL PASSWORD LOGIN
    # --------------------------------------------------------

    match = ACCEPTED_PASSWORD_REGEX.search(
        line
    )

    if match:

        username = match.group(
            1
        )

        ip = match.group(
            2
        )

        if valid_ip(
            ip
        ):

            handle_success(
                username,
                ip,
                line.strip(),
                "password",
                None
            )

        return

    # --------------------------------------------------------
    # FAILED LOGIN
    # --------------------------------------------------------

    match = FAILED_REGEX.search(
        line
    )

    if match:

        username = match.group(
            1
        )

        ip = match.group(
            2
        )

        if valid_ip(
            ip
        ):

            handle_failed(
                username,
                ip,
                line.strip()
            )


# ============================================================
# JOURNALCTL
# ============================================================

def start_journal():

    command = [

        "journalctl",

        "-f",

        "-n",

        "0",

        "-u",

        "ssh"
    ]

    return subprocess.Popen(

        command,

        stdout=subprocess.PIPE,

        stderr=subprocess.STDOUT,

        text=True,

        bufsize=1
    )


# ============================================================
# STORAGE INFORMATION
# ============================================================

def print_storage_info():

    print(
        f"[DATA] Events: {EVENTS_FILE}",
        flush=True
    )

    print(
        f"[DATA] Blocks: {BLOCKS_FILE}",
        flush=True
    )

    print(
        f"[DATA] IP statistics: {STATS_FILE}",
        flush=True
    )

    print(
        f"[DATA] Owner configuration: "
        f"{OWNER_CONFIG_FILE}",
        flush=True
    )

    print(
        f"[DATA] Protection configuration: "
        f"{PROTECTION_CONFIG_FILE}",
        flush=True
    )

    print(
        f"[DATA] Event retention: "
        f"{EVENT_RETENTION_DAYS} days",
        flush=True
    )

    print(
        f"[DATA] Maximum events: "
        f"{MAX_EVENTS}",
        flush=True
    )

    print(
        f"[DATA] IP statistics retention: "
        f"{STATS_RETENTION_DAYS} days",
        flush=True
    )


# ============================================================
# PROTECTION INFORMATION
# ============================================================

def print_protection_config():

    config = get_protection_config()

    print(
        "[PROTECTION] Configuration:",
        flush=True
    )

    print(
        f"[PROTECTION] Enabled: "
        f"{config['enabled']}",
        flush=True
    )

    print(
        f"[PROTECTION] Attempts: "
        f"{config['attempts']}",
        flush=True
    )

    print(
        f"[PROTECTION] Duration: "
        f"{config['duration']} seconds",
        flush=True
    )

    print(
        f"[PROTECTION] Permanent: "
        f"{config['permanent']}",
        flush=True
    )

    print(
        f"[PROTECTION] Mode: "
        f"{config['mode']}",
        flush=True
    )

    print(
        f"[PROTECTION] Whitelist: "
        f"{len(config['whitelist'])} IPs",
        flush=True
    )


# ============================================================
# MAIN LOOP
# ============================================================

def main():

    print(
        "==================================================",
        flush=True
    )

    print(
        "ServerGuard SSH Protection",
        flush=True
    )

    print(
        "Protection mode: ACTIVE",
        flush=True
    )

    print(
        "Login tracking: SUCCESS + FAILED",
        flush=True
    )

    print(
        "Blocking mode: DYNAMIC TELEGRAM CONFIGURATION",
        flush=True
    )

    print(
        "Owner protection: SSH KEY FINGERPRINT",
        flush=True
    )

    print(
        "Password logging: DISABLED",
        flush=True
    )

    print(
        "==================================================",
        flush=True
    )

    print_storage_info()

    print_protection_config()

    print(
        f"[DATA] Loaded events: "
        f"{len(events)}",
        flush=True
    )

    print(
        f"[DATA] Loaded blocks: "
        f"{len(blocks)}",
        flush=True
    )

    print(
        f"[DATA] Loaded IP statistics: "
        f"{len(ip_stats)}",
        flush=True
    )

    print_owner_config()

    rebuild_stats_from_events()

    normalize_stats()

    cleanup()

    journal = start_journal()

    last_cleanup = now()

    try:

        while True:

            current_time = now()

            if (
                current_time
                -
                last_cleanup
                >= CLEANUP_INTERVAL
            ):

                cleanup()

                last_cleanup = current_time

            line = journal.stdout.readline()

            if line:

                process_log_line(
                    line
                )

            else:

                time.sleep(
                    0.2
                )

    except KeyboardInterrupt:

        print(
            "\n[STOP] ServerGuard protection stopped.",
            flush=True
        )

    except Exception as e:

        print(
            f"[ERROR] Main loop: {e}",
            flush=True
        )

    finally:

        try:

            journal.terminate()

        except Exception:

            pass


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()

#!/usr/bin/env python3

import asyncio
import html
import json
import os
import time

from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.types import Message


# ============================================================
# VERSION
# ============================================================

VERSION = "1.7.1"


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path("/opt/serverguard")

DATA_DIR = BASE_DIR / "data"
TELEGRAM_DIR = BASE_DIR / "telegram"

CONFIG_FILE = TELEGRAM_DIR / "telegram.conf"
VERIFICATION_FILE = TELEGRAM_DIR / "verification.json"
OWNER_FILE = TELEGRAM_DIR / "owner.json"

# ------------------------------------------------------------
# SSH SECURITY
# ------------------------------------------------------------

EVENTS_FILE = DATA_DIR / "ssh_events.json"
BLOCKS_FILE = DATA_DIR / "blocked_ips.json"
STATS_FILE = DATA_DIR / "ip_stats.json"

SEEN_BLOCKS_FILE = TELEGRAM_DIR / "seen_blocks.json"
SEEN_EVENTS_FILE = TELEGRAM_DIR / "seen_events.json"

# ------------------------------------------------------------
# FILEGUARD
# ------------------------------------------------------------

FILEGUARD_EVENTS_FILE = DATA_DIR / "file_events.json"

SEEN_FILEGUARD_EVENTS_FILE = (
    TELEGRAM_DIR / "seen_file_events.json"
)


# ============================================================
# SETTINGS
# ============================================================

CHECK_INTERVAL = 3

MAX_EVENTS_TO_SHOW = 10

MAX_BLOCKS_TO_SHOW = 30

MAX_FILE_EVENTS_TO_SHOW = 20

VERIFICATION_TIMEOUT = 10 * 60

DEFAULT_TIMEZONE = "Europe/Kyiv"


# ============================================================
# DIRECTORIES
# ============================================================

TELEGRAM_DIR.mkdir(
    parents=True,
    exist_ok=True
)

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# JSON HELPERS
# ============================================================

def load_json(
    path: Path,
    default
):

    try:

        if not path.exists():
            return default

        with path.open(
            "r",
            encoding="utf-8"
        ) as f:

            return json.load(f)

    except Exception as e:

        print(
            f"[JSON] Cannot read {path}: {e}",
            flush=True
        )

        return default


def save_json(
    path: Path,
    data
):

    try:

        path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        temp_path = path.with_suffix(
            path.suffix + ".tmp"
        )

        with temp_path.open(
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                data,
                f,
                ensure_ascii=False,
                indent=2
            )

            f.write("\n")

        os.replace(
            temp_path,
            path
        )

        return True

    except Exception as e:

        print(
            f"[JSON] Cannot write {path}: {e}",
            flush=True
        )

        return False


# ============================================================
# CONFIG
# ============================================================

def load_config():

    token = ""

    try:

        if not CONFIG_FILE.exists():
            return ""

        with CONFIG_FILE.open(
            "r",
            encoding="utf-8"
        ) as f:

            for raw_line in f:

                line = raw_line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                if line.startswith("BOT_TOKEN="):

                    token = line.split(
                        "=",
                        1
                    )[1].strip()

        return token

    except Exception as e:

        print(
            f"[CONFIG] Cannot read config: {e}",
            flush=True
        )

        return ""


# ============================================================
# OWNER
# ============================================================

def get_owner():

    data = load_json(
        OWNER_FILE,
        {}
    )

    if not isinstance(
        data,
        dict
    ):
        return None

    if not data.get("verified"):
        return None

    if not data.get("chat_id"):
        return None

    # --------------------------------------------------------
    # Add timezone to old owner.json
    # --------------------------------------------------------

    if not data.get("timezone"):

        data["timezone"] = DEFAULT_TIMEZONE

        save_json(
            OWNER_FILE,
            data
        )

    return data


def is_owner(
    chat_id: int
):

    owner = get_owner()

    if not owner:
        return False

    try:

        return int(
            owner["chat_id"]
        ) == int(chat_id)

    except Exception:

        return False


# ============================================================
# TIMEZONE
# ============================================================

def get_owner_timezone():

    owner = get_owner()

    if not owner:
        return DEFAULT_TIMEZONE

    timezone_name = owner.get(
        "timezone",
        DEFAULT_TIMEZONE
    )

    if not isinstance(
        timezone_name,
        str
    ):
        return DEFAULT_TIMEZONE

    timezone_name = timezone_name.strip()

    if not timezone_name:
        return DEFAULT_TIMEZONE

    try:

        ZoneInfo(
            timezone_name
        )

        return timezone_name

    except ZoneInfoNotFoundError:

        print(
            f"[TIMEZONE] Invalid owner timezone: "
            f"{timezone_name}",
            flush=True
        )

        return DEFAULT_TIMEZONE


def set_owner_timezone(
    chat_id: int,
    timezone_name: str
):

    owner = get_owner()

    if not owner:
        return False

    if int(owner["chat_id"]) != int(chat_id):
        return False

    timezone_name = timezone_name.strip()

    try:

        ZoneInfo(
            timezone_name
        )

    except ZoneInfoNotFoundError:

        return False

    owner["timezone"] = timezone_name

    return save_json(
        OWNER_FILE,
        owner
    )


def format_timestamp(
    timestamp,
    include_timezone=True
):

    try:

        timestamp = int(timestamp)

        tz_name = get_owner_timezone()

        tz = ZoneInfo(
            tz_name
        )

        dt = datetime.fromtimestamp(
            timestamp,
            tz
        )

        if include_timezone:

            return (
                dt.strftime(
                    "%d.%m.%Y %H:%M:%S"
                )
                + f" {tz_name}"
            )

        return dt.strftime(
            "%d.%m.%Y %H:%M:%S"
        )

    except Exception:

        return "unknown"


def format_iso(
    value,
    include_timezone=True
):

    if not value:
        return "unknown"

    try:

        timestamp = int(value)

        return format_timestamp(
            timestamp,
            include_timezone
        )

    except Exception:
        pass

    try:

        text = str(value).strip()

        dt = datetime.fromisoformat(
            text.replace(
                "Z",
                "+00:00"
            )
        )

        if dt.tzinfo is None:

            dt = dt.replace(
                tzinfo=timezone.utc
            )

        tz_name = get_owner_timezone()

        dt = dt.astimezone(
            ZoneInfo(tz_name)
        )

        if include_timezone:

            return (
                dt.strftime(
                    "%d.%m.%Y %H:%M:%S"
                )
                + f" {tz_name}"
            )

        return dt.strftime(
            "%d.%m.%Y %H:%M:%S"
        )

    except Exception:

        return str(value)


# ============================================================
# VERIFICATION
# ============================================================

def get_verification():

    data = load_json(
        VERIFICATION_FILE,
        {}
    )

    if not isinstance(
        data,
        dict
    ):
        return None

    code = str(
        data.get(
            "code",
            ""
        )
    ).strip()

    if not code:
        return None

    expires_at = int(
        data.get(
            "expires_at",
            0
        )
    )

    if expires_at <= int(
        time.time()
    ):

        try:

            VERIFICATION_FILE.unlink(
                missing_ok=True
            )

        except Exception:
            pass

        return None

    return data


def consume_verification(
    message: Message,
    verification: dict
):

    user = message.from_user

    owner_data = {

        "chat_id":
            message.chat.id,

        "user_id":
            user.id
            if user
            else None,

        "username":
            user.username
            if user
            else None,

        "first_name":
            user.first_name
            if user
            else None,

        "registered_at":
            int(time.time()),

        "registered_at_iso":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "timezone":
            DEFAULT_TIMEZONE,

        "verified":
            True
    }

    if not save_json(
        OWNER_FILE,
        owner_data
    ):

        return False

    try:

        VERIFICATION_FILE.unlink(
            missing_ok=True
        )

    except Exception:
        pass

    return True


# ============================================================
# SSH DATA
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


def load_stats():

    data = load_json(
        STATS_FILE,
        {}
    )

    if not isinstance(
        data,
        dict
    ):
        return {}

    return data


# ============================================================
# FILEGUARD DATA
# ============================================================

def load_file_events():

    data = load_json(
        FILEGUARD_EVENTS_FILE,
        []
    )

    if not isinstance(
        data,
        list
    ):
        return []

    return data


def fileguard_installed():

    return (
        (BASE_DIR / "file_guard.py").exists()
        and
        (
            Path(
                "/etc/systemd/system/"
                "serverguard-fileguard.service"
            ).exists()
        )
    )


def fileguard_service_active():

    service_path = Path(
        "/etc/systemd/system/"
        "serverguard-fileguard.service"
    )

    if not service_path.exists():
        return False

    result = os.system(
        "systemctl is-active "
        "--quiet serverguard-fileguard.service "
        "> /dev/null 2>&1"
    )

    return result == 0


def fileguard_status():

    events = load_file_events()

    critical = 0
    high = 0
    medium = 0

    for event in events:

        if not isinstance(
            event,
            dict
        ):
            continue

        severity = str(
            event.get(
                "severity",
                ""
            )
        ).upper()

        if severity == "CRITICAL":

            critical += 1

        elif severity == "HIGH":

            high += 1

        elif severity == "MEDIUM":

            medium += 1

    return {

        "installed":
            fileguard_installed(),

        "active":
            fileguard_service_active(),

        "events":
            len(events),

        "critical":
            critical,

        "high":
            high,

        "medium":
            medium
    }


# ============================================================
# BLOCK STATUS
# ============================================================

def block_is_active(
    block
):

    if not isinstance(
        block,
        dict
    ):
        return False

    if block.get("permanent"):
        return True

    expires_at = block.get(
        "expires_at"
    )

    if expires_at is None:
        return False

    try:

        return int(
            expires_at
        ) > int(
            time.time()
        )

    except Exception:

        return False


def active_blocks():

    blocks = load_blocks()

    result = {}

    for ip, block in blocks.items():

        if block_is_active(
            block
        ):

            result[ip] = block

    return result


# ============================================================
# SSH SECURITY STATUS
# ============================================================

def security_status():

    events = load_events()

    blocks = active_blocks()

    stats = load_stats()

    failed_events = 0

    successful_events = 0

    for event in events:

        if not isinstance(
            event,
            dict
        ):
            continue

        event_type = event.get(
            "type"
        )

        if event_type == "failed":

            failed_events += 1

        elif event_type == "success":

            successful_events += 1

    return {

        "events":
            len(events),

        "failed":
            failed_events,

        "success":
            successful_events,

        "blocked":
            len(blocks),

        "stats":
            len(stats)
    }


# ============================================================
# SEEN BLOCKS
# ============================================================

def block_signature(
    ip,
    block
):

    return (

        str(ip),

        str(
            block.get(
                "level"
            )
        ),

        str(
            block.get(
                "failed_attempts"
            )
        ),

        str(
            block.get(
                "blocked_at"
            )
        ),

        str(
            block.get(
                "expires_at"
            )
        ),

        str(
            block.get(
                "permanent"
            )
        )
    )


def load_seen_blocks():

    data = load_json(
        SEEN_BLOCKS_FILE,
        []
    )

    if not isinstance(
        data,
        list
    ):

        return set()

    return set(
        str(x)
        for x in data
    )


def save_seen_blocks(
    seen
):

    return save_json(
        SEEN_BLOCKS_FILE,
        list(seen)
    )


# ============================================================
# SEEN SSH EVENTS
# ============================================================

def event_signature(
    event
):

    return "|".join(
        [
            str(
                event.get(
                    "time",
                    ""
                )
            ),

            str(
                event.get(
                    "type",
                    ""
                )
            ),

            str(
                event.get(
                    "username",
                    ""
                )
            ),

            str(
                event.get(
                    "ip",
                    ""
                )
            ),

            str(
                event.get(
                    "auth_method",
                    ""
                )
            ),

            str(
                event.get(
                    "fingerprint",
                    ""
                )
            ),

            str(
                event.get(
                    "owner_login",
                    ""
                )
            )
        ]
    )


def load_seen_events():

    data = load_json(
        SEEN_EVENTS_FILE,
        []
    )

    if not isinstance(
        data,
        list
    ):

        return set()

    return set(
        str(x)
        for x in data
    )


def save_seen_events(
    seen
):

    return save_json(
        SEEN_EVENTS_FILE,
        list(seen)
    )


# ============================================================
# SEEN FILEGUARD EVENTS
# ============================================================

def fileguard_event_signature(
    event
):

    """
    Creates a stable identifier for a FileGuard event.

    The event can safely be processed again after bot restart
    without creating duplicate Telegram notifications.
    """

    return "|".join(
        [
            str(
                event.get(
                    "timestamp",
                    ""
                )
            ),

            str(
                event.get(
                    "time",
                    ""
                )
            ),

            str(
                event.get(
                    "path",
                    ""
                )
            ),

            str(
                event.get(
                    "event",
                    ""
                )
            ),

            str(
                event.get(
                    "severity",
                    ""
                )
            )
        ]
    )


def load_seen_fileguard_events():

    data = load_json(
        SEEN_FILEGUARD_EVENTS_FILE,
        []
    )

    if not isinstance(
        data,
        list
    ):
        return set()

    return set(
        str(x)
        for x in data
    )


def save_seen_fileguard_events(
    seen
):

    return save_json(
        SEEN_FILEGUARD_EVENTS_FILE,
        list(seen)
    )


# ============================================================
# TELEGRAM: BLOCK NOTIFICATION
# ============================================================

async def send_block_notification(
    bot: Bot,
    ip: str,
    block: dict
):

    try:

        owner = get_owner()

        if not owner:
            return False

        ip_safe = html.escape(
            str(ip)
        )

        level = html.escape(
            str(
                block.get(
                    "level",
                    "unknown"
                )
            )
        )

        attempts = html.escape(
            str(
                block.get(
                    "failed_attempts",
                    "unknown"
                )
            )
        )

        blocked_at = html.escape(
            format_iso(
                block.get(
                    "blocked_at_iso"
                )
            )
        )

        permanent = bool(
            block.get(
                "permanent",
                False
            )
        )

        if permanent:

            text = (

                "🚨 <b>ServerGuard</b>\n\n"

                "🔴 "
                "<b>IP ЗАБЛОКИРОВАН НАВСЕГДА</b>\n\n"

                f"🌐 IP: "
                f"<code>{ip_safe}</code>\n"

                f"❌ Попыток: "
                f"<b>{attempts}</b>\n"

                f"⚠️ Уровень: "
                f"<b>{level}</b>\n"

                f"🕒 Время: "
                f"<code>{blocked_at}</code>"
            )

        else:

            expires_at = html.escape(
                format_iso(
                    block.get(
                        "expires_at_iso"
                    )
                )
            )

            text = (

                "🚨 <b>ServerGuard</b>\n\n"

                "🔒 <b>IP ЗАБЛОКИРОВАН</b>\n\n"

                f"🌐 IP: "
                f"<code>{ip_safe}</code>\n"

                f"❌ Попыток: "
                f"<b>{attempts}</b>\n"

                f"⚠️ Уровень: "
                f"<b>{level}</b>\n"

                f"🕒 Заблокирован: "
                f"<code>{blocked_at}</code>\n"

                f"🔓 До: "
                f"<code>{expires_at}</code>"
            )

        await bot.send_message(

            chat_id=int(
                owner["chat_id"]
            ),

            text=text
        )

        print(
            f"[TELEGRAM] Block notification sent: {ip}",
            flush=True
        )

        return True

    except Exception as e:

        print(
            "[TELEGRAM] Cannot send block "
            f"notification: {e}",
            flush=True
        )

        return False


# ============================================================
# TELEGRAM: SUCCESSFUL SSH LOGIN
# ============================================================

async def send_success_notification(
    bot: Bot,
    event: dict
):

    try:

        owner = get_owner()

        if not owner:
            return False

        username = html.escape(
            str(
                event.get(
                    "username",
                    "unknown"
                )
            )
        )

        ip = html.escape(
            str(
                event.get(
                    "ip",
                    "unknown"
                )
            )
        )

        auth_method = str(
            event.get(
                "auth_method",
                "unknown"
            )
        )

        fingerprint = event.get(
            "fingerprint"
        )

        owner_login = bool(
            event.get(
                "owner_login",
                False
            )
        )

        timestamp = event.get(
            "time"
        )

        if timestamp is not None:

            event_time = format_timestamp(
                timestamp
            )

        else:

            event_time = format_iso(
                event.get(
                    "time_iso"
                )
            )

        event_time = html.escape(
            event_time
        )

        if auth_method == "publickey":

            method_text = (
                "🔑 <b>SSH public key</b>"
            )

        elif auth_method == "password":

            method_text = (
                "🔐 <b>SSH password</b>"
            )

        else:

            method_text = (
                f"🔐 <b>"
                f"{html.escape(auth_method)}"
                f"</b>"
            )

        if owner_login:

            title = (
                "🟢 <b>ДОВЕРЕННЫЙ SSH ВХОД</b>"
            )

            owner_text = (
                "\n🛡 "
                "<b>Владелец: "
                "подтверждённый SSH-ключ</b>"
            )

        else:

            title = (
                "✅ <b>УСПЕШНЫЙ SSH ВХОД</b>"
            )

            owner_text = ""

        text = (

            "🛡 <b>ServerGuard</b>\n\n"

            f"{title}\n\n"

            f"👤 Пользователь: "
            f"<b>{username}</b>\n"

            f"🌐 IP: "
            f"<code>{ip}</code>\n"

            f"{method_text}\n"

            f"🕒 Время: "
            f"<code>{event_time}</code>"

            f"{owner_text}"
        )

        if (
            auth_method == "publickey"
            and fingerprint
        ):

            fingerprint_safe = html.escape(
                str(fingerprint)
            )

            text += (
                "\n🔑 Fingerprint:\n"
                f"<code>{fingerprint_safe}</code>"
            )

        await bot.send_message(

            chat_id=int(
                owner["chat_id"]
            ),

            text=text
        )

        print(
            "[TELEGRAM] Successful SSH login "
            f"notification sent: {ip}",
            flush=True
        )

        return True

    except Exception as e:

        print(
            "[TELEGRAM] Cannot send successful "
            f"login notification: {e}",
            flush=True
        )

        return False


# ============================================================
# FILEGUARD NOTIFICATION
# ============================================================

async def send_fileguard_notification(
    bot: Bot,
    event: dict
):

    try:

        owner = get_owner()

        if not owner:
            return False

        path = html.escape(
            str(
                event.get(
                    "path",
                    "unknown"
                )
            )
        )

        event_type = html.escape(
            str(
                event.get(
                    "event",
                    "unknown"
                )
            )
        )

        severity = str(
            event.get(
                "severity",
                "MEDIUM"
            )
        ).upper()

        event_time = html.escape(
            format_iso(
                event.get(
                    "timestamp"
                )
            )
        )

        # ----------------------------------------------------
        # Severity
        # ----------------------------------------------------

        if severity == "CRITICAL":

            severity_icon = "🔴"

            title = (
                "🚨 "
                "<b>КРИТИЧЕСКОЕ ИЗМЕНЕНИЕ ФАЙЛА</b>"
            )

        elif severity == "HIGH":

            severity_icon = "🟠"

            title = (
                "⚠️ "
                "<b>ОПАСНОЕ ИЗМЕНЕНИЕ ФАЙЛА</b>"
            )

        else:

            severity_icon = "🟡"

            title = (
                "ℹ️ "
                "<b>ИЗМЕНЕНИЕ ФАЙЛА</b>"
            )


        text = (

            "🛡 <b>ServerGuard FileGuard</b>\n\n"

            f"{severity_icon} {title}\n\n"

            f"📄 Файл:\n"
            f"<code>{path}</code>\n\n"

            f"⚙️ Событие: "
            f"<b>{event_type}</b>\n"

            f"⚠️ Уровень: "
            f"<b>{html.escape(severity)}</b>\n"

            f"🕒 Время: "
            f"<code>{event_time}</code>"
        )


        # ----------------------------------------------------
        # Old state
        # ----------------------------------------------------

        old_info = event.get(
            "old"
        )

        new_info = event.get(
            "new"
        )


        if isinstance(
            old_info,
            dict
        ) and isinstance(
            new_info,
            dict
        ):

            old_hash = old_info.get(
                "sha256"
            )

            new_hash = new_info.get(
                "sha256"
            )

            if (
                old_hash
                and
                new_hash
                and
                old_hash != new_hash
            ):

                text += (

                    "\n\n🔐 <b>SHA-256 изменён</b>\n"

                    f"<code>{html.escape(str(old_hash))}</code>\n"

                    "↓\n"

                    f"<code>{html.escape(str(new_hash))}</code>"
                )


        # ----------------------------------------------------
        # Special warnings
        # ----------------------------------------------------

        if path in (
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/gshadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config"
        ):

            text += (
                "\n\n"
                "🛡 <b>КРИТИЧЕСКИЙ СИСТЕМНЫЙ ФАЙЛ</b>"
            )


        await bot.send_message(

            chat_id=int(
                owner["chat_id"]
            ),

            text=text
        )

        print(
            "[TELEGRAM] FileGuard notification sent: "
            f"{path}",
            flush=True
        )

        return True

    except Exception as e:

        print(
            "[TELEGRAM] Cannot send FileGuard "
            f"notification: {e}",
            flush=True
        )

        return False


# ============================================================
# SECURITY MONITOR
# ============================================================

async def security_monitor(
    bot: Bot
):

    print(
        "[MONITOR] ServerGuard security monitor started",
        flush=True
    )

    seen_blocks = load_seen_blocks()

    seen_events = load_seen_events()

    seen_fileguard_events = (
        load_seen_fileguard_events()
    )


    while True:

        try:

            owner = get_owner()

            if not owner:

                await asyncio.sleep(
                    CHECK_INTERVAL
                )

                continue


            # ==================================================
            # NEW SUCCESSFUL SSH LOGINS
            # ==================================================

            events = load_events()

            changed_events = False

            current_event_signatures = set()


            for event in events:

                if not isinstance(
                    event,
                    dict
                ):
                    continue

                if event.get(
                    "type"
                ) != "success":

                    continue

                signature = event_signature(
                    event
                )

                current_event_signatures.add(
                    signature
                )

                if signature in seen_events:
                    continue


                success = (
                    await send_success_notification(
                        bot,
                        event
                    )
                )


                if success:

                    seen_events.add(
                        signature
                    )

                    changed_events = True


            if changed_events:

                seen_events = {
                    x
                    for x in seen_events
                    if x in current_event_signatures
                }

                save_seen_events(
                    seen_events
                )


            # ==================================================
            # NEW BLOCKS
            # ==================================================

            blocks = active_blocks()

            changed_blocks = False

            current_block_signatures = set()


            for ip, block in blocks.items():

                signature = block_signature(
                    ip,
                    block
                )

                signature_string = "|".join(
                    signature
                )

                current_block_signatures.add(
                    signature_string
                )

                if signature_string in seen_blocks:
                    continue


                success = (
                    await send_block_notification(
                        bot,
                        ip,
                        block
                    )
                )


                if success:

                    seen_blocks.add(
                        signature_string
                    )

                    changed_blocks = True


            if changed_blocks:

                seen_blocks = {
                    x
                    for x in seen_blocks
                    if x in current_block_signatures
                }

                save_seen_blocks(
                    seen_blocks
                )


            # ==================================================
            # FILEGUARD EVENTS
            # ==================================================

            file_events = load_file_events()

            changed_file_events = False

            current_file_signatures = set()


            for event in file_events:

                if not isinstance(
                    event,
                    dict
                ):
                    continue


                signature = (
                    fileguard_event_signature(
                        event
                    )
                )


                current_file_signatures.add(
                    signature
                )


                if signature in seen_fileguard_events:
                    continue


                success = (
                    await send_fileguard_notification(
                        bot,
                        event
                    )
                )


                if success:

                    seen_fileguard_events.add(
                        signature
                    )

                    changed_file_events = True


            if changed_file_events:

                seen_fileguard_events = {
                    x
                    for x in seen_fileguard_events
                    if x in current_file_signatures
                }

                save_seen_fileguard_events(
                    seen_fileguard_events
                )


        except Exception as e:

            print(
                f"[MONITOR] Error: {e}",
                flush=True
            )


        await asyncio.sleep(
            CHECK_INTERVAL
        )


# ============================================================
# /STATUS
# ============================================================

async def command_status(
    message: Message
):

    if not is_owner(
        message.chat.id
    ):

        await message.answer(
            "⛔ <b>Доступ запрещён.</b>"
        )

        return


    status = security_status()

    blocks = active_blocks()

    fg = fileguard_status()

    timezone_name = html.escape(
        get_owner_timezone()
    )


    if fg["active"]:

        fileguard_text = (
            "🟢 ACTIVE"
        )

    elif fg["installed"]:

        fileguard_text = (
            "🟠 INSTALLED / STOPPED"
        )

    else:

        fileguard_text = (
            "⚪ NOT INSTALLED"
        )


    text = (

        "🛡 <b>ServerGuard Status</b>\n\n"

        "🟢 Защита SSH: <b>ACTIVE</b>\n"

        f"🛡 FileGuard: "
        f"<b>{fileguard_text}</b>\n"

        "🟢 Telegram: <b>CONNECTED</b>\n\n"

        f"🕒 Часовой пояс: "
        f"<code>{timezone_name}</code>\n\n"

        "<b>SSH</b>\n"

        f"📊 Событий: "
        f"<b>{status['events']}</b>\n"

        f"❌ Неудачных входов: "
        f"<b>{status['failed']}</b>\n"

        f"✅ Успешных входов: "
        f"<b>{status['success']}</b>\n"

        f"🔒 Заблокировано IP: "
        f"<b>{status['blocked']}</b>\n"

        f"📈 IP в статистике: "
        f"<b>{status['stats']}</b>\n\n"

        "<b>FileGuard</b>\n"

        f"📄 Событий: "
        f"<b>{fg['events']}</b>\n"

        f"🔴 Critical: "
        f"<b>{fg['critical']}</b>\n"

        f"🟠 High: "
        f"<b>{fg['high']}</b>\n"

        f"🟡 Medium: "
        f"<b>{fg['medium']}</b>"
    )


    await message.answer(
        text
    )


# ============================================================
# /FILEGUARD
# ============================================================

async def command_fileguard(
    message: Message
):

    if not is_owner(
        message.chat.id
    ):

        await message.answer(
            "⛔ <b>Доступ запрещён.</b>"
        )

        return


    fg = fileguard_status()


    if not fg["installed"]:

        await message.answer(

            "🛡 <b>FileGuard</b>\n\n"

            "⚪ <b>НЕ УСТАНОВЛЕН</b>\n\n"

            "Установите FileGuard через "
            "ServerGuard."
        )

        return


    if fg["active"]:

        status_text = (
            "🟢 <b>ACTIVE / RUNNING</b>"
        )

    else:

        status_text = (
            "🔴 <b>INSTALLED / STOPPED</b>"
        )


    await message.answer(

        "🛡 <b>ServerGuard FileGuard</b>\n\n"

        f"Состояние: {status_text}\n\n"

        f"📄 Всего событий: "
        f"<b>{fg['events']}</b>\n"

        f"🔴 Critical: "
        f"<b>{fg['critical']}</b>\n"

        f"🟠 High: "
        f"<b>{fg['high']}</b>\n"

        f"🟡 Medium: "
        f"<b>{fg['medium']}</b>\n\n"

        "Команда <code>/fileevents</code> "
        "покажет последние изменения."
    )


# ============================================================
# /FILEEVENTS
# ============================================================

async def command_fileevents(
    message: Message
):

    if not is_owner(
        message.chat.id
    ):

        await message.answer(
            "⛔ <b>Доступ запрещён.</b>"
        )

        return


    events = load_file_events()


    if not events:

        await message.answer(
            "📭 <b>FileGuard событий пока нет.</b>"
        )

        return


    events = events[
        -MAX_FILE_EVENTS_TO_SHOW:
    ]


    lines = [
        "🛡 <b>Последние FileGuard события</b>\n"
    ]


    for event in reversed(
        events
    ):

        if not isinstance(
            event,
            dict
        ):
            continue


        severity = str(
            event.get(
                "severity",
                "MEDIUM"
            )
        ).upper()


        if severity == "CRITICAL":

            icon = "🔴"

        elif severity == "HIGH":

            icon = "🟠"

        else:

            icon = "🟡"


        event_type = html.escape(
            str(
                event.get(
                    "event",
                    "unknown"
                )
            )
        )


        path = html.escape(
            str(
                event.get(
                    "path",
                    "unknown"
                )
            )
        )


        timestamp = event.get(
            "timestamp"
        )


        time_text = html.escape(
            format_timestamp(
                timestamp
            )
        )


        lines.append(

            f"{icon} "
            f"<code>{time_text}</code>\n"

            f"   Event: "
            f"<b>{event_type}</b>\n"

            f"   Severity: "
            f"<b>{html.escape(severity)}</b>\n"

            f"   File: "
            f"<code>{path}</code>\n"
        )


    await message.answer(
        "\n".join(lines)
    )


# ============================================================
# /BLOCKED
# ============================================================

async def command_blocked(
    message: Message
):

    if not is_owner(
        message.chat.id
    ):

        await message.answer(
            "⛔ <b>Доступ запрещён.</b>"
        )

        return


    blocks = active_blocks()


    if not blocks:

        await message.answer(
            "🟢 <b>Заблокированных IP нет.</b>"
        )

        return


    lines = [
        "🔒 <b>Заблокированные IP</b>\n"
    ]


    count = 0


    for ip, block in blocks.items():

        if count >= MAX_BLOCKS_TO_SHOW:
            break


        ip_safe = html.escape(
            str(ip)
        )


        attempts = html.escape(
            str(
                block.get(
                    "failed_attempts",
                    "?"
                )
            )
        )


        level = html.escape(
            str(
                block.get(
                    "level",
                    "?"
                )
            )
        )


        if block.get(
            "permanent"
        ):

            lines.append(

                f"🔴 "
                f"<code>{ip_safe}</code> — "

                f"<b>PERMANENT</b> — "

                f"{attempts} попыток"
            )

        else:

            expires = html.escape(
                format_iso(
                    block.get(
                        "expires_at_iso"
                    )
                )
            )

            lines.append(

                f"🟠 "
                f"<code>{ip_safe}</code> — "

                f"{attempts} попыток — "

                f"{level} — "

                f"до {expires}"
            )


        count += 1


    await message.answer(
        "\n".join(lines)
    )


# ============================================================
# /EVENTS
# ============================================================

async def command_events(
    message: Message
):

    if not is_owner(
        message.chat.id
    ):

        await message.answer(
            "⛔ <b>Доступ запрещён.</b>"
        )

        return


    events = load_events()


    if not events:

        await message.answer(
            "📭 <b>SSH-событий пока нет.</b>"
        )

        return


    events = events[
        -MAX_EVENTS_TO_SHOW:
    ]


    lines = [
        "📋 <b>Последние SSH события</b>\n"
    ]


    for event in reversed(
        events
    ):

        if not isinstance(
            event,
            dict
        ):
            continue


        event_type = str(
            event.get(
                "type",
                "unknown"
            )
        )


        username = html.escape(
            str(
                event.get(
                    "username",
                    "?"
                )
            )
        )


        ip = html.escape(
            str(
                event.get(
                    "ip",
                    "?"
                )
            )
        )


        timestamp = event.get(
            "time"
        )


        if timestamp:

            time_text = format_timestamp(
                timestamp
            )

        else:

            time_text = format_iso(
                event.get(
                    "time_iso"
                )
            )


        time_text = html.escape(
            time_text
        )


        if event_type == "failed":

            icon = "❌"

        elif event_type == "success":

            icon = "✅"

        else:

            icon = "ℹ️"


        auth_method = event.get(
            "auth_method"
        )


        method_text = ""


        if auth_method:

            method_text = (

                f"\n   Method: "
                f"<b>"
                f"{html.escape(str(auth_method))}"
                f"</b>"
            )


        lines.append(

            f"{icon} "
            f"<code>{time_text}</code>\n"

            f"   User: "
            f"<b>{username}</b>\n"

            f"   IP: "
            f"<code>{ip}</code>"

            f"{method_text}"
        )


    await message.answer(
        "\n".join(lines)
    )


# ============================================================
# /IP
# ============================================================

async def command_ip(
    message: Message
):

    if not is_owner(
        message.chat.id
    ):

        await message.answer(
            "⛔ <b>Доступ запрещён.</b>"
        )

        return


    parts = message.text.split()


    if len(parts) != 2:

        await message.answer(

            "Использование:\n"

            "<code>/ip 1.2.3.4</code>"
        )

        return


    ip = parts[1].strip()


    blocks = load_blocks()

    stats = load_stats()


    block = blocks.get(
        ip
    )

    stat = stats.get(
        ip
    )


    text = (

        "🔎 <b>Информация об IP</b>\n\n"

        f"🌐 IP: "
        f"<code>{html.escape(ip)}</code>\n"
    )


    if block and block_is_active(
        block
    ):

        if block.get(
            "permanent"
        ):

            text += (
                "\n🔴 "
                "<b>ЗАБЛОКИРОВАН НАВСЕГДА</b>\n"
            )

        else:

            text += (

                "\n🟠 <b>ЗАБЛОКИРОВАН</b>\n"

                f"🔓 До: "
                f"<code>"
                f"{html.escape(format_iso(block.get('expires_at_iso')))}"
                f"</code>\n"
            )


        text += (

            f"⚠️ Уровень: "
            f"<b>"
            f"{html.escape(str(block.get('level', '?')))}"
            f"</b>\n"

            f"❌ Попыток: "
            f"<b>"
            f"{html.escape(str(block.get('failed_attempts', '?')))}"
            f"</b>"
        )

    else:

        text += (
            "\n🟢 <b>Сейчас не заблокирован</b>"
        )


    if isinstance(
        stat,
        dict
    ):

        failed = stat.get(
            "failed_attempts",
            0
        )

        success = stat.get(
            "successful_logins",
            0
        )

        streak = stat.get(
            "current_failed_streak",
            0
        )


        text += (

            "\n\n📊 <b>Статистика</b>\n"

            f"❌ Failed: "
            f"<b>{html.escape(str(failed))}</b>\n"

            f"✅ Success: "
            f"<b>{html.escape(str(success))}</b>\n"

            f"🔥 Текущая серия ошибок: "
            f"<b>{html.escape(str(streak))}</b>"
        )


    await message.answer(
        text
    )


# ============================================================
# /TIMEZONE
# ============================================================

async def command_timezone(
    message: Message
):

    if not is_owner(
        message.chat.id
    ):

        await message.answer(
            "⛔ <b>Доступ запрещён.</b>"
        )

        return


    parts = message.text.split(
        maxsplit=1
    )


    if len(parts) == 1:

        timezone_name = html.escape(
            get_owner_timezone()
        )


        await message.answer(

            "🕒 <b>Часовой пояс ServerGuard</b>\n\n"

            f"Текущий: "
            f"<code>{timezone_name}</code>\n\n"

            "Чтобы изменить:\n"

            "<code>/timezone Europe/Kyiv</code>\n"

            "<code>/timezone Europe/London</code>\n"

            "<code>/timezone America/New_York</code>\n\n"

            "Используйте названия часовых поясов "
            "из базы IANA."
        )

        return


    timezone_name = parts[1].strip()


    if set_owner_timezone(
        message.chat.id,
        timezone_name
    ):

        await message.answer(

            "✅ <b>Часовой пояс изменён.</b>\n\n"

            f"🕒 Теперь используется:\n"

            f"<code>"
            f"{html.escape(timezone_name)}"
            f"</code>\n\n"

            "Все новые уведомления и время в "
            "/events и /fileevents будут "
            "отображаться в этом часовом поясе."
        )

    else:

        await message.answer(

            "❌ <b>Неверный часовой пояс.</b>\n\n"

            "Например:\n"

            "<code>Europe/Kyiv</code>\n"

            "<code>Europe/London</code>\n"

            "<code>America/New_York</code>"
        )


# ============================================================
# /HELP
# ============================================================

async def command_help(
    message: Message
):

    if not is_owner(
        message.chat.id
    ):

        await message.answer(
            "⛔ <b>Доступ запрещён.</b>"
        )

        return


    text = (

        "🛡 <b>ServerGuard</b>\n\n"

        "<b>SSH защита:</b>\n"

        "/status — состояние всей защиты\n"

        "/blocked — заблокированные IP\n"

        "/events — последние SSH события\n"

        "/ip &lt;IP&gt; — информация об IP\n\n"

        "<b>FileGuard:</b>\n"

        "/fileguard — состояние FileGuard\n"

        "/fileevents — изменения файлов\n\n"

        "<b>Настройки:</b>\n"

        "/timezone — текущий часовой пояс\n"

        "/timezone &lt;ZONE&gt; — изменить часовой пояс\n"

        "/help — список команд"
    )


    await message.answer(
        text
    )


# ============================================================
# /START
# ============================================================

async def command_start(
    message: Message
):

    chat_id = message.chat.id


    # --------------------------------------------------------
    # Already owner
    # --------------------------------------------------------

    if is_owner(
        chat_id
    ):

        timezone_name = html.escape(
            get_owner_timezone()
        )


        await message.answer(

            "🛡 <b>ServerGuard</b>\n\n"

            "🟢 Вы уже зарегистрированы "
            "как владелец.\n"

            "🔔 Уведомления безопасности "
            "включены.\n"

            f"🕒 Часовой пояс: "
            f"<code>{timezone_name}</code>\n\n"

            "Используйте /help."
        )

        return


    # --------------------------------------------------------
    # Another owner already exists
    # --------------------------------------------------------

    owner = get_owner()


    if owner:

        await message.answer(

            "⛔ <b>Доступ запрещён.</b>\n\n"

            "Владелец ServerGuard "
            "уже зарегистрирован."
        )

        return


    # --------------------------------------------------------
    # Verification
    # --------------------------------------------------------

    parts = message.text.split(
        maxsplit=1
    )


    if len(parts) < 2:

        await message.answer(

            "🔐 <b>ServerGuard</b>\n\n"

            "Для регистрации владельца необходимо "
            "ввести код проверки.\n\n"

            "Пример:\n"

            "<code>/start 123456</code>"
        )

        return


    code = parts[1].strip()


    if (
        not code.isdigit()
        or
        len(code) != 6
    ):

        await message.answer(

            "❌ Неверный формат кода.\n\n"

            "Код должен содержать ровно "
            "<b>6 цифр</b>."
        )

        return


    verification = get_verification()


    if not verification:

        await message.answer(

            "❌ Код недействителен или истёк.\n\n"

            "Сгенерируйте новый код "
            "в ServerGuard."
        )

        return


    expected_code = str(
        verification.get(
            "code",
            ""
        )
    )


    if code != expected_code:

        await message.answer(
            "❌ <b>Неверный код.</b>\n\n"
            "Попробуйте ещё раз."
        )

        return


    if not consume_verification(
        message,
        verification
    ):

        await message.answer(
            "❌ Не удалось "
            "зарегистрировать владельца."
        )

        return


    await message.answer(

        "✅ "
        "<b>Владелец успешно зарегистрирован!</b>\n\n"

        "🛡 ServerGuard подключён.\n"

        "🔔 Уведомления безопасности "
        "включены.\n"

        f"🕒 Часовой пояс: "
        f"<code>{DEFAULT_TIMEZONE}</code>\n\n"

        "Используйте /help."
    )


    print(
        f"[OWNER] Registered chat_id={chat_id}",
        flush=True
    )


# ============================================================
# UNKNOWN MESSAGE
# ============================================================

async def handle_message(
    message: Message
):

    if not is_owner(
        message.chat.id
    ):

        await message.answer(

            "⛔ <b>Доступ запрещён.</b>\n\n"

            "Этот бот предназначен только "
            "для владельца ServerGuard."
        )

        return


    await message.answer(

        "🛡 <b>ServerGuard</b>\n\n"

        "Используйте /help "
        "для списка команд."
    )


# ============================================================
# MAIN
# ============================================================

async def main():

    token = load_config()


    if not token:

        print(
            "[ERROR] BOT_TOKEN not found in "
            f"{CONFIG_FILE}",
            flush=True
        )

        return


    print(
        f"[BOT] Starting ServerGuard Telegram "
        f"bot v{VERSION}...",
        flush=True
    )


    bot = Bot(

        token=token,

        default=DefaultBotProperties(
            parse_mode=ParseMode.HTML
        )
    )


    dp = Dispatcher()


    # ========================================================
    # HANDLERS
    # ========================================================

    dp.message.register(
        command_start,
        CommandStart()
    )

    dp.message.register(
        command_status,
        Command("status")
    )

    dp.message.register(
        command_blocked,
        Command("blocked")
    )

    dp.message.register(
        command_events,
        Command("events")
    )

    dp.message.register(
        command_fileguard,
        Command("fileguard")
    )

    dp.message.register(
        command_fileevents,
        Command("fileevents")
    )

    dp.message.register(
        command_ip,
        Command("ip")
    )

    dp.message.register(
        command_timezone,
        Command("timezone")
    )

    dp.message.register(
        command_help,
        Command("help")
    )

    dp.message.register(
        handle_message
    )


    # ========================================================
    # BOT TEST
    # ========================================================

    try:

        me = await bot.get_me()

        print(
            f"[BOT] Connected as "
            f"@{me.username}",
            flush=True
        )

    except Exception as e:

        print(
            f"[ERROR] Telegram connection failed: {e}",
            flush=True
        )

        await bot.session.close()

        return


    # ========================================================
    # SECURITY MONITOR
    # ========================================================

    monitor_task = asyncio.create_task(
        security_monitor(
            bot
        )
    )


    try:

        print(
            "[BOT] Polling started",
            flush=True
        )

        await dp.start_polling(
            bot
        )

    except Exception as e:

        print(
            f"[BOT] Polling error: {e}",
            flush=True
        )

    finally:

        monitor_task.cancel()

        try:

            await monitor_task

        except asyncio.CancelledError:

            pass

        await bot.session.close()

        print(
            "[BOT] Stopped",
            flush=True
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        asyncio.run(
            main()
        )

    except KeyboardInterrupt:

        print(
            "[BOT] Interrupted",
            flush=True
        )

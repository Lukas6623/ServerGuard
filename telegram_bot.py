import asyncio
import html
import json
import os
import time
from pathlib import Path
from datetime import datetime, timezone

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.types import Message


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path("/opt/serverguard")

DATA_DIR = BASE_DIR / "data"
TELEGRAM_DIR = BASE_DIR / "telegram"

CONFIG_FILE = TELEGRAM_DIR / "telegram.conf"
VERIFICATION_FILE = TELEGRAM_DIR / "verification.json"
OWNER_FILE = TELEGRAM_DIR / "owner.json"

EVENTS_FILE = DATA_DIR / "ssh_events.json"
BLOCKS_FILE = DATA_DIR / "blocked_ips.json"
STATS_FILE = DATA_DIR / "ip_stats.json"


# ============================================================
# SETTINGS
# ============================================================

CHECK_INTERVAL = 3

MAX_EVENTS_TO_SHOW = 10
MAX_BLOCKS_TO_SHOW = 30

VERIFICATION_TIMEOUT = 10 * 60


# ============================================================
# DIRECTORIES
# ============================================================

TELEGRAM_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# JSON HELPERS
# ============================================================

def load_json(path: Path, default):
    try:
        if not path.exists():
            return default

        with path.open("r", encoding="utf-8") as f:
            return json.load(f)

    except Exception as e:
        print(f"[JSON] Cannot read {path}: {e}", flush=True)
        return default


def save_json(path: Path, data):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)

        temp_path = path.with_suffix(path.suffix + ".tmp")

        with temp_path.open("w", encoding="utf-8") as f:
            json.dump(
                data,
                f,
                ensure_ascii=False,
                indent=2
            )
            f.write("\n")

        os.replace(temp_path, path)

        return True

    except Exception as e:
        print(f"[JSON] Cannot write {path}: {e}", flush=True)
        return False


# ============================================================
# CONFIG
# ============================================================

def load_config():
    token = ""

    try:
        if not CONFIG_FILE.exists():
            return ""

        with CONFIG_FILE.open("r", encoding="utf-8") as f:

            for raw_line in f:
                line = raw_line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                if line.startswith("BOT_TOKEN="):
                    token = line.split("=", 1)[1].strip()

        return token

    except Exception as e:
        print(f"[CONFIG] Cannot read config: {e}", flush=True)
        return ""


# ============================================================
# OWNER
# ============================================================

def get_owner():
    data = load_json(OWNER_FILE, {})

    if not isinstance(data, dict):
        return None

    if not data.get("verified"):
        return None

    if not data.get("chat_id"):
        return None

    return data


def is_owner(chat_id: int):
    owner = get_owner()

    if not owner:
        return False

    try:
        return int(owner["chat_id"]) == int(chat_id)

    except Exception:
        return False


# ============================================================
# VERIFICATION
# ============================================================

def get_verification():
    data = load_json(VERIFICATION_FILE, {})

    if not isinstance(data, dict):
        return None

    code = str(data.get("code", "")).strip()

    if not code:
        return None

    expires_at = int(data.get("expires_at", 0))

    if expires_at <= int(time.time()):
        try:
            VERIFICATION_FILE.unlink(missing_ok=True)
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
        "chat_id": message.chat.id,
        "user_id": user.id if user else None,
        "username": user.username if user else None,
        "first_name": user.first_name if user else None,
        "registered_at": int(time.time()),
        "registered_at_iso": datetime.now(
            timezone.utc
        ).isoformat(),
        "verified": True
    }

    if not save_json(OWNER_FILE, owner_data):
        return False

    try:
        VERIFICATION_FILE.unlink(missing_ok=True)
    except Exception:
        pass

    return True


# ============================================================
# TIME
# ============================================================

def format_time(value):
    try:
        timestamp = int(value)

        dt = datetime.fromtimestamp(
            timestamp,
            timezone.utc
        )

        return dt.strftime("%d.%m.%Y %H:%M:%S UTC")

    except Exception:
        return "unknown"


def format_iso(value):
    if not value:
        return "unknown"

    return str(value).replace("T", " ")[:19]


# ============================================================
# BLOCK DATA
# ============================================================

def load_blocks():
    data = load_json(BLOCKS_FILE, {})

    if not isinstance(data, dict):
        return {}

    return data


def load_events():
    data = load_json(EVENTS_FILE, [])

    if not isinstance(data, list):
        return []

    return data


def load_stats():
    data = load_json(STATS_FILE, {})

    if not isinstance(data, dict):
        return {}

    return data


# ============================================================
# BLOCK STATUS
# ============================================================

def block_is_active(block):
    if not isinstance(block, dict):
        return False

    if block.get("permanent"):
        return True

    expires_at = block.get("expires_at")

    if expires_at is None:
        return False

    try:
        return int(expires_at) > int(time.time())

    except Exception:
        return False


def active_blocks():
    blocks = load_blocks()

    result = {}

    for ip, block in blocks.items():

        if block_is_active(block):
            result[ip] = block

    return result


# ============================================================
# SECURITY STATUS
# ============================================================

def security_status():
    events = load_events()
    blocks = active_blocks()
    stats = load_stats()

    failed_events = 0
    successful_events = 0

    for event in events:

        event_type = event.get("type")

        if event_type == "failed":
            failed_events += 1

        elif event_type == "success":
            successful_events += 1

    return {
        "events": len(events),
        "failed": failed_events,
        "success": successful_events,
        "blocked": len(blocks),
        "stats": len(stats)
    }


# ============================================================
# NEW BLOCK DETECTION
# ============================================================

def block_signature(ip, block):
    return (
        str(ip),
        str(block.get("level")),
        str(block.get("failed_attempts")),
        str(block.get("blocked_at")),
        str(block.get("expires_at")),
        str(block.get("permanent"))
    )


def load_seen_blocks():
    data = load_json(
        TELEGRAM_DIR / "seen_blocks.json",
        []
    )

    if not isinstance(data, list):
        return set()

    return set(str(x) for x in data)


def save_seen_blocks(seen):
    path = TELEGRAM_DIR / "seen_blocks.json"

    return save_json(
        path,
        list(seen)
    )


# ============================================================
# TELEGRAM NOTIFICATION
# ============================================================

async def send_block_notification(
    bot: Bot,
    ip: str,
    block: dict
):
    try:
        ip_safe = html.escape(str(ip))

        level = html.escape(
            str(block.get("level", "unknown"))
        )

        attempts = html.escape(
            str(block.get("failed_attempts", "unknown"))
        )

        blocked_at = html.escape(
            format_iso(block.get("blocked_at_iso"))
        )

        permanent = bool(
            block.get("permanent", False)
        )

        if permanent:

            text = (
                "🚨 <b>ServerGuard</b>\n\n"
                "🔴 <b>IP ЗАБЛОКИРОВАН НАВСЕГДА</b>\n\n"
                f"🌐 IP: <code>{ip_safe}</code>\n"
                f"❌ Попыток: <b>{attempts}</b>\n"
                f"⚠️ Уровень: <b>{level}</b>\n"
                f"🕒 Время: <code>{blocked_at}</code>"
            )

        else:

            expires_at = html.escape(
                format_iso(
                    block.get("expires_at_iso")
                )
            )

            text = (
                "🚨 <b>ServerGuard</b>\n\n"
                "🔒 <b>IP ЗАБЛОКИРОВАН</b>\n\n"
                f"🌐 IP: <code>{ip_safe}</code>\n"
                f"❌ Попыток: <b>{attempts}</b>\n"
                f"⚠️ Уровень: <b>{level}</b>\n"
                f"🕒 Заблокирован: <code>{blocked_at}</code>\n"
                f"🔓 До: <code>{expires_at}</code>"
            )

        owner = get_owner()

        if not owner:
            return False

        await bot.send_message(
            chat_id=int(owner["chat_id"]),
            text=text
        )

        print(
            f"[TELEGRAM] Block notification sent: {ip}",
            flush=True
        )

        return True

    except Exception as e:

        print(
            f"[TELEGRAM] Cannot send block notification: {e}",
            flush=True
        )

        return False


# ============================================================
# MONITOR
# ============================================================

async def security_monitor(bot: Bot):

    print(
        "[MONITOR] ServerGuard security monitor started",
        flush=True
    )

    seen = load_seen_blocks()

    while True:

        try:

            owner = get_owner()

            if not owner:
                await asyncio.sleep(CHECK_INTERVAL)
                continue

            blocks = active_blocks()

            changed = False

            for ip, block in blocks.items():

                signature = block_signature(
                    ip,
                    block
                )

                signature_string = "|".join(
                    signature
                )

                if signature_string in seen:
                    continue

                success = await send_block_notification(
                    bot,
                    ip,
                    block
                )

                if success:

                    seen.add(signature_string)
                    changed = True

            if changed:

                # Remove old entries which are no longer
                # present in current block list.
                current_signatures = set()

                for ip, block in blocks.items():

                    current_signatures.add(
                        "|".join(
                            block_signature(ip, block)
                        )
                    )

                seen = {
                    x for x in seen
                    if x in current_signatures
                }

                save_seen_blocks(seen)

        except Exception as e:

            print(
                f"[MONITOR] Error: {e}",
                flush=True
            )

        await asyncio.sleep(CHECK_INTERVAL)


# ============================================================
# /STATUS
# ============================================================

async def command_status(message: Message):

    if not is_owner(message.chat.id):

        await message.answer(
            "⛔ <b>Доступ запрещён.</b>"
        )

        return

    status = security_status()

    blocks = active_blocks()

    text = (
        "🛡 <b>ServerGuard Status</b>\n\n"
        "🟢 Защита SSH: <b>ACTIVE</b>\n"
        "🟢 Telegram: <b>CONNECTED</b>\n\n"
        f"📊 Событий: <b>{status['events']}</b>\n"
        f"❌ Неудачных входов: <b>{status['failed']}</b>\n"
        f"✅ Успешных входов: <b>{status['success']}</b>\n"
        f"🔒 Заблокировано IP: <b>{status['blocked']}</b>\n"
        f"📈 IP в статистике: <b>{status['stats']}</b>"
    )

    await message.answer(text)


# ============================================================
# /BLOCKED
# ============================================================

async def command_blocked(message: Message):

    if not is_owner(message.chat.id):

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

        ip_safe = html.escape(str(ip))

        attempts = html.escape(
            str(block.get("failed_attempts", "?"))
        )

        level = html.escape(
            str(block.get("level", "?"))
        )

        if block.get("permanent"):

            lines.append(
                f"🔴 <code>{ip_safe}</code> — "
                f"<b>PERMANENT</b> — "
                f"{attempts} попыток"
            )

        else:

            expires = format_iso(
                block.get("expires_at_iso")
            )

            expires = html.escape(expires)

            lines.append(
                f"🟠 <code>{ip_safe}</code> — "
                f"{attempts} попыток — "
                f"{level} — до {expires}"
            )

        count += 1

    await message.answer(
        "\n".join(lines)
    )


# ============================================================
# /EVENTS
# ============================================================

async def command_events(message: Message):

    if not is_owner(message.chat.id):

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

    events = events[-MAX_EVENTS_TO_SHOW:]

    lines = [
        "📋 <b>Последние SSH события</b>\n"
    ]

    for event in reversed(events):

        event_type = str(
            event.get("type", "unknown")
        )

        username = html.escape(
            str(event.get("username", "?"))
        )

        ip = html.escape(
            str(event.get("ip", "?"))
        )

        time_text = html.escape(
            format_iso(
                event.get("time_iso")
            )
        )

        if event_type == "failed":

            icon = "❌"

        elif event_type == "success":

            icon = "✅"

        else:

            icon = "ℹ️"

        lines.append(
            f"{icon} <code>{time_text}</code>\n"
            f"   User: <b>{username}</b>\n"
            f"   IP: <code>{ip}</code>"
        )

    await message.answer(
        "\n".join(lines)
    )


# ============================================================
# /IP
# ============================================================

async def command_ip(message: Message):

    if not is_owner(message.chat.id):

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

    block = blocks.get(ip)
    stat = stats.get(ip)

    text = (
        "🔎 <b>Информация об IP</b>\n\n"
        f"🌐 IP: <code>{html.escape(ip)}</code>\n"
    )

    if block and block_is_active(block):

        if block.get("permanent"):

            text += (
                "\n🔴 <b>ЗАБЛОКИРОВАН НАВСЕГДА</b>\n"
            )

        else:

            text += (
                "\n🟠 <b>ЗАБЛОКИРОВАН</b>\n"
                f"🔓 До: <code>"
                f"{html.escape(format_iso(block.get('expires_at_iso')))}"
                f"</code>\n"
            )

        text += (
            f"⚠️ Уровень: <b>"
            f"{html.escape(str(block.get('level', '?')))}"
            f"</b>\n"
            f"❌ Попыток: <b>"
            f"{html.escape(str(block.get('failed_attempts', '?')))}"
            f"</b>"
        )

    else:

        text += "\n🟢 <b>Сейчас не заблокирован</b>"

    if isinstance(stat, dict):

        text += (
            "\n\n📊 <b>Статистика</b>\n"
            f"❌ Failed: <b>"
            f"{html.escape(str(stat.get('failed', 0)))}"
            f"</b>\n"
            f"✅ Success: <b>"
            f"{html.escape(str(stat.get('success', 0)))}"
            f"</b>"
        )

    await message.answer(text)


# ============================================================
# /HELP
# ============================================================

async def command_help(message: Message):

    if not is_owner(message.chat.id):

        await message.answer(
            "⛔ <b>Доступ запрещён.</b>"
        )

        return

    text = (
        "🛡 <b>ServerGuard</b>\n\n"
        "<b>Команды:</b>\n\n"
        "/status — состояние защиты\n"
        "/blocked — заблокированные IP\n"
        "/events — последние SSH события\n"
        "/ip &lt;IP&gt; — информация об IP\n"
        "/help — список команд"
    )

    await message.answer(text)


# ============================================================
# /START
# ============================================================

async def command_start(message: Message):

    chat_id = message.chat.id

    # Already owner
    if is_owner(chat_id):

        await message.answer(
            "🛡 <b>ServerGuard</b>\n\n"
            "🟢 Вы уже зарегистрированы как владелец.\n"
            "🔔 Уведомления о блокировках включены.\n\n"
            "Используйте /help."
        )

        return

    # Another owner already exists
    owner = get_owner()

    if owner:

        await message.answer(
            "⛔ <b>Доступ запрещён.</b>\n\n"
            "Владелец ServerGuard уже зарегистрирован."
        )

        return

    # Get verification code
    parts = message.text.split(maxsplit=1)

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

    if not code.isdigit() or len(code) != 6:

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
            "Сгенерируйте новый код в ServerGuard."
        )

        return

    expected_code = str(
        verification.get("code", "")
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
            "❌ Не удалось зарегистрировать владельца."
        )

        return

    await message.answer(
        "✅ <b>Владелец успешно зарегистрирован!</b>\n\n"
        "🛡 ServerGuard подключён.\n"
        "🔔 Уведомления о безопасности включены.\n\n"
        "Используйте /help."
    )

    print(
        f"[OWNER] Registered chat_id={chat_id}",
        flush=True
    )


# ============================================================
# UNKNOWN MESSAGE
# ============================================================

async def handle_message(message: Message):

    if not is_owner(message.chat.id):

        await message.answer(
            "⛔ <b>Доступ запрещён.</b>\n\n"
            "Этот бот предназначен только "
            "для владельца ServerGuard."
        )

        return

    await message.answer(
        "🛡 <b>ServerGuard</b>\n\n"
        "Используйте /help для списка команд."
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
        "[BOT] Starting ServerGuard Telegram bot...",
        flush=True
    )

    bot = Bot(
        token=token,
        default=DefaultBotProperties(
            parse_mode=ParseMode.HTML
        )
    )

    dp = Dispatcher()

    # --------------------------------------------------------
    # HANDLERS
    # --------------------------------------------------------

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
        command_ip,
        Command("ip")
    )

    dp.message.register(
        command_help,
        Command("help")
    )

    dp.message.register(
        handle_message
    )

    # --------------------------------------------------------
    # BOT TEST
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # SECURITY MONITOR
    # --------------------------------------------------------

    monitor_task = asyncio.create_task(
        security_monitor(bot)
    )

    try:

        print(
            "[BOT] Polling started",
            flush=True
        )

        await dp.start_polling(bot)

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

        asyncio.run(main())

    except KeyboardInterrupt:

        print(
            "[BOT] Interrupted",
            flush=True
        )

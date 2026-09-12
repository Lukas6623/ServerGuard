import asyncio
import json
import os
import time
from pathlib import Path

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import CommandStart
from aiogram.types import Message


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path("/opt/serverguard")
TELEGRAM_DIR = BASE_DIR / "telegram"

CONFIG_FILE = TELEGRAM_DIR / "telegram.conf"
VERIFICATION_FILE = TELEGRAM_DIR / "verification.json"
OWNER_FILE = TELEGRAM_DIR / "owner.json"
QUEUE_DIR = TELEGRAM_DIR / "queue"

POLL_INTERVAL = 2


# ============================================================
# DIRECTORIES
# ============================================================

TELEGRAM_DIR.mkdir(parents=True, exist_ok=True)
QUEUE_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# DISPATCHER
# ============================================================

dp = Dispatcher()


# ============================================================
# JSON HELPERS
# ============================================================

def load_json(path: Path):
    try:
        if not path.exists():
            return None

        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    except Exception:
        return None


def save_json(path: Path, data):
    temp_path = path.with_suffix(".tmp")

    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(
                data,
                f,
                ensure_ascii=False,
                indent=2
            )

        os.replace(temp_path, path)
        return True

    except Exception:
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass

        return False


# ============================================================
# CONFIG
# ============================================================

def load_config():
    if not CONFIG_FILE.exists():
        return None

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:

            for line in f:
                line = line.strip()

                if not line:
                    continue

                if line.startswith("BOT_TOKEN="):
                    return line.split("=", 1)[1].strip()

    except Exception:
        pass

    return None


# ============================================================
# OWNER
# ============================================================

def get_owner():
    data = load_json(OWNER_FILE)

    if not data:
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
    data = load_json(VERIFICATION_FILE)

    if not data:
        return None

    code = str(data.get("code", ""))
    expires_at = float(data.get("expires_at", 0))

    if not code:
        return None

    if time.time() > expires_at:
        try:
            VERIFICATION_FILE.unlink()
        except Exception:
            pass

        return None

    return data


def consume_verification(message: Message):

    verification = get_verification()

    if not verification:
        return False

    code = str(verification.get("code", ""))

    user = message.from_user

    owner_data = {
        "chat_id": message.chat.id,
        "user_id": user.id if user else None,
        "username": user.username if user else None,
        "first_name": user.first_name if user else None,
        "registered_at": int(time.time()),
        "verified": True
    }

    if not save_json(OWNER_FILE, owner_data):
        return False

    try:
        VERIFICATION_FILE.unlink()
    except Exception:
        pass

    return True


# ============================================================
# /START
# ============================================================

@dp.message(CommandStart())
async def command_start(message: Message):

    chat_id = message.chat.id

    # --------------------------------------------------------
    # Already owner
    # --------------------------------------------------------

    if is_owner(chat_id):

        await message.answer(
            "🛡 <b>ServerGuard</b>\n\n"
            "✅ Вы уже зарегистрированы как владелец.\n"
            "🔔 Уведомления безопасности включены.\n\n"
            "Доступные команды:\n"
            "/status — состояние защиты"
        )

        return

    # --------------------------------------------------------
    # Another user when owner already exists
    # --------------------------------------------------------

    owner = get_owner()

    if owner:

        await message.answer(
            "⛔ <b>Доступ запрещён.</b>\n\n"
            "Этот бот уже привязан к владельцу сервера."
        )

        return

    # --------------------------------------------------------
    # Get command arguments
    # --------------------------------------------------------

    text = message.text or ""

    parts = text.split(maxsplit=1)

    if len(parts) < 2:

        await message.answer(
            "🛡 <b>ServerGuard</b>\n\n"
            "Для регистрации необходимо ввести "
            "код подтверждения.\n\n"
            "Пример:\n"
            "<code>/start 123456</code>"
        )

        return

    code = parts[1].strip()

    # --------------------------------------------------------
    # Code format
    # --------------------------------------------------------

    if not code.isdigit() or len(code) != 6:

        await message.answer(
            "❌ Неверный формат кода.\n\n"
            "Код должен состоять из <b>6 цифр</b>."
        )

        return

    # --------------------------------------------------------
    # Check verification
    # --------------------------------------------------------

    verification = get_verification()

    if not verification:

        await message.answer(
            "❌ Код подтверждения отсутствует "
            "или уже истёк.\n\n"
            "Сгенерируйте новый код через ServerGuard."
        )

        return

    expected_code = str(verification.get("code", ""))

    if code != expected_code:

        await message.answer(
            "❌ Неверный код подтверждения."
        )

        return

    # --------------------------------------------------------
    # Register owner
    # --------------------------------------------------------

    if consume_verification(message):

        await message.answer(
            "✅ <b>Регистрация успешно завершена!</b>\n\n"
            "🛡 Вы назначены владельцем ServerGuard.\n"
            "🔔 Уведомления безопасности включены.\n\n"
            "Теперь бот принимает события безопасности "
            "от вашего ServerGuard."
        )

    else:

        await message.answer(
            "❌ Не удалось сохранить регистрацию владельца."
        )


# ============================================================
# NORMAL MESSAGES
# ============================================================

@dp.message()
async def normal_message(message: Message):

    chat_id = message.chat.id

    # --------------------------------------------------------
    # Not owner
    # --------------------------------------------------------

    if not is_owner(chat_id):

        await message.answer(
            "⛔ <b>Доступ запрещён.</b>\n\n"
            "Этот Telegram-бот предназначен только "
            "для владельца сервера."
        )

        return

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

    text = (message.text or "").strip()

    if text == "/status":

        await message.answer(
            "🛡 <b>ServerGuard</b>\n\n"
            "🟢 Владелец подтверждён\n"
            "🟢 Telegram-уведомления активны\n"
            "🟢 Защита сервера активна"
        )

        return

    # --------------------------------------------------------
    # Unknown command
    # --------------------------------------------------------

    await message.answer(
        "🛡 <b>ServerGuard</b>\n\n"
        "Доступные команды:\n"
        "/status — состояние защиты"
    )


# ============================================================
# ALERT QUEUE
# ============================================================

async def alert_worker(bot: Bot):

    while True:

        try:

            owner = get_owner()

            if not owner:
                await asyncio.sleep(POLL_INTERVAL)
                continue

            chat_id = owner.get("chat_id")

            if not chat_id:
                await asyncio.sleep(POLL_INTERVAL)
                continue

            files = sorted(
                QUEUE_DIR.glob("*.json"),
                key=lambda p: p.stat().st_mtime
            )

            for file_path in files:

                data = load_json(file_path)

                if not data:
                    continue

                message_text = data.get("message")

                if not message_text:
                    continue

                try:

                    await bot.send_message(
                        chat_id=int(chat_id),
                        text=message_text
                    )

                    # Delete only after successful sending
                    try:
                        file_path.unlink()
                    except Exception:
                        pass

                except Exception:
                    # Keep file for retry
                    pass

        except Exception:
            pass

        await asyncio.sleep(POLL_INTERVAL)


# ============================================================
# MAIN
# ============================================================

async def main():

    token = load_config()

    if not token:

        print("ERROR: Telegram bot token not found.")
        return

    bot = Bot(
        token=token,
        default=DefaultBotProperties(
            parse_mode=ParseMode.HTML
        )
    )

    worker_task = None

    try:

        # ----------------------------------------------------
        # Check bot token
        # ----------------------------------------------------

        me = await bot.get_me()

        print(
            f"Telegram bot started: "
            f"@{me.username}"
        )

        # ----------------------------------------------------
        # Start alert worker
        # ----------------------------------------------------

        worker_task = asyncio.create_task(
            alert_worker(bot)
        )

        # ----------------------------------------------------
        # Start polling
        # ----------------------------------------------------

        await dp.start_polling(bot)

    except Exception as e:

        print(
            f"Telegram bot error: {e}"
        )

    finally:

        if worker_task:

            worker_task.cancel()

            try:
                await worker_task
            except asyncio.CancelledError:
                pass

        await bot.session.close()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    asyncio.run(main())

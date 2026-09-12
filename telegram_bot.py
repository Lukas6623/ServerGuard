#!/usr/bin/env python3

import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import CommandStart
from aiogram.types import Message


# ============================================================
# SERVERGUARD TELEGRAM BOT
# ============================================================

BASE_DIR = Path("/opt/serverguard")
TELEGRAM_DIR = BASE_DIR / "telegram"

CONFIG_FILE = TELEGRAM_DIR / "telegram.conf"
VERIFICATION_FILE = TELEGRAM_DIR / "verification.json"
OWNER_FILE = TELEGRAM_DIR / "owner.json"
QUEUE_DIR = TELEGRAM_DIR / "queue"

POLL_INTERVAL = 2


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("ServerGuardTelegram")


# ============================================================
# DIRECTORIES
# ============================================================

TELEGRAM_DIR.mkdir(parents=True, exist_ok=True)
QUEUE_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# FILE HELPERS
# ============================================================

def load_json(path: Path, default=None):
    try:
        if not path.exists():
            return default

        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)

    except Exception as exc:
        logger.error("Failed to read %s: %s", path, exc)
        return default


def save_json(path: Path, data):
    temporary = path.with_suffix(path.suffix + ".tmp")

    try:
        with open(temporary, "w", encoding="utf-8") as file:
            json.dump(
                data,
                file,
                indent=4,
                ensure_ascii=False
            )

        os.replace(temporary, path)

    except Exception as exc:
        logger.error("Failed to write %s: %s", path, exc)

        try:
            if temporary.exists():
                temporary.unlink()
        except Exception:
            pass


# ============================================================
# CONFIG
# ============================================================

def load_config():
    if not CONFIG_FILE.exists():
        logger.error("Telegram configuration does not exist.")
        logger.error("Expected: %s", CONFIG_FILE)
        return None

    config = {}

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                if "=" not in line:
                    continue

                key, value = line.split("=", 1)

                key = key.strip()
                value = value.strip()

                config[key] = value

    except Exception as exc:
        logger.error("Cannot read telegram.conf: %s", exc)
        return None

    token = config.get("BOT_TOKEN", "").strip()

    if not token:
        logger.error("BOT_TOKEN is missing.")
        return None

    return {
        "token": token
    }


# ============================================================
# OWNER
# ============================================================

def get_owner():
    owner = load_json(OWNER_FILE, None)

    if not isinstance(owner, dict):
        return None

    if not owner.get("verified"):
        return None

    chat_id = owner.get("chat_id")

    if chat_id is None:
        return None

    return owner


def is_owner(chat_id: int) -> bool:
    owner = get_owner()

    if owner is None:
        return False

    return str(owner.get("chat_id")) == str(chat_id)


# ============================================================
# VERIFICATION
# ============================================================

def get_verification():
    verification = load_json(
        VERIFICATION_FILE,
        None
    )

    if not isinstance(verification, dict):
        return None

    return verification


def verification_is_valid(code: str) -> bool:
    verification = get_verification()

    if verification is None:
        return False

    expected_code = str(
        verification.get("code", "")
    ).strip()

    expires_at = verification.get("expires_at", 0)

    try:
        expires_at = float(expires_at)
    except Exception:
        return False

    if not expected_code:
        return False

    if expected_code != code:
        return False

    if time.time() > expires_at:
        return False

    return True


def consume_verification(
    message: Message,
    code: str
) -> bool:

    if not verification_is_valid(code):
        return False

    owner = {
        "chat_id": message.chat.id,
        "user_id": message.from_user.id if message.from_user else None,
        "username": (
            message.from_user.username
            if message.from_user
            else None
        ),
        "first_name": (
            message.from_user.first_name
            if message.from_user
            else None
        ),
        "registered_at": int(time.time()),
        "verified": True
    }

    save_json(
        OWNER_FILE,
        owner
    )

    # Verification code becomes invalid immediately.
    try:
        if VERIFICATION_FILE.exists():
            VERIFICATION_FILE.unlink()
    except Exception as exc:
        logger.error(
            "Cannot remove verification file: %s",
            exc
        )

    return True


# ============================================================
# START COMMAND
# ============================================================

@Dispatcher().message()
async def unused_handler(message: Message):
    pass


dp = Dispatcher()


@dp.message(CommandStart())
async def command_start(message: Message):

    if message.from_user is None:
        return

    chat_id = message.chat.id

    # --------------------------------------------------------
    # ALREADY REGISTERED OWNER
    # --------------------------------------------------------

    if is_owner(chat_id):

        await message.answer(
            "🛡 <b>ServerGuard</b>\n\n"
            "✅ Owner verification: <b>OK</b>\n"
            "🔔 Telegram alerts: <b>ENABLED</b>\n\n"
            "This Telegram account is registered "
            "as the ServerGuard owner."
        )

        return

    # --------------------------------------------------------
    # ANOTHER USER WHEN OWNER ALREADY EXISTS
    # --------------------------------------------------------

    owner = get_owner()

    if owner is not None:

        await message.answer(
            "❌ <b>Access denied.</b>\n\n"
            "This ServerGuard bot is already registered "
            "to its owner.\n\n"
            "You cannot register another Telegram account."
        )

        logger.warning(
            "Unauthorized Telegram user tried to access bot: chat_id=%s",
            chat_id
        )

        return

    # --------------------------------------------------------
    # GET /start ARGUMENT
    # --------------------------------------------------------

    text = message.text or ""

    parts = text.split(maxsplit=1)

    code = ""

    if len(parts) == 2:
        code = parts[1].strip()

    # --------------------------------------------------------
    # NO CODE
    # --------------------------------------------------------

    if not code:

        await message.answer(
            "🛡 <b>ServerGuard</b>\n\n"
            "This bot is protected.\n\n"
            "Registration requires a verification code "
            "generated by ServerGuard.\n\n"
            "Send the verification command provided "
            "by ServerGuard."
        )

        return

    # --------------------------------------------------------
    # CODE FORMAT
    # --------------------------------------------------------

    if not re.fullmatch(r"\d{6}", code):

        await message.answer(
            "❌ <b>Invalid verification code.</b>\n\n"
            "The code must contain exactly 6 digits."
        )

        return

    # --------------------------------------------------------
    # VERIFY
    # --------------------------------------------------------

    if not verification_is_valid(code):

        await message.answer(
            "❌ <b>Verification failed.</b>\n\n"
            "The code is invalid or expired.\n\n"
            "Generate a new verification code "
            "from ServerGuard."
        )

        logger.warning(
            "Failed Telegram verification: chat_id=%s",
            chat_id
        )

        return

    # --------------------------------------------------------
    # REGISTER OWNER
    # --------------------------------------------------------

    if consume_verification(message, code):

        await message.answer(
            "🛡 <b>ServerGuard</b>\n\n"
            "✅ <b>Verification successful!</b>\n\n"
            "👤 Telegram account registered as owner.\n"
            "🔔 Security alerts: <b>ENABLED</b>\n\n"
            "Critical ServerGuard security events "
            "will now be sent to this chat."
        )

        logger.info(
            "Telegram owner registered: chat_id=%s username=%s",
            chat_id,
            message.from_user.username
        )

        return

    await message.answer(
        "❌ Verification failed."
    )


# ============================================================
# NORMAL MESSAGES
# ============================================================

@dp.message()
async def normal_message(message: Message):

    if message.from_user is None:
        return

    chat_id = message.chat.id

    # Only owner receives useful responses.
    if not is_owner(chat_id):

        await message.answer(
            "🔒 <b>ServerGuard</b>\n\n"
            "Access denied.\n"
            "Owner verification is required."
        )

        return

    text = (message.text or "").strip()

    if text == "/status":

        await message.answer(
            "🛡 <b>ServerGuard</b>\n\n"
            "Owner: ✅ verified\n"
            "Telegram alerts: ✅ enabled\n"
            "Security channel: 🟢 active"
        )

        return

    await message.answer(
        "🛡 <b>ServerGuard</b>\n\n"
        "Telegram security channel is active.\n\n"
        "Available command:\n"
        "/status"
    )


# ============================================================
# TELEGRAM ALERT QUEUE
# ============================================================

async def process_alert_queue(bot: Bot):

    logger.info(
        "Telegram alert worker started."
    )

    while True:

        try:

            owner = get_owner()

            if owner is None:
                await asyncio.sleep(POLL_INTERVAL)
                continue

            chat_id = owner.get("chat_id")

            if chat_id is None:
                await asyncio.sleep(POLL_INTERVAL)
                continue

            files = sorted(
                QUEUE_DIR.glob("*.json")
            )

            for alert_file in files:

                try:

                    alert = load_json(
                        alert_file,
                        None
                    )

                    if not isinstance(alert, dict):
                        logger.error(
                            "Invalid alert file: %s",
                            alert_file
                        )

                        alert_file.unlink(
                            missing_ok=True
                        )

                        continue

                    text = alert.get("message")

                    if not text:
                        logger.error(
                            "Alert without message: %s",
                            alert_file
                        )

                        alert_file.unlink(
                            missing_ok=True
                        )

                        continue

                    # ------------------------------------------------
                    # SEND ALERT
                    # ------------------------------------------------

                    await bot.send_message(
                        chat_id=chat_id,
                        text=text,
                        parse_mode=ParseMode.HTML
                    )

                    # ------------------------------------------------
                    # DELETE ONLY AFTER SUCCESSFUL SEND
                    # ------------------------------------------------

                    alert_file.unlink(
                        missing_ok=True
                    )

                    logger.info(
                        "Telegram alert sent: %s",
                        alert_file.name
                    )

                except Exception as exc:

                    logger.error(
                        "Failed to send Telegram alert %s: %s",
                        alert_file.name,
                        exc
                    )

                    # Do NOT delete file.
                    # It will be retried later.

        except Exception as exc:

            logger.error(
                "Alert worker error: %s",
                exc
            )

        await asyncio.sleep(POLL_INTERVAL)


# ============================================================
# MAIN
# ============================================================

async def main():

    config = load_config()

    if config is None:
        logger.error(
            "Telegram bot cannot start."
        )
        return

    token = config["token"]

    logger.info(
        "Starting ServerGuard Telegram Bot..."
    )

    bot = Bot(
        token=token,
        default=DefaultBotProperties(
            parse_mode=ParseMode.HTML
        )
    )

    try:

        me = await bot.get_me()

        logger.info(
            "Connected to Telegram as @%s",
            me.username
        )

        # Start alert worker.
        worker = asyncio.create_task(
            process_alert_queue(bot)
        )

        try:

            await dp.start_polling(
                bot
            )

        finally:

            worker.cancel()

            try:
                await worker
            except asyncio.CancelledError:
                pass

    finally:

        await bot.session.close()

        logger.info(
            "ServerGuard Telegram Bot stopped."
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:
        asyncio.run(main())

    except KeyboardInterrupt:

        logger.info(
            "ServerGuard Telegram Bot stopped by user."
        )

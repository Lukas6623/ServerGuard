#!/usr/bin/env python3
"""
ServerGuard - SSH Brute Force Guard (hardened rewrite)

Обмен с Telegram-ботом идёт ТОЛЬКО через JSON-файлы в /opt/serverguard/data.
Имена файлов, ключи и типы значений сохранены без изменений:

    protection_config.json  - читаем (бот пишет)
    ssh_events.json         - пишем список событий
    blocked_ips.json        - пишем словарь блокировок {ip: {...}}
    stats.json              - пишем счётчики failed/success/blocked/unblocked

Необязательный пример unit-файла systemd (Type=notify + watchdog):

    [Service]
    Type=notify
    NotifyAccess=main
    WatchdogSec=60
    Restart=always
    RestartSec=3
    ExecStart=/usr/bin/python3 /opt/serverguard/brute_force_guard.py

Если unit у вас Type=simple - скрипт тоже работает (sd_notify просто не используется).

Самопроверка разбора логов (без root, без ufw):
    python3 brute_force_guard.py --selftest
"""

from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import time
from collections import OrderedDict, deque
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Iterator, List, NamedTuple, Optional, Set, Tuple

# --------------------------------------------------------------------------- #
# Константы
# --------------------------------------------------------------------------- #

BASE_DIR = Path("/opt/serverguard")
DATA_DIR = BASE_DIR / "data"

PROTECTION_CONFIG_FILE = DATA_DIR / "protection_config.json"
EVENTS_FILE = DATA_DIR / "ssh_events.json"
BLOCKS_FILE = DATA_DIR / "blocked_ips.json"
STATS_FILE = DATA_DIR / "stats.json"
DATA_LOCK_FILE = DATA_DIR / ".guard.lock"
INSTANCE_LOCK_FILE = Path("/run/serverguard-guard.lock")

MAX_EVENTS = 2000
EVENT_RETENTION_DAYS = 7
CLEANUP_INTERVAL = 60          # сек: истечение блокировок, чистка событий
RECONCILE_INTERVAL = 600       # сек: сверка blocked_ips.json с правилами ufw
CONFIG_CHECK_INTERVAL = 5      # сек: как часто проверять mtime конфига
FLUSH_INTERVAL = 1.0           # сек: как часто сбрасывать события/статистику на диск
COMMAND_TIMEOUT = 15
SELECT_TIMEOUT = 1.0

MAX_TRACKED_IPS = 50_000       # защита памяти от ботнетов
MAX_TRACKED_CONNS = 20_000
CONN_CREDIT_TTL = 60.0         # сек: окно дедупликации "Invalid user" + "Failed ..."
MAX_LINE_BYTES = 64 * 1024
PENDING_LIMIT = 5_000

DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": True,
    "attempts": 5,
    "duration": 600,
    "permanent": False,
    "mode": "ip",
    "whitelist": [],
    "window": 3600,   # новый необязательный ключ: окно подсчёта попыток, сек
}

AUTH_LOG_CANDIDATES = ("/var/log/auth.log", "/var/log/secure")


def log(message: str) -> None:
    print(f"[ServerGuard] {message}", flush=True)


# --------------------------------------------------------------------------- #
# systemd notify (необязательно)
# --------------------------------------------------------------------------- #

def sd_notify(state: str) -> None:
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(state.encode("utf-8"))
    except OSError:
        pass


def watchdog_interval() -> Optional[float]:
    try:
        usec = int(os.environ.get("WATCHDOG_USEC", "0"))
    except ValueError:
        return None
    return usec / 2_000_000 if usec > 0 else None


# --------------------------------------------------------------------------- #
# Работа с файлами: блокировка, атомарная запись
# --------------------------------------------------------------------------- #

@contextmanager
def data_lock(timeout: float = 10.0) -> Iterator[None]:
    """Межпроцессная блокировка на время read-modify-write."""
    fd = None
    locked = False
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(DATA_LOCK_FILE), os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    log("Data lock timeout, continuing without lock")
                    break
                time.sleep(0.05)
    except OSError as exc:
        log(f"Cannot open data lock: {exc}")
    try:
        yield
    finally:
        if fd is not None:
            if locked:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            os.close(fd)


_MISSING = object()


def load_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError as exc:
        log(f"Corrupted JSON in {path}: {exc}")
        quarantine(path)
        return default
    except (OSError, UnicodeDecodeError) as exc:
        log(f"Cannot read {path}: {exc}")
        return default


def quarantine(path: Path) -> None:
    """Повреждённый файл не затираем молча - переименовываем для разбора."""
    if path == PROTECTION_CONFIG_FILE:
        return
    target = path.with_name(f"{path.name}.corrupt-{int(time.time())}")
    try:
        path.replace(target)
        log(f"Moved corrupted file to {target}")
    except OSError:
        pass


def save_json(path: Path, data: Any) -> bool:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            fd = None
            json.dump(data, file, indent=2, ensure_ascii=False)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        try:
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
        return True
    except (OSError, TypeError, ValueError) as exc:
        log(f"Cannot save {path}: {exc}")
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            temporary.unlink()
        except OSError:
            pass
        return False


# --------------------------------------------------------------------------- #
# Утилиты
# --------------------------------------------------------------------------- #

_UNSAFE_TEXT = re.compile(
    "[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]"
)


def clean_text(value: Any, limit: int) -> str:
    """Убирает управляющие/bidi-символы из строк, контролируемых атакующим."""
    return _UNSAFE_TEXT.sub("?", str(value))[:limit]


def utc_iso(timestamp: Optional[float] = None) -> str:
    if timestamp is None:
        timestamp = time.time()
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
    return default


def normalize_ip(value: Any) -> Optional[str]:
    try:
        text = str(value).strip().split("%", 1)[0]
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def is_blockable(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (address.is_loopback or address.is_unspecified or address.is_multicast)


def run_command(command: List[str], timeout: float = COMMAND_TIMEOUT):
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log(f"Command error ({command[0]}): {exc}")
        return None


# --------------------------------------------------------------------------- #
# Конфигурация
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Config:
    enabled: bool = True
    attempts: int = 5
    duration: int = 600
    permanent: bool = False
    window: int = 3600
    mode: str = "ip"
    whitelist: Tuple[str, ...] = ()
    networks: Tuple[Any, ...] = ()


def _clamp_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(int(value), high))
    except (TypeError, ValueError):
        return default


def parse_config(raw: Any) -> Config:
    data = dict(DEFAULT_CONFIG)
    if isinstance(raw, dict):
        data.update(raw)

    clean: List[str] = []
    networks: List[Any] = []
    entries = data.get("whitelist", [])

    if isinstance(entries, list):
        for entry in entries:
            try:
                network = ipaddress.ip_network(str(entry).strip(), strict=False)
            except ValueError:
                log(f"Ignoring invalid whitelist entry: {clean_text(entry, 80)}")
                continue
            normalized = str(network)
            if normalized not in clean:
                clean.append(normalized)
                networks.append(network)

    return Config(
        enabled=as_bool(data.get("enabled"), True),
        attempts=_clamp_int(data.get("attempts"), DEFAULT_CONFIG["attempts"], 1, 100),
        duration=_clamp_int(
            data.get("duration"), DEFAULT_CONFIG["duration"], 60, 30 * 24 * 60 * 60
        ),
        permanent=as_bool(data.get("permanent"), False),
        window=_clamp_int(data.get("window"), DEFAULT_CONFIG["window"], 60, 86400),
        mode="ip",
        whitelist=tuple(clean),
        networks=tuple(networks),
    )


class ConfigManager:
    """Перечитывает конфиг при изменении файла. Битый файл не сбрасывает настройки."""

    def __init__(self) -> None:
        self._config = parse_config(None)
        self._signature: Optional[Tuple[int, int]] = None
        self._last_check = 0.0
        self._loaded_once = False

    def get(self, force: bool = False) -> Config:
        now = time.monotonic()
        if not force and now - self._last_check < CONFIG_CHECK_INTERVAL:
            return self._config
        self._last_check = now

        try:
            stat = PROTECTION_CONFIG_FILE.stat()
            signature: Optional[Tuple[int, int]] = (stat.st_mtime_ns, stat.st_size)
        except FileNotFoundError:
            signature = None
        except OSError as exc:
            log(f"Cannot stat config: {exc}")
            return self._config

        if self._loaded_once and signature == self._signature and not force:
            return self._config

        if signature is None:
            self._config = parse_config(None)
        else:
            raw = load_json(PROTECTION_CONFIG_FILE, _MISSING)
            if raw is _MISSING or not isinstance(raw, dict):
                log("Config unreadable, keeping previous settings")
                return self._config
            self._config = parse_config(raw)

        self._signature = signature
        self._loaded_once = True
        return self._config


# --------------------------------------------------------------------------- #
# Разбор строк журнала (чистые функции, без побочных эффектов)
# --------------------------------------------------------------------------- #
# ВАЖНО: имя пользователя в логе контролируется атакующим. Поэтому:
#   * шаблоны привязаны к началу И КОНЦУ строки;
#   * имя - жадная группа, а IP/порт берутся из хвоста строки, который
#     добавляет сам sshd. Подделать хвост нельзя.
# Иначе можно (а) заставить сервер заблокировать чужой IP,
# (б) подделать "Accepted ..." и сбросить свой счётчик попыток.

_SYSLOG_PREFIX = re.compile(
    r"^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)"
    r"\s+\S+\s+sshd(?:-session)?\[\d+\]:\s+"
)

_IP = r"([0-9A-Fa-f:.]+(?:%\w+)?)"
_TAIL = r"(?:\s+ssh\d)?(?:\s+\[preauth\])?\s*$"

_FAILED_RE = re.compile(
    rf"^Failed (password|publickey|keyboard-interactive/pam) for "
    rf"(?:invalid user )?(.+) from {_IP} port (\d+){_TAIL}"
)
_INVALID_RE = re.compile(
    rf"^Invalid user (.*) from {_IP}(?: port (\d+))?(?:\s+\[preauth\])?\s*$"
)
_ACCEPTED_RE = re.compile(
    rf"^Accepted (password|publickey|keyboard-interactive/pam) for "
    rf"(.+) from {_IP} port (\d+)(?:\s+ssh\d)?(?::\s.*)?$"
)

_FAILED_TYPES = {
    "password": "failed_password",
    "publickey": "failed_publickey",
    "keyboard-interactive/pam": "failed_password",
}
_SUCCESS_METHODS = {
    "password": "password",
    "publickey": "publickey",
    "keyboard-interactive/pam": "keyboard-interactive",
}


class Parsed(NamedTuple):
    kind: str                 # "success" | "failure"
    event_type: str
    username: str
    ip: str
    port: Optional[int]
    method: str


def parse_line(line: str) -> Optional[Parsed]:
    line = line.strip()
    if not line:
        return None

    line = _SYSLOG_PREFIX.sub("", line, count=1)

    match = _ACCEPTED_RE.match(line)
    if match:
        ip = normalize_ip(match.group(3))
        if ip:
            return Parsed(
                "success", "success", clean_text(match.group(2), 64), ip,
                int(match.group(4)), _SUCCESS_METHODS[match.group(1)],
            )
        return None

    match = _INVALID_RE.match(line)
    if match:
        ip = normalize_ip(match.group(2))
        if ip:
            port = int(match.group(3)) if match.group(3) else None
            return Parsed(
                "failure", "invalid_user", clean_text(match.group(1), 64) or "unknown",
                ip, port, "",
            )
        return None

    match = _FAILED_RE.match(line)
    if match:
        ip = normalize_ip(match.group(3))
        if ip:
            return Parsed(
                "failure", _FAILED_TYPES[match.group(1)],
                clean_text(match.group(2), 64) or "unknown", ip,
                int(match.group(4)), "",
            )
    return None


# --------------------------------------------------------------------------- #
# UFW
# --------------------------------------------------------------------------- #

_UFW_ADDED_RE = re.compile(
    r"^ufw\s+(?:insert\s+\d+\s+)?(?:deny|reject)\s+from\s+(\S+)(?:\s+to\s+any)?\s*$",
    re.IGNORECASE,
)


class Ufw:
    def __init__(self) -> None:
        self.available = shutil.which("ufw") is not None

    def check(self) -> None:
        if not self.available:
            log("[ERROR] ufw not found: blocking is impossible")
            return
        result = run_command(["ufw", "status"])
        if result and result.returncode == 0:
            first = (result.stdout.splitlines() or [""])[0].lower()
            if "inactive" in first:
                log("[WARNING] ufw is INACTIVE: blocks will be recorded but not enforced")

    def denied(self) -> Optional[Set[str]]:
        """Множество IP с правилом deny/reject. None - если узнать не удалось."""
        if not self.available:
            return None

        result = run_command(["ufw", "show", "added"])
        if result and result.returncode == 0:
            found: Set[str] = set()
            for line in result.stdout.splitlines():
                match = _UFW_ADDED_RE.match(line.strip())
                if match:
                    address = normalize_ip(match.group(1))
                    if address:
                        found.add(address)
            return found

        result = run_command(["ufw", "status"])
        if not result or result.returncode != 0:
            return None

        found = set()
        for line in result.stdout.splitlines():
            tokens = line.split("#", 1)[0].split()
            if len(tokens) < 3 or tokens[0] != "Anywhere":
                continue
            if any(token.upper() in {"DENY", "REJECT"} for token in tokens[1:3]):
                address = normalize_ip(tokens[-1])
                if address:
                    found.add(address)
        return found

    def is_blocked(self, ip: str) -> bool:
        denied = self.denied()
        return denied is not None and ip in denied

    def block(self, ip: str) -> bool:
        if not self.available:
            log(f"[BLOCK ERROR] {ip}: ufw not available")
            return False
        if not normalize_ip(ip):
            log(f"Refusing to block invalid IP: {ip}")
            return False
        if self.is_blocked(ip):
            return True

        error = "command failed"
        for attempt in range(2):
            result = run_command(["ufw", "insert", "1", "deny", "from", ip])
            if result is not None and result.returncode != 0:
                output = f"{result.stdout}\n{result.stderr}".lower()
                if "invalid position" in output:
                    # В ufw нет ни одного правила - вставка в позицию 1 невозможна
                    result = run_command(["ufw", "deny", "from", ip])
            if result and result.returncode == 0:
                log(f"[BLOCK] {ip}")
                return True
            error = result.stderr.strip() if result else "command failed"
            if attempt == 0:
                time.sleep(1.0)

        log(f"[BLOCK ERROR] {ip}: {error}")
        return False

    def unblock(self, ip: str) -> bool:
        if not self.available or not normalize_ip(ip):
            return False

        result = run_command(["ufw", "delete", "deny", "from", ip])
        if result and result.returncode == 0:
            log(f"[UNBLOCK] {ip}")
            return True

        output = f"{result.stdout}\n{result.stderr}".lower() if result else ""
        if any(message in output for message in (
            "could not delete",
            "not found",
            "no rules found",
            "could not find",
        )):
            return True

        error = result.stderr.strip() if result else "command failed"
        log(f"[UNBLOCK ERROR] {ip}: {error}")
        return False


# --------------------------------------------------------------------------- #
# Файлы данных, общие с ботом
# --------------------------------------------------------------------------- #

def load_events() -> List[Any]:
    data = load_json(EVENTS_FILE, [])
    return data if isinstance(data, list) else []


def load_blocks() -> Dict[str, Any]:
    data = load_json(BLOCKS_FILE, {})
    return data if isinstance(data, dict) else {}


def save_blocks(blocks: Dict[str, Any]) -> bool:
    return save_json(BLOCKS_FILE, blocks)


def load_stats() -> Dict[str, Any]:
    data = load_json(STATS_FILE, {})
    return data if isinstance(data, dict) else {}


def block_expiry(block: Any) -> Optional[int]:
    """None - блокировка постоянная или срок не определён."""
    if not isinstance(block, dict) or block.get("permanent", False):
        return None
    try:
        return int(block.get("expires_at"))
    except (TypeError, ValueError):
        return None


def block_is_active(block: Any, now: float) -> bool:
    if not isinstance(block, dict):
        return False
    if block.get("permanent", False):
        return True
    expires_at = block_expiry(block)
    return expires_at is None or expires_at > now


class Recorder:
    """Буферизует события и статистику; пишет на диск не чаще FLUSH_INTERVAL."""

    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []
        self.stats: Dict[str, int] = {}
        self._last_flush = time.monotonic()

    def event(self, event_type: str, ip: str, username: str = "unknown",
              auth_method: str = "", raw: str = "") -> None:
        now = int(time.time())
        self.events.append({
            "time": now,
            "time_iso": utc_iso(now),
            "type": event_type,
            "username": clean_text(username, 64),
            "ip": ip,
            "auth_method": auth_method,
            "raw": clean_text(raw, 1000),
        })
        if len(self.events) > PENDING_LIMIT:
            del self.events[:-PENDING_LIMIT]

    def stat(self, name: str, amount: int = 1) -> None:
        self.stats[name] = self.stats.get(name, 0) + amount

    def flush(self, force: bool = False) -> None:
        if not self.events and not self.stats:
            return
        now = time.monotonic()
        if not force and now - self._last_flush < FLUSH_INTERVAL:
            return
        self._last_flush = now

        with data_lock():
            if self.events:
                events = load_events()
                events.extend(self.events)
                if save_json(EVENTS_FILE, events[-MAX_EVENTS:]):
                    self.events.clear()

            if self.stats:
                stats = load_stats()
                for name, amount in self.stats.items():
                    try:
                        stats[name] = int(stats.get(name, 0)) + amount
                    except (TypeError, ValueError):
                        stats[name] = amount
                if save_json(STATS_FILE, stats):
                    self.stats.clear()


# --------------------------------------------------------------------------- #
# Учёт неудачных попыток
# --------------------------------------------------------------------------- #

class AttemptTracker:
    """Скользящее окно неудач по IP, с ограничением памяти."""

    def __init__(self) -> None:
        self._data: "OrderedDict[str, Deque[float]]" = OrderedDict()

    def add(self, ip: str, window: int) -> int:
        now = time.monotonic()
        stamps = self._data.get(ip)
        if stamps is None:
            stamps = deque()
            self._data[ip] = stamps
        else:
            self._data.move_to_end(ip)

        stamps.append(now)
        cutoff = now - window
        while stamps and stamps[0] < cutoff:
            stamps.popleft()

        while len(self._data) > MAX_TRACKED_IPS:
            self._data.popitem(last=False)

        return len(stamps)

    def reset(self, ip: str) -> bool:
        return self._data.pop(ip, None) is not None

    def cleanup(self, window: int) -> None:
        cutoff = time.monotonic() - window
        for ip in [ip for ip, stamps in self._data.items()
                   if not stamps or stamps[-1] < cutoff]:
            del self._data[ip]


# --------------------------------------------------------------------------- #
# Источник логов
# --------------------------------------------------------------------------- #

def build_source_command(since: Optional[float]) -> Optional[List[str]]:
    if shutil.which("journalctl"):
        command = ["journalctl", "-f", "-o", "cat", "-u", "ssh", "-u", "sshd"]
        if since is None:
            command += ["-n", "0"]
        else:
            stamp = datetime.fromtimestamp(int(since), tz=timezone.utc)
            command += ["--since", stamp.strftime("%Y-%m-%d %H:%M:%S UTC")]
        return command

    for candidate in AUTH_LOG_CANDIDATES:
        if os.path.exists(candidate):
            return ["tail", "-n", "0", "-F", candidate]
    return None


class LogSource:
    def __init__(self, command: List[str]) -> None:
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,   # PIPE без чтения может привести к зависанию
            bufsize=0,
        )
        if self.process.stdout is None:
            raise RuntimeError("Could not open log output")
        self.fd = self.process.stdout.fileno()
        self._buffer = bytearray()

    def read_lines(self) -> Optional[List[str]]:
        """None - поток закрыт."""
        chunk = os.read(self.fd, 65536)
        if not chunk:
            return None
        self._buffer.extend(chunk)

        lines: List[str] = []
        while True:
            index = self._buffer.find(b"\n")
            if index < 0:
                break
            raw = bytes(self._buffer[:index])
            del self._buffer[:index + 1]
            lines.append(raw.decode("utf-8", "replace"))

        if len(self._buffer) > MAX_LINE_BYTES:
            self._buffer.clear()
        return lines

    def close(self) -> None:
        process = self.process
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
        if process.stdout:
            try:
                process.stdout.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# Основная логика
# --------------------------------------------------------------------------- #

class Guard:
    def __init__(self) -> None:
        self.configs = ConfigManager()
        self.ufw = Ufw()
        self.recorder = Recorder()
        self.tracker = AttemptTracker()
        self.running = True
        self._reload_requested = False

        self._conn_credit: "OrderedDict[Tuple[str, int], float]" = OrderedDict()
        self._local_ips: Set[str] = set()
        self._local_ips_at = 0.0

        self._last_cleanup = 0.0
        self._last_reconcile = 0.0
        self._last_watchdog = 0.0
        self._watchdog = watchdog_interval()

    # ---- безопасность ---------------------------------------------------- #

    def local_ips(self) -> Set[str]:
        now = time.monotonic()
        if now - self._local_ips_at < 60 and self._local_ips:
            return self._local_ips

        addresses = {"127.0.0.1", "::1"}
        result = run_command(["hostname", "-I"], timeout=5)
        if result and result.returncode == 0:
            for value in result.stdout.split():
                address = normalize_ip(value)
                if address:
                    addresses.add(address)

        self._local_ips = addresses
        self._local_ips_at = now
        return addresses

    @staticmethod
    def is_whitelisted(ip: str, config: Config) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in network for network in config.networks
                   if network.version == address.version)

    # ---- блокировки ------------------------------------------------------ #

    def create_block(self, ip: str, failed_attempts: int, config: Config) -> None:
        now = int(time.time())
        expires_at = None if config.permanent else now + config.duration

        with data_lock():
            blocks = load_blocks()
            blocks[ip] = {
                "ip": ip,
                "blocked_at": now,
                "blocked_at_iso": utc_iso(now),
                "failed_attempts": failed_attempts,
                "permanent": config.permanent,
                "duration": config.duration,
                "expires_at": expires_at,
                "expires_at_iso": utc_iso(expires_at) if expires_at else None,
                "reason": "SSH brute-force protection",
            }
            save_blocks(blocks)

    def block_ip(self, ip: str, failed_attempts: int, config: Config) -> bool:
        address = normalize_ip(ip)

        if not address:
            log(f"[SAFETY] Invalid IP ignored: {clean_text(ip, 64)}")
            return False
        if not is_blockable(address):
            log(f"[SAFETY] Refusing to block special address {address}")
            return False
        if self.is_whitelisted(address, config):
            log(f"[WHITELIST] Skipping {address}")
            return False
        if address in self.local_ips():
            log(f"[SAFETY] Skipping local/server IP {address}")
            return False
        if not self.ufw.block(address):
            return False

        self.create_block(address, failed_attempts, config)
        self.recorder.stat("blocked")

        if config.permanent:
            log(f"{address} blocked permanently after {failed_attempts} failed attempts")
        else:
            log(f"{address} blocked for {config.duration} seconds")
        return True

    def expire_blocks(self) -> None:
        blocks = load_blocks()
        if not blocks:
            return

        now = int(time.time())
        expired: List[str] = []
        invalid: List[str] = []

        for ip, block in blocks.items():
            if not isinstance(block, dict):
                invalid.append(ip)
                continue
            if block.get("permanent", False):
                continue
            expires_at = block_expiry(block)
            if expires_at is not None and expires_at <= now:
                expired.append(ip)

        removed: List[str] = []
        for ip in expired:
            if self.ufw.unblock(ip):
                removed.append(ip)
                self.recorder.stat("unblocked")
                log(f"[EXPIRED] Temporary block expired for {ip}")

        if removed or invalid:
            with data_lock():
                current = load_blocks()   # перечитываем: бот мог изменить файл
                for ip in removed + invalid:
                    current.pop(ip, None)
                save_blocks(current)

    def reconcile_blocks(self) -> None:
        """Восстанавливает правила ufw для активных записей blocked_ips.json."""
        blocks = load_blocks()
        if not blocks:
            return

        denied = self.ufw.denied()
        if denied is None:
            return

        now = time.time()
        for ip, block in blocks.items():
            address = normalize_ip(ip)
            if not address or not block_is_active(block, now):
                continue
            if address not in denied:
                log(f"[RESTORE] Missing firewall rule for {address}")
                self.ufw.block(address)

    # ---- обработка событий ---------------------------------------------- #

    def _credit_connection(self, ip: str, port: int) -> None:
        key = (ip, port)
        self._conn_credit[key] = time.monotonic()
        self._conn_credit.move_to_end(key)
        while len(self._conn_credit) > MAX_TRACKED_CONNS:
            self._conn_credit.popitem(last=False)

    def _consume_credit(self, ip: str, port: int) -> bool:
        stamp = self._conn_credit.pop((ip, port), None)
        return stamp is not None and time.monotonic() - stamp <= CONN_CREDIT_TTL

    def handle_failed_login(self, parsed: Parsed, raw: str) -> None:
        address = parsed.ip
        username = parsed.username or "unknown"

        # sshd пишет одну неудачную попытку двумя строками:
        # "Invalid user X from IP port N" и "Failed password for invalid user X ...".
        # Считаем попытку один раз.
        if parsed.port is not None:
            if parsed.event_type == "invalid_user":
                self._credit_connection(address, parsed.port)
            elif self._consume_credit(address, parsed.port):
                return

        config = self.configs.get()

        self.recorder.event(parsed.event_type, address, username, "", raw)
        self.recorder.stat("failed")

        if not config.enabled:
            return

        if self.is_whitelisted(address, config):
            log(f"[WHITELIST] Failed SSH from {address}")
            return

        attempts = self.tracker.add(address, config.window)
        threshold = config.attempts

        log(f"[SSH FAILED] IP={address} user={username} attempt={attempts}/{threshold}")

        if attempts < threshold:
            return

        existing = load_blocks().get(address)
        if block_is_active(existing, time.time()):
            # Запись есть, а попытки идут - убедимся, что правило ufw на месте.
            self.ufw.block(address)
            self.tracker.reset(address)
            return

        if self.block_ip(address, attempts, config):
            self.tracker.reset(address)

    def handle_success_login(self, parsed: Parsed, raw: str) -> None:
        address = parsed.ip

        self.recorder.event("success", address, parsed.username, parsed.method, raw)
        self.recorder.stat("success")

        if self.tracker.reset(address):
            log(f"[SSH SUCCESS] Counter reset for {address}")
        else:
            log(f"[SSH SUCCESS] {address}")

    def process_line(self, line: str) -> None:
        parsed = parse_line(line)
        if parsed is None:
            return
        raw = clean_text(line.strip(), 1000)
        if parsed.kind == "success":
            self.handle_success_login(parsed, raw)
        else:
            self.handle_failed_login(parsed, raw)

    # ---- обслуживание ---------------------------------------------------- #

    def cleanup_events(self) -> None:
        events = load_events()
        if not events:
            return

        cutoff = int(time.time() - EVENT_RETENTION_DAYS * 86400)
        cleaned = []
        for event in events:
            if not isinstance(event, dict):
                continue
            try:
                timestamp = int(event.get("time", 0))
            except (TypeError, ValueError):
                continue
            if timestamp >= cutoff:
                cleaned.append(event)

        cleaned = cleaned[-MAX_EVENTS:]
        if len(cleaned) != len(events):
            with data_lock():
                # Перечитываем, чтобы не потерять события, записанные между вызовами
                latest = load_events()
                extra = latest[len(events):] if len(latest) > len(events) else []
                save_json(EVENTS_FILE, (cleaned + extra)[-MAX_EVENTS:])

    def cleanup_conn_credit(self) -> None:
        cutoff = time.monotonic() - CONN_CREDIT_TTL
        while self._conn_credit:
            key, stamp = next(iter(self._conn_credit.items()))
            if stamp >= cutoff:
                break
            del self._conn_credit[key]

    def tick(self) -> None:
        now = time.monotonic()

        if self._reload_requested:
            self._reload_requested = False
            self.configs.get(force=True)
            log("Configuration reloaded (SIGHUP)")

        self.recorder.flush()

        if now - self._last_cleanup >= CLEANUP_INTERVAL:
            self._last_cleanup = now
            config = self.configs.get()
            self.expire_blocks()
            self.cleanup_events()
            self.tracker.cleanup(config.window)
            self.cleanup_conn_credit()

        if now - self._last_reconcile >= RECONCILE_INTERVAL:
            self._last_reconcile = now
            self.reconcile_blocks()

        if self._watchdog and now - self._last_watchdog >= self._watchdog:
            self._last_watchdog = now
            sd_notify("WATCHDOG=1")

    # ---- главный цикл ---------------------------------------------------- #

    def stop(self, *_: Any) -> None:
        self.running = False

    def request_reload(self, *_: Any) -> None:
        self._reload_requested = True

    def run(self) -> None:
        backoff = 3.0
        last_seen: Optional[float] = None

        while self.running:
            command = build_source_command(last_seen)
            if command is None:
                log("No SSH log source found (journalctl or auth.log). Retrying in 30 seconds...")
                self._sleep(30)
                continue

            log("Starting SSH journal monitor...")
            started = time.monotonic()
            source: Optional[LogSource] = None

            try:
                source = LogSource(command)
                while self.running:
                    ready, _, _ = select.select([source.fd], [], [], SELECT_TIMEOUT)

                    if ready:
                        lines = source.read_lines()
                        if lines is None:
                            break
                        last_seen = time.time()
                        for line in lines:
                            try:
                                self.process_line(line)
                            except Exception as exc:  # noqa: BLE001 - демон не должен падать
                                log(f"Line processing error: {type(exc).__name__}: {exc}")

                    try:
                        self.tick()
                    except Exception as exc:  # noqa: BLE001
                        log(f"Maintenance error: {type(exc).__name__}: {exc}")

            except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
                log(f"Journal error: {exc}")
            finally:
                if source:
                    source.close()
                self.recorder.flush(force=True)

            if not self.running:
                break

            backoff = 3.0 if time.monotonic() - started > 60 else min(backoff * 2, 30.0)
            log(f"SSH journal stopped. Restarting in {int(backoff)} seconds...")
            self._sleep(backoff)

    def _sleep(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while self.running and time.monotonic() < end:
            time.sleep(min(0.5, max(0.0, end - time.monotonic())))
            self.tick()

    def startup(self) -> None:
        config = self.configs.get(force=True)

        log("========================================")
        log("ServerGuard Brute Force Guard")
        log("========================================")
        log(f"Protection: {'ON' if config.enabled else 'OFF'}")
        log(f"Block after: {config.attempts} failed attempts")

        if config.permanent:
            log("Block type: PERMANENT")
        else:
            log(f"Block type: TEMPORARY ({config.duration} seconds)")

        log(f"Whitelist entries: {len(config.whitelist)}")

        self.ufw.check()
        self.expire_blocks()
        self.reconcile_blocks()
        self._last_cleanup = time.monotonic()
        self._last_reconcile = time.monotonic()


# --------------------------------------------------------------------------- #
# Самопроверка и запуск
# --------------------------------------------------------------------------- #

def selftest() -> int:
    cases = [
        # (строка, ожидание: None | (kind, type, user, ip, port))
        ("Failed password for invalid user admin from 203.0.113.5 port 5000 ssh2",
         ("failure", "failed_password", "admin", "203.0.113.5", 5000)),
        ("Failed password for root from 2001:db8::1 port 22 ssh2",
         ("failure", "failed_password", "root", "2001:db8::1", 22)),
        ("Failed publickey for deploy from 203.0.113.6 port 41 ssh2",
         ("failure", "failed_publickey", "deploy", "203.0.113.6", 41)),
        ("Invalid user test from 192.0.2.9 port 4444",
         ("failure", "invalid_user", "test", "192.0.2.9", 4444)),
        ("Accepted publickey for root from 198.51.100.7 port 4022 ssh2: RSA SHA256:abc",
         ("success", "success", "root", "198.51.100.7", 4022)),
        ("Accepted password for bob from 198.51.100.8 port 1 ssh2",
         ("success", "success", "bob", "198.51.100.8", 1)),
        ("Oct 23 10:00:00 host sshd[123]: Failed password for root from ::ffff:1.2.3.4 port 1 ssh2",
         ("failure", "failed_password", "root", "1.2.3.4", 1)),
        # Инъекции через имя пользователя: реальный IP - последний в строке
        ("Failed password for invalid user x from 8.8.8.8 port 1 ssh2 from 203.0.113.5 port 5000 ssh2",
         ("failure", "failed_password", "x from 8.8.8.8 port 1 ssh2", "203.0.113.5", 5000)),
        ("Failed password for invalid user Accepted password for root from 8.8.8.8 port 1 ssh2 "
         "from 203.0.113.5 port 5 ssh2",
         ("failure", "failed_password",
          "Accepted password for root from 8.8.8.8 port 1 ssh2", "203.0.113.5", 5)),
        ("Invalid user a from 8.8.8.8 from 203.0.113.9 port 7",
         ("failure", "invalid_user", "a from 8.8.8.8", "203.0.113.9", 7)),
        # Не должно срабатывать
        ("pam_unix(sshd:auth): authentication failure; rhost=1.2.3.4  user=root", None),
        ("Failed password for root from not-an-ip port 22 ssh2", None),
        ("Connection closed by 1.2.3.4 port 22 [preauth]", None),
        ("", None),
    ]

    failed = 0
    for line, expected in cases:
        parsed = parse_line(line)
        actual = None if parsed is None else (
            parsed.kind, parsed.event_type, parsed.username, parsed.ip, parsed.port
        )
        if actual != expected:
            failed += 1
            print(f"FAIL: {line!r}\n  expected {expected}\n  got      {actual}")

    # Конфиг
    config = parse_config({"attempts": "abc", "duration": 5, "whitelist": ["10.0.0.0/8", "bad", "1.2.3.4"]})
    assert config.attempts == 5 and config.duration == 60, config
    assert config.whitelist == ("10.0.0.0/8", "1.2.3.4/32"), config.whitelist
    assert Guard.is_whitelisted("10.1.2.3", config) and not Guard.is_whitelisted("11.0.0.1", config)

    print("selftest:", "OK" if not failed else f"{failed} FAILED")
    return 1 if failed else 0


def acquire_instance_lock() -> Optional[int]:
    for path in (INSTANCE_LOCK_FILE, DATA_LOCK_FILE.with_name(".instance.lock")):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
        except OSError:
            continue
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except OSError:
            os.close(fd)
            return None
    return -1  # блокировку создать негде - работаем без неё


def trust_ip(value: str) -> int:
    """--trust <ip>: добавляет IP в whitelist конфига и снимает его блокировку."""
    address = normalize_ip(value)
    if not address:
        print(f"Invalid IP: {clean_text(value, 64)}")
        return 2

    with data_lock():
        raw = load_json(PROTECTION_CONFIG_FILE, _MISSING)
        if raw is _MISSING:
            if PROTECTION_CONFIG_FILE.exists():
                print("Config is unreadable, not modifying it")
                return 1
            raw = {k: v for k, v in DEFAULT_CONFIG.items() if k != "window"}
        if not isinstance(raw, dict):
            print("Config has unexpected format, not modifying it")
            return 1

        whitelist = raw.get("whitelist", [])
        if not isinstance(whitelist, list):
            whitelist = []

        target = ipaddress.ip_address(address)
        for entry in whitelist:
            try:
                network = ipaddress.ip_network(str(entry).strip(), strict=False)
            except ValueError:
                continue
            if network.version == target.version and target in network:
                print(f"{address} is already trusted")
                return 0

        whitelist.append(address)
        raw["whitelist"] = whitelist
        if not save_json(PROTECTION_CONFIG_FILE, raw):
            return 1

    print(f"{address} added to whitelist")

    if address in load_blocks() and Ufw().unblock(address):
        with data_lock():
            current = load_blocks()
            current.pop(address, None)
            save_blocks(current)
        print(f"Existing block for {address} removed")
    return 0


def cleanup_blocks() -> int:
    """--cleanup: снимает все блокировки ServerGuard (используется при удалении модуля)."""
    blocks = load_blocks()
    if not blocks:
        print("No ServerGuard blocks to remove")
        return 0

    ufw = Ufw()
    removed: List[str] = []
    failed: List[str] = []

    for ip in list(blocks):
        address = normalize_ip(ip)
        if address and ufw.unblock(address):
            removed.append(ip)
        else:
            failed.append(ip)

    if removed:
        with data_lock():
            current = load_blocks()
            for ip in removed:
                current.pop(ip, None)
            save_blocks(current)

    print(f"Removed {len(removed)} block(s), failed {len(failed)}")
    return 1 if failed else 0


def main() -> int:
    args = sys.argv[1:]

    if args == ["--selftest"]:
        return selftest()
    if len(args) == 2 and args[0] == "--trust":
        return trust_ip(args[1])
    if args == ["--cleanup"]:
        return cleanup_blocks()
    if args:
        print("Usage: brute_force_guard.py [--selftest | --trust <ip> | --cleanup]")
        return 2

    os.umask(0o077)

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        log("[WARNING] Not running as root: ufw commands will probably fail")

    lock_fd = acquire_instance_lock()
    if lock_fd is None:
        log("Another ServerGuard instance is already running. Exiting.")
        return 1

    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)

    guard = Guard()
    signal.signal(signal.SIGTERM, guard.stop)
    signal.signal(signal.SIGINT, guard.stop)
    signal.signal(signal.SIGHUP, guard.request_reload)

    guard.startup()
    sd_notify("READY=1")

    try:
        guard.run()
    finally:
        sd_notify("STOPPING=1")
        guard.recorder.flush(force=True)
        log("Stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

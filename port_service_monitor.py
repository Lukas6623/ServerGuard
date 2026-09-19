import asyncio
import hashlib
import json
import os
import re
import shlex
import subprocess
import time

from pathlib import Path
from typing import Any, Dict, List, Optional


# ============================================================
# SERVERGUARD
# PORT & SERVICE MONITOR
# ============================================================

VERSION = "1.0.0"


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path("/opt/serverguard")

DATA_DIR = BASE_DIR / "data"

BASELINE_FILE = DATA_DIR / "ports_baseline.json"

EVENTS_FILE = DATA_DIR / "port_service_events.json"


# ============================================================
# LIMITS
# ============================================================

MAX_EVENTS = 500

COMMAND_TIMEOUT = 15


# ============================================================
# DIRECTORY
# ============================================================

def ensure_directories() -> None:
    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


# ============================================================
# JSON
# ============================================================

def load_json(
    path: Path,
    default: Any
) -> Any:

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
    path: Path,
    data: Any
) -> bool:

    try:

        ensure_directories()

        temporary = path.with_suffix(
            path.suffix + ".tmp"
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

            file.flush()

            os.fsync(
                file.fileno()
            )

        os.replace(
            temporary,
            path
        )

        return True

    except Exception:

        return False


# ============================================================
# COMMAND
# ============================================================

def run_command(
    command: List[str],
    timeout: int = COMMAND_TIMEOUT
) -> str:

    try:

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False
        )

        if result.returncode != 0:

            return ""

        return result.stdout.strip()

    except Exception:

        return ""


# ============================================================
# PROCESS INFO
# ============================================================

def parse_process_info(
    text: str
) -> Dict[str, str]:

    result = {
        "process": "",
        "pid": "",
        "user": ""
    }

    if not text:
        return result

    match = re.search(
        r'\(\("([^"]+)"',
        text
    )

    if match:

        result["process"] = match.group(1)

    match = re.search(
        r"pid=(\d+)",
        text
    )

    if match:

        result["pid"] = match.group(1)

    match = re.search(
        r'uid=(\d+)',
        text
    )

    if match:

        uid = match.group(1)

        result["user"] = get_username_from_uid(
            uid
        )

    return result


def get_username_from_uid(
    uid: str
) -> str:

    try:

        result = subprocess.run(
            [
                "getent",
                "passwd",
                uid
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return ""

        line = result.stdout.strip()

        if not line:
            return ""

        return line.split(
            ":",
            1
        )[0]

    except Exception:

        return ""


# ============================================================
# ADDRESS PARSER
# ============================================================

def split_address(
    address: str
) -> tuple[str, int]:

    address = address.strip()

    if not address:
        return "", 0

    # IPv6:
    #
    # [::]:22
    # [::1]:80
    #
    if address.startswith("["):

        closing = address.rfind("]")

        if closing != -1:

            host = address[
                1:
                closing
            ]

            port_text = address[
                closing + 1:
            ]

            if port_text.startswith(":"):

                port_text = port_text[1:]

            try:

                return (
                    host,
                    int(port_text)
                )

            except ValueError:

                return (
                    host,
                    0
                )

    # Normal:
    #
    # 0.0.0.0:22
    # 127.0.0.1:80
    #
    if ":" in address:

        host, port = address.rsplit(
            ":",
            1
        )

        try:

            return (
                host,
                int(port)
            )

        except ValueError:

            return (
                host,
                0
            )

    return (
        address,
        0
    )


# ============================================================
# NORMALIZE ADDRESS
# ============================================================

def normalize_address(
    address: str
) -> str:

    address = address.strip()

    if not address:
        return ""

    if address == "*:*":
        return address

    return address


# ============================================================
# PARSE SS
# ============================================================

def parse_ss_line(
    line: str
) -> Optional[Dict[str, Any]]:

    line = line.strip()

    if not line:
        return None

    if line.startswith(
        "Netid"
    ):
        return None

    parts = line.split()

    if len(parts) < 5:
        return None

    protocol = parts[0]

    state = parts[1]

    local_address = parts[4]

    peer_address = ""

    if len(parts) >= 6:

        peer_address = parts[5]

    process_text = ""

    users_index = line.find(
        'users:('
    )

    if users_index != -1:

        process_text = line[
            users_index:
        ]

    process = parse_process_info(
        process_text
    )

    host, port = split_address(
        local_address
    )

    return {
        "protocol": protocol.lower(),
        "state": state.upper(),
        "address": normalize_address(
            local_address
        ),
        "host": host,
        "port": port,
        "peer": peer_address,
        "process": process["process"],
        "pid": process["pid"],
        "user": process["user"]
    }


# ============================================================
# LISTENING PORTS
# ============================================================

def get_listening_ports() -> List[Dict[str, Any]]:

    output = run_command(
        [
            "ss",
            "-H",
            "-O",
            "-lntup"
        ]
    )

    if not output:

        # Fallback if a particular ss build
        # does not accept all options together.

        output = run_command(
            [
                "ss",
                "-H",
                "-lntup"
            ]
        )

    if not output:
        return []

    ports = []

    for line in output.splitlines():

        item = parse_ss_line(
            line
        )

        if item is None:
            continue

        if item["port"] <= 0:
            continue

        ports.append(
            item
        )

    ports.sort(
        key=lambda item: (
            item["protocol"],
            item["port"],
            item["address"]
        )
    )

    return ports


# ============================================================
# PORT KEY
# ============================================================

def port_key(
    item: Dict[str, Any]
) -> str:

    return "|".join(
        [
            str(item.get("protocol", "")),
            str(item.get("address", "")),
            str(item.get("port", 0))
        ]
    )


# ============================================================
# SECURITY KEY
# ============================================================

def security_key(
    item: Dict[str, Any]
) -> Dict[str, Any]:

    return {
        "protocol": item.get(
            "protocol",
            ""
        ),
        "address": item.get(
            "address",
            ""
        ),
        "host": item.get(
            "host",
            ""
        ),
        "port": int(
            item.get(
                "port",
                0
            )
        ),
        "process": item.get(
            "process",
            ""
        ),
        "user": item.get(
            "user",
            ""
        )
    }


# ============================================================
# SERVICES
# ============================================================

def get_running_services() -> List[str]:

    output = run_command(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
            "--no-legend"
        ]
    )

    if not output:
        return []

    services = []

    for line in output.splitlines():

        parts = line.split()

        if not parts:
            continue

        service = parts[0]

        if service.endswith(
            ".service"
        ):

            services.append(
                service
            )

    return sorted(
        set(services)
    )


# ============================================================
# FAILED SERVICES
# ============================================================

def get_failed_services() -> List[str]:

    output = run_command(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=failed",
            "--no-pager",
            "--no-legend"
        ]
    )

    if not output:
        return []

    services = []

    for line in output.splitlines():

        parts = line.split()

        if not parts:
            continue

        service = parts[0]

        if service.endswith(
            ".service"
        ):

            services.append(
                service
            )

    return sorted(
        set(services)
    )


# ============================================================
# SERVICE STATUS
# ============================================================

def get_service_status(
    service: str
) -> Dict[str, str]:

    if not service:
        return {}

    if not re.fullmatch(
        r"[A-Za-z0-9_.@:-]+",
        service
    ):
        return {}

    output = run_command(
        [
            "systemctl",
            "show",
            service,
            "--no-pager",
            "--property=Id,ActiveState,SubState,MainPID,User,Description"
        ]
    )

    if not output:
        return {}

    result = {}

    for line in output.splitlines():

        if "=" not in line:
            continue

        key, value = line.split(
            "=",
            1
        )

        result[key] = value

    return result


# ============================================================
# BASELINE
# ============================================================

def build_snapshot() -> Dict[str, Any]:

    ports = get_listening_ports()

    services = get_running_services()

    failed_services = get_failed_services()

    normalized_ports = []

    for item in ports:

        normalized_ports.append(
            security_key(
                item
            )
        )

    normalized_ports.sort(
        key=lambda item: (
            item["protocol"],
            item["address"],
            item["port"],
            item["process"],
            item["user"]
        )
    )

    services = sorted(
        set(services)
    )

    failed_services = sorted(
        set(failed_services)
    )

    return {
        "version": VERSION,
        "created_at": int(
            time.time()
        ),
        "ports": normalized_ports,
        "services": services,
        "failed_services": failed_services
    }


def create_baseline() -> Dict[str, Any]:

    snapshot = build_snapshot()

    save_json(
        BASELINE_FILE,
        snapshot
    )

    return snapshot


def load_baseline() -> Optional[Dict[str, Any]]:

    data = load_json(
        BASELINE_FILE,
        None
    )

    if not isinstance(
        data,
        dict
    ):
        return None

    return data


# ============================================================
# EVENTS
# ============================================================

def load_events() -> List[Dict[str, Any]]:

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
    event_type: str,
    details: Dict[str, Any]
) -> None:

    events = load_events()

    events.append(
        {
            "timestamp": int(
                time.time()
            ),
            "type": event_type,
            "details": details
        }
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
# SNAPSHOT HASH
# ============================================================

def snapshot_hash(
    snapshot: Dict[str, Any]
) -> str:

    raw = json.dumps(
        snapshot,
        sort_keys=True,
        ensure_ascii=False
    )

    return hashlib.sha256(
        raw.encode(
            "utf-8"
        )
    ).hexdigest()


# ============================================================
# COMPARE PORTS
# ============================================================

def compare_ports(
    baseline: List[Dict[str, Any]],
    current: List[Dict[str, Any]]
) -> Dict[str, List[Dict[str, Any]]]:

    baseline_map = {}

    for item in baseline:

        key = (
            item.get("protocol", ""),
            item.get("address", ""),
            int(
                item.get(
                    "port",
                    0
                )
            )
        )

        baseline_map[key] = item

    current_map = {}

    for item in current:

        key = (
            item.get("protocol", ""),
            item.get("address", ""),
            int(
                item.get(
                    "port",
                    0
                )
            )
        )

        current_map[key] = item

    added = []

    removed = []

    changed = []

    for key, item in current_map.items():

        if key not in baseline_map:

            added.append(
                item
            )

            continue

        old = baseline_map[key]

        old_process = old.get(
            "process",
            ""
        )

        new_process = item.get(
            "process",
            ""
        )

        old_user = old.get(
            "user",
            ""
        )

        new_user = item.get(
            "user",
            ""
        )

        if (
            old_process != new_process
            or old_user != new_user
        ):

            changed.append(
                {
                    "old": old,
                    "new": item
                }
            )

    for key, item in baseline_map.items():

        if key not in current_map:

            removed.append(
                item
            )

    return {
        "added": added,
        "removed": removed,
        "changed": changed
    }


# ============================================================
# COMPARE SERVICES
# ============================================================

def compare_services(
    baseline: List[str],
    current: List[str]
) -> Dict[str, List[str]]:

    baseline_set = set(
        baseline
    )

    current_set = set(
        current
    )

    return {
        "added": sorted(
            current_set -
            baseline_set
        ),
        "removed": sorted(
            baseline_set -
            current_set
        )
    }


# ============================================================
# CHECK BASELINE
# ============================================================

def check_baseline() -> Dict[str, Any]:

    baseline = load_baseline()

    if baseline is None:

        return {
            "status": "NO_BASELINE",
            "ports": {
                "added": [],
                "removed": [],
                "changed": []
            },
            "services": {
                "added": [],
                "removed": []
            }
        }

    current = build_snapshot()

    port_changes = compare_ports(
        baseline.get(
            "ports",
            []
        ),
        current.get(
            "ports",
            []
        )
    )

    service_changes = compare_services(
        baseline.get(
            "services",
            []
        ),
        current.get(
            "services",
            []
        )
    )

    failed_services = current.get(
        "failed_services",
        []
    )

    changed = (
        bool(
            port_changes["added"]
        )
        or bool(
            port_changes["removed"]
        )
        or bool(
            port_changes["changed"]
        )
        or bool(
            service_changes["added"]
        )
        or bool(
            service_changes["removed"]
        )
        or bool(
            failed_services
        )
    )

    result = {
        "status": (
            "CHANGED"
            if changed
            else "OK"
        ),
        "ports": port_changes,
        "services": service_changes,
        "failed_services": failed_services,
        "current": current
    }

    if port_changes["added"]:

        for item in port_changes["added"]:

            save_event(
                "PORT_ADDED",
                item
            )

    if port_changes["removed"]:

        for item in port_changes["removed"]:

            save_event(
                "PORT_REMOVED",
                item
            )

    if port_changes["changed"]:

        for item in port_changes["changed"]:

            save_event(
                "PORT_PROCESS_CHANGED",
                item
            )

    if service_changes["added"]:

        for service in service_changes["added"]:

            save_event(
                "SERVICE_ADDED",
                {
                    "service": service
                }
            )

    if service_changes["removed"]:

        for service in service_changes["removed"]:

            save_event(
                "SERVICE_REMOVED",
                {
                    "service": service
                }
            )

    return result


# ============================================================
# FORMAT PORT
# ============================================================

def format_port(
    item: Dict[str, Any]
) -> str:

    protocol = str(
        item.get(
            "protocol",
            ""
        )
    ).upper()

    address = item.get(
        "address",
        ""
    )

    port = item.get(
        "port",
        0
    )

    process = item.get(
        "process",
        ""
    )

    pid = item.get(
        "pid",
        ""
    )

    user = item.get(
        "user",
        ""
    )

    result = (
        f"{protocol} "
        f"{address} "
        f"port={port}"
    )

    if process:

        result += (
            f" | process={process}"
        )

    if pid:

        result += (
            f" | pid={pid}"
        )

    if user:

        result += (
            f" | user={user}"
        )

    return result


# ============================================================
# REPORT
# ============================================================

def get_report() -> str:

    ports = get_listening_ports()

    services = get_running_services()

    failed = get_failed_services()

    lines = []

    lines.append(
        "🛡 <b>Port & Service Monitor</b>"
    )

    lines.append("")

    lines.append(
        f"🔌 Listening ports: "
        f"<b>{len(ports)}</b>"
    )

    lines.append(
        f"⚙️ Running services: "
        f"<b>{len(services)}</b>"
    )

    lines.append(
        f"❌ Failed services: "
        f"<b>{len(failed)}</b>"
    )

    lines.append("")

    lines.append(
        "<b>LISTENING PORTS</b>"
    )

    if not ports:

        lines.append(
            "Нет открытых listening-портов."
        )

    else:

        for item in ports:

            lines.append(
                "• "
                + escape_html(
                    format_port(
                        item
                    )
                )
            )

    lines.append("")

    lines.append(
        "<b>RUNNING SERVICES</b>"
    )

    if not services:

        lines.append(
            "Нет запущенных systemd-сервисов."
        )

    else:

        for service in services:

            lines.append(
                "• "
                + escape_html(
                    service
                )
            )

    if failed:

        lines.append("")

        lines.append(
            "<b>FAILED SERVICES</b>"
        )

        for service in failed:

            lines.append(
                "❌ "
                + escape_html(
                    service
                )
            )

    return "\n".join(
        lines
    )


# ============================================================
# BASELINE REPORT
# ============================================================

def get_baseline_report() -> str:

    result = check_baseline()

    if result["status"] == "NO_BASELINE":

        return (
            "🛡 <b>Port & Service Monitor</b>\n\n"
            "⚠️ Baseline ещё не создан.\n\n"
            "Сначала выполни:\n"
            "<code>create_baseline()</code>"
        )

    lines = []

    if result["status"] == "OK":

        lines.append(
            "🟢 <b>Port baseline OK</b>"
        )

        lines.append(
            "Изменений не обнаружено."
        )

        return "\n".join(
            lines
        )

    lines.append(
        "🔴 <b>Обнаружены изменения!</b>"
    )

    lines.append("")

    added = result[
        "ports"
    ]["added"]

    removed = result[
        "ports"
    ]["removed"]

    changed = result[
        "ports"
    ]["changed"]

    if added:

        lines.append(
            "🔴 <b>Новые порты:</b>"
        )

        for item in added:

            lines.append(
                "• "
                + escape_html(
                    format_port(
                        item
                    )
                )
            )

        lines.append("")

    if removed:

        lines.append(
            "🟡 <b>Закрытые порты:</b>"
        )

        for item in removed:

            lines.append(
                "• "
                + escape_html(
                    format_port(
                        item
                    )
                )
            )

        lines.append("")

    if changed:

        lines.append(
            "🟠 <b>Изменился процесс порта:</b>"
        )

        for change in changed:

            old = change["old"]

            new = change["new"]

            lines.append(
                "• "
                + escape_html(
                    format_port(
                        old
                    )
                )
                + "\n"
                + "  → "
                + escape_html(
                    format_port(
                        new
                    )
                )
            )

        lines.append("")

    service_changes = result[
        "services"
    ]

    if service_changes["added"]:

        lines.append(
            "🔴 <b>Новые сервисы:</b>"
        )

        for service in service_changes["added"]:

            lines.append(
                "• "
                + escape_html(
                    service
                )
            )

        lines.append("")

    if service_changes["removed"]:

        lines.append(
            "🟡 <b>Исчезнувшие сервисы:</b>"
        )

        for service in service_changes["removed"]:

            lines.append(
                "• "
                + escape_html(
                    service
                )
            )

        lines.append("")

    failed = result[
        "failed_services"
    ]

    if failed:

        lines.append(
            "❌ <b>Failed services:</b>"
        )

        for service in failed:

            lines.append(
                "• "
                + escape_html(
                    service
                )
            )

    return "\n".join(
        lines
    )


# ============================================================
# HTML ESCAPE
# ============================================================

def escape_html(
    value: Any
) -> str:

    text = str(
        value
    )

    return (
        text
        .replace(
            "&",
            "&amp;"
        )
        .replace(
            "<",
            "&lt;"
        )
        .replace(
            ">",
            "&gt;"
        )
    )


# ============================================================
# LIVE MONITOR
# ============================================================

class PortServiceLiveMonitor:

    def __init__(
        self,
        interval: int = 30
    ):

        self.interval = max(
            5,
            int(interval)
        )

        self.running = False

        self.last_snapshot = None

    def start(
        self,
        callback=None
    ) -> None:

        self.running = True

        self.last_snapshot = build_snapshot()

        while self.running:

            time.sleep(
                self.interval
            )

            if not self.running:
                break

            current = build_snapshot()

            changes = compare_snapshots(
                self.last_snapshot,
                current
            )

            if has_changes(
                changes
            ):

                save_event(
                    "LIVE_CHANGE",
                    changes
                )

                if callback:

                    try:

                        callback(
                            changes
                        )

                    except Exception:

                        pass

            self.last_snapshot = current

    def stop(self) -> None:

        self.running = False


# ============================================================
# SNAPSHOT COMPARISON
# ============================================================

def compare_snapshots(
    old: Dict[str, Any],
    new: Dict[str, Any]
) -> Dict[str, Any]:

    return {
        "ports": compare_ports(
            old.get(
                "ports",
                []
            ),
            new.get(
                "ports",
                []
            )
        ),
        "services": compare_services(
            old.get(
                "services",
                []
            ),
            new.get(
                "services",
                []
            )
        ),
        "failed_services": new.get(
            "failed_services",
            []
        )
    }


def has_changes(
    changes: Dict[str, Any]
) -> bool:

    ports = changes.get(
        "ports",
        {}
    )

    services = changes.get(
        "services",
        {}
    )

    return bool(
        ports.get("added")
        or ports.get("removed")
        or ports.get("changed")
        or services.get("added")
        or services.get("removed")
        or changes.get(
            "failed_services"
        )
    )


# ============================================================
# ASYNC LIVE MONITOR
# ============================================================

async def monitor_once() -> Dict[str, Any]:

    return await asyncio.to_thread(
        check_baseline
    )


async def live_check_loop(
    callback,
    interval: int = 30,
    stop_event: Optional[asyncio.Event] = None
) -> None:

    interval = max(
        5,
        int(interval)
    )

    previous = await asyncio.to_thread(
        build_snapshot
    )

    while True:

        if stop_event is not None:

            if stop_event.is_set():
                break

        try:

            await asyncio.sleep(
                interval
            )

        except asyncio.CancelledError:

            break

        if stop_event is not None:

            if stop_event.is_set():
                break

        current = await asyncio.to_thread(
            build_snapshot
        )

        changes = compare_snapshots(
            previous,
            current
        )

        if has_changes(
            changes
        ):

            save_event(
                "LIVE_CHANGE",
                changes
            )

            if callback:

                try:

                    result = callback(
                        changes
                    )

                    if asyncio.iscoroutine(
                        result
                    ):

                        await result

                except Exception:

                    pass

        previous = current


# ============================================================
# PORT DETAILS
# ============================================================

def get_port_details(
    port: int
) -> List[Dict[str, Any]]:

    try:

        port = int(
            port
        )

    except Exception:

        return []

    if port < 1 or port > 65535:

        return []

    result = []

    for item in get_listening_ports():

        if item.get(
            "port"
        ) == port:

            result.append(
                item
            )

    return result


def get_port_details_report(
    port: int
) -> str:

    items = get_port_details(
        port
    )

    if not items:

        return (
            f"🔎 Порт "
            f"<b>{port}</b> "
            f"не найден среди listening-портов."
        )

    lines = []

    lines.append(
        f"🔎 <b>Port {port}</b>"
    )

    lines.append("")

    for item in items:

        lines.append(
            escape_html(
                format_port(
                    item
                )
            )
        )

    return "\n".join(
        lines
    )


# ============================================================
# EVENTS REPORT
# ============================================================

def get_events_report(
    limit: int = 20
) -> str:

    events = load_events()

    events = events[
        -max(
            1,
            int(limit)
        ):
    ]

    if not events:

        return (
            "📋 <b>Port Monitor Events</b>\n\n"
            "Событий пока нет."
        )

    lines = []

    lines.append(
        "📋 <b>Port Monitor Events</b>"
    )

    lines.append("")

    for event in reversed(
        events
    ):

        timestamp = event.get(
            "timestamp",
            0
        )

        event_type = event.get(
            "type",
            "UNKNOWN"
        )

        try:

            date_text = time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(
                    timestamp
                )
            )

        except Exception:

            date_text = "unknown"

        lines.append(
            f"• <code>{date_text}</code> "
            f"<b>{escape_html(event_type)}</b>"
        )

    return "\n".join(
        lines
    )


# ============================================================
# SERVICE REPORT
# ============================================================

def get_service_report(
    service: str
) -> str:

    status = get_service_status(
        service
    )

    if not status:

        return (
            "❌ Сервис не найден "
            "или systemctl не смог получить его состояние."
        )

    lines = []

    lines.append(
        "⚙️ <b>Service details</b>"
    )

    lines.append("")

    lines.append(
        f"Name: "
        f"<code>{escape_html(status.get('Id', service))}</code>"
    )

    lines.append(
        f"Active: "
        f"<b>{escape_html(status.get('ActiveState', 'unknown'))}</b>"
    )

    lines.append(
        f"SubState: "
        f"<b>{escape_html(status.get('SubState', 'unknown'))}</b>"
    )

    lines.append(
        f"PID: "
        f"<code>{escape_html(status.get('MainPID', '0'))}</code>"
    )

    lines.append(
        f"User: "
        f"<code>{escape_html(status.get('User', ''))}</code>"
    )

    description = status.get(
        "Description",
        ""
    )

    if description:

        lines.append(
            f"Description: "
            f"{escape_html(description)}"
        )

    return "\n".join(
        lines
    )


# ============================================================
# CLI
# ============================================================

def cli() -> int:

    import sys

    ensure_directories()

    if len(sys.argv) < 2:

        print(
            "ServerGuard Port & Service Monitor"
        )

        print()

        print(
            "Usage:"
        )

        print(
            "  python3 port_service_monitor.py ports"
        )

        print(
            "  python3 port_service_monitor.py baseline"
        )

        print(
            "  python3 port_service_monitor.py check"
        )

        print(
            "  python3 port_service_monitor.py events"
        )

        print(
            "  python3 port_service_monitor.py port <PORT>"
        )

        print(
            "  python3 port_service_monitor.py service <NAME>"
        )

        return 0

    command = sys.argv[1].lower()

    if command == "ports":

        print(
            get_report()
        )

        return 0

    if command == "baseline":

        snapshot = create_baseline()

        print(
            "Baseline created."
        )

        print(
            f"Ports: {len(snapshot.get('ports', []))}"
        )

        print(
            f"Services: {len(snapshot.get('services', []))}"
        )

        return 0

    if command == "check":

        print(
            get_baseline_report()
        )

        return 0

    if command == "events":

        print(
            get_events_report()
        )

        return 0

    if command == "port":

        if len(sys.argv) < 3:

            print(
                "Port number required."
            )

            return 1

        print(
            get_port_details_report(
                sys.argv[2]
            )
        )

        return 0

    if command == "service":

        if len(sys.argv) < 3:

            print(
                "Service name required."
            )

            return 1

        print(
            get_service_report(
                sys.argv[2]
            )
        )

        return 0

    print(
        f"Unknown command: {command}"
    )

    return 1


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    raise SystemExit(
        cli()
    )

#!/usr/bin/env python3

import argparse
import json
import os
import re
import subprocess
import sys
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

BASE_DIR = Path(
    "/opt/serverguard"
)

DATA_DIR = (
    BASE_DIR /
    "data"
)

BASELINE_FILE = (
    DATA_DIR /
    "port_service_baseline.json"
)

EVENTS_FILE = (
    DATA_DIR /
    "port_service_events.json"
)


# ============================================================
# SETTINGS
# ============================================================

MAX_EVENTS = 500

DEFAULT_INTERVAL = 30


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

            return json.load(
                file
            )

    except Exception:

        return default


# ============================================================
# JSON SAVE
# ============================================================

def save_json(
    path: Path,
    data: Any
) -> bool:

    try:

        ensure_directories()

        temporary = path.with_suffix(
            path.suffix +
            ".tmp"
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

    except Exception as error:

        print(
            f"Save error: {error}",
            file=sys.stderr
        )

        return False


# ============================================================
# COMMAND
# ============================================================

def run_command(
    command: List[str],
    timeout: int = 15
) -> tuple[int, str]:

    try:

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False
        )

        return (
            result.returncode,
            result.stdout.strip()
        )

    except Exception:

        return (
            -1,
            ""
        )


# ============================================================
# UID
# ============================================================

def get_username(
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
# PROCESS
# ============================================================

def parse_process(
    text: str
) -> Dict[str, str]:

    result = {
        "process": "",
        "pid": "",
        "user": ""
    }


    if not text:
        return result


    process_match = re.search(
        r'\(\("([^"]+)"',
        text
    )


    if process_match:

        result[
            "process"
        ] = process_match.group(1)


    pid_match = re.search(
        r"pid=(\d+)",
        text
    )


    if pid_match:

        result[
            "pid"
        ] = pid_match.group(1)


    uid_match = re.search(
        r"uid=(\d+)",
        text
    )


    if uid_match:

        result[
            "user"
        ] = get_username(
            uid_match.group(1)
        )


    return result


# ============================================================
# ADDRESS
# ============================================================

def parse_address(
    address: str
) -> tuple[str, int]:

    address = address.strip()


    if not address:

        return (
            "",
            0
        )


    # --------------------------------------------------------
    # IPv6
    # --------------------------------------------------------

    if address.startswith("["):

        closing = address.rfind(
            "]"
        )


        if closing != -1:

            host = address[
                1:
                closing
            ]

            port_text = address[
                closing + 1:
            ]


            if port_text.startswith(
                ":"
            ):

                port_text = (
                    port_text[1:]
                )


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


    # --------------------------------------------------------
    # IPv4 / wildcard
    # --------------------------------------------------------

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
# SS LINE
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


    protocol = (
        parts[0]
        .lower()
    )


    state = (
        parts[1]
        .upper()
    )


    local_address = (
        parts[4]
    )


    peer_address = ""


    if len(parts) >= 6:

        peer_address = (
            parts[5]
        )


    process_text = ""


    users_index = line.find(
        "users:("
    )


    if users_index != -1:

        process_text = line[
            users_index:
        ]


    process = parse_process(
        process_text
    )


    host, port = parse_address(
        local_address
    )


    if port <= 0:

        return None


    return {
        "protocol": protocol,
        "state": state,
        "address": local_address,
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

def get_ports() -> List[Dict[str, Any]]:

    commands = [
        [
            "ss",
            "-H",
            "-O",
            "-n",
            "-l",
            "-t",
            "-u",
            "-p"
        ],
        [
            "ss",
            "-H",
            "-n",
            "-l",
            "-t",
            "-u",
            "-p"
        ]
    ]


    output = ""


    for command in commands:

        code, result = run_command(
            command
        )


        if code == 0 and result:

            output = result

            break


    if not output:

        return []


    ports = []


    for line in output.splitlines():

        item = parse_ss_line(
            line
        )


        if item is None:
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
# PORT SECURITY KEY
# ============================================================

def port_key(
    item: Dict[str, Any]
) -> tuple:

    return (
        item.get(
            "protocol",
            ""
        ),
        item.get(
            "address",
            ""
        ),
        int(
            item.get(
                "port",
                0
            )
        )
    )


# ============================================================
# NORMAL PORT
# ============================================================

def normalized_port(
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

def get_services() -> List[str]:

    code, output = run_command(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
            "--no-legend"
        ]
    )


    if code != 0:

        return []


    result = []


    for line in output.splitlines():

        parts = line.split()


        if not parts:
            continue


        name = parts[0]


        if name.endswith(
            ".service"
        ):

            result.append(
                name
            )


    return sorted(
        set(result)
    )


# ============================================================
# FAILED SERVICES
# ============================================================

def get_failed_services() -> List[str]:

    code, output = run_command(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=failed",
            "--no-pager",
            "--no-legend"
        ]
    )


    if code != 0:

        return []


    result = []


    for line in output.splitlines():

        parts = line.split()


        if not parts:
            continue


        name = parts[0]


        if name.endswith(
            ".service"
        ):

            result.append(
                name
            )


    return sorted(
        set(result)
    )


# ============================================================
# SNAPSHOT
# ============================================================

def create_snapshot() -> Dict[str, Any]:

    ports = [
        normalized_port(
            item
        )
        for item in get_ports()
    ]


    ports.sort(
        key=lambda item: (
            item["protocol"],
            item["address"],
            item["port"],
            item["process"],
            item["user"]
        )
    )


    services = get_services()

    failed_services = (
        get_failed_services()
    )


    return {
        "version": VERSION,
        "timestamp": int(
            time.time()
        ),
        "ports": ports,
        "services": services,
        "failed_services": failed_services
    }


# ============================================================
# BASELINE
# ============================================================

def create_baseline() -> Dict[str, Any]:

    snapshot = (
        create_snapshot()
    )


    if not save_json(
        BASELINE_FILE,
        snapshot
    ):

        raise RuntimeError(
            "Cannot save baseline."
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


def add_event(
    event_type: str,
    data: Dict[str, Any]
):

    events = load_events()


    events.append(
        {
            "timestamp": int(
                time.time()
            ),
            "type": event_type,
            "data": data
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
# COMPARE PORTS
# ============================================================

def compare_ports(
    old_ports: List[Dict[str, Any]],
    new_ports: List[Dict[str, Any]]
) -> Dict[str, Any]:

    old_map = {
        port_key(item): item
        for item in old_ports
    }


    new_map = {
        port_key(item): item
        for item in new_ports
    }


    added = []

    removed = []

    changed = []


    # --------------------------------------------------------
    # NEW
    # --------------------------------------------------------

    for key, item in new_map.items():

        if key not in old_map:

            added.append(
                item
            )

            continue


        old = old_map[key]


        if (
            old.get("process", "")
            !=
            item.get("process", "")
            or
            old.get("user", "")
            !=
            item.get("user", "")
        ):

            changed.append(
                {
                    "old": old,
                    "new": item
                }
            )


    # --------------------------------------------------------
    # REMOVED
    # --------------------------------------------------------

    for key, item in old_map.items():

        if key not in new_map:

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
    old_services: List[str],
    new_services: List[str]
) -> Dict[str, List[str]]:

    old_set = set(
        old_services
    )

    new_set = set(
        new_services
    )


    return {
        "added": sorted(
            new_set - old_set
        ),
        "removed": sorted(
            old_set - new_set
        )
    }


# ============================================================
# CHECK
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
            },
            "failed_services": []
        }


    current = create_snapshot()


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


    failed_services = (
        current.get(
            "failed_services",
            []
        )
    )


    changed = (
        bool(
            port_changes["added"]
        )
        or
        bool(
            port_changes["removed"]
        )
        or
        bool(
            port_changes["changed"]
        )
        or
        bool(
            service_changes["added"]
        )
        or
        bool(
            service_changes["removed"]
        )
        or
        bool(
            failed_services
        )
    )


    result = {
        "status":
            "CHANGED"
            if changed
            else "OK",

        "ports":
            port_changes,

        "services":
            service_changes,

        "failed_services":
            failed_services,

        "current":
            current
    }


    # --------------------------------------------------------
    # EVENTS
    # --------------------------------------------------------

    for item in port_changes[
        "added"
    ]:

        add_event(
            "PORT_ADDED",
            item
        )


    for item in port_changes[
        "removed"
    ]:

        add_event(
            "PORT_REMOVED",
            item
        )


    for item in port_changes[
        "changed"
    ]:

        add_event(
            "PORT_PROCESS_CHANGED",
            item
        )


    for service in service_changes[
        "added"
    ]:

        add_event(
            "SERVICE_ADDED",
            {
                "service": service
            }
        )


    for service in service_changes[
        "removed"
    ]:

        add_event(
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
# SCAN OUTPUT
# ============================================================

def command_scan():

    ports = get_ports()


    print()
    print(
        "============================================"
    )
    print(
        "       SERVERGUARD PORT MONITOR"
    )
    print(
        "============================================"
    )
    print()


    print(
        f"Listening ports: {len(ports)}"
    )


    print()


    if not ports:

        print(
            "No listening ports found."
        )

        return 0


    for item in ports:

        print(
            " - " +
            format_port(
                item
            )
        )


    print()

    return 0


# ============================================================
# SERVICES OUTPUT
# ============================================================

def command_services():

    services = get_services()

    failed = get_failed_services()


    print()
    print(
        "============================================"
    )
    print(
        "       SERVERGUARD SERVICES"
    )
    print(
        "============================================"
    )
    print()


    print(
        f"Running services: {len(services)}"
    )


    print()


    for service in services:

        print(
            " - " +
            service
        )


    print()


    print(
        f"Failed services: {len(failed)}"
    )


    for service in failed:

        print(
            " - FAILED: " +
            service
        )


    print()

    return 0


# ============================================================
# PORT DETAILS
# ============================================================

def command_port(
    port: int
):

    ports = get_ports()


    found = [
        item
        for item in ports
        if item.get(
            "port"
        ) == port
    ]


    print()
    print(
        f"Port details: {port}"
    )
    print()


    if not found:

        print(
            "Port is not listening."
        )

        return 0


    for item in found:

        print(
            format_port(
                item
            )
        )


    return 0


# ============================================================
# BASELINE OUTPUT
# ============================================================

def command_baseline():

    snapshot = (
        create_baseline()
    )


    print()
    print(
        "============================================"
    )
    print(
        "       SECURITY BASELINE CREATED"
    )
    print(
        "============================================"
    )
    print()


    print(
        f"Ports: "
        f"{len(snapshot['ports'])}"
    )


    print(
        f"Services: "
        f"{len(snapshot['services'])}"
    )


    print(
        f"Failed services: "
        f"{len(snapshot['failed_services'])}"
    )


    print()


    print(
        "Baseline:"
    )


    print(
        BASELINE_FILE
    )


    return 0


# ============================================================
# CHECK OUTPUT
# ============================================================

def command_check():

    result = check_baseline()


    print()
    print(
        "============================================"
    )
    print(
        "       SECURITY BASELINE CHECK"
    )
    print(
        "============================================"
    )
    print()


    if result[
        "status"
    ] == "NO_BASELINE":

        print(
            "Baseline does not exist."
        )

        print(
            "Create it first with:"
        )

        print(
            "baseline"
        )

        return 1


    if result[
        "status"
    ] == "OK":

        print(
            "STATUS: OK"
        )

        print(
            "No changes detected."
        )

        return 0


    print(
        "STATUS: CHANGED"
    )


    print()


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

        print(
            "NEW PORTS:"
        )


        for item in added:

            print(
                " + " +
                format_port(
                    item
                )
            )


        print()


    if removed:

        print(
            "REMOVED PORTS:"
        )


        for item in removed:

            print(
                " - " +
                format_port(
                    item
                )
            )


        print()


    if changed:

        print(
            "CHANGED PROCESSES:"
        )


        for item in changed:

            print(
                " OLD: " +
                format_port(
                    item["old"]
                )
            )


            print(
                " NEW: " +
                format_port(
                    item["new"]
                )
            )


        print()


    service_changes = (
        result[
            "services"
        ]
    )


    if service_changes[
        "added"
    ]:

        print(
            "NEW SERVICES:"
        )


        for service in service_changes[
            "added"
        ]:

            print(
                " + " +
                service
            )


        print()


    if service_changes[
        "removed"
    ]:

        print(
            "REMOVED SERVICES:"
        )


        for service in service_changes[
            "removed"
        ]:

            print(
                " - " +
                service
            )


        print()


    failed = result[
        "failed_services"
    ]


    if failed:

        print(
            "FAILED SERVICES:"
        )


        for service in failed:

            print(
                " ! " +
                service
            )


    return 2


# ============================================================
# EVENTS
# ============================================================

def command_events():

    events = load_events()


    print()
    print(
        "============================================"
    )
    print(
        "       PORT MONITOR SECURITY EVENTS"
    )
    print(
        "============================================"
    )
    print()


    if not events:

        print(
            "No events."
        )

        return 0


    for event in reversed(
        events[-50:]
    ):

        timestamp = event.get(
            "timestamp",
            0
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


        print(
            f"[{date_text}] "
            f"{event.get('type', 'UNKNOWN')}"
        )


        data = event.get(
            "data",
            {}
        )


        if isinstance(
            data,
            dict
        ):

            print(
                json.dumps(
                    data,
                    ensure_ascii=False
                )
            )


        print()


    return 0


# ============================================================
# LIVE MONITOR
# ============================================================

def command_monitor(
    interval: int
):

    print()
    print(
        "============================================"
    )
    print(
        "       SERVERGUARD LIVE MONITOR"
    )
    print(
        "============================================"
    )
    print()


    print(
        f"Interval: {interval} seconds"
    )


    print(
        "Press Ctrl+C to stop."
    )


    print()


    previous = create_snapshot()


    while True:

        try:

            time.sleep(
                interval
            )

        except KeyboardInterrupt:

            print()
            print(
                "Live monitor stopped."
            )

            return 0


        current = (
            create_snapshot()
        )


        changes = compare_ports(
            previous[
                "ports"
            ],
            current[
                "ports"
            ]
        )


        service_changes = (
            compare_services(
                previous[
                    "services"
                ],
                current[
                    "services"
                ]
            )
        )


        changed = (
            bool(
                changes["added"]
            )
            or
            bool(
                changes["removed"]
            )
            or
            bool(
                changes["changed"]
            )
            or
            bool(
                service_changes["added"]
            )
            or
            bool(
                service_changes["removed"]
            )
        )


        if changed:

            print()
            print(
                "!!! SECURITY CHANGE DETECTED !!!"
            )


            for item in changes[
                "added"
            ]:

                print(
                    "NEW PORT: " +
                    format_port(
                        item
                    )
                )


                add_event(
                    "LIVE_PORT_ADDED",
                    item
                )


            for item in changes[
                "removed"
            ]:

                print(
                    "REMOVED PORT: " +
                    format_port(
                        item
                    )
                )


                add_event(
                    "LIVE_PORT_REMOVED",
                    item
                )


            for item in changes[
                "changed"
            ]:

                print(
                    "PROCESS CHANGED:"
                )


                print(
                    " OLD: " +
                    format_port(
                        item["old"]
                    )
                )


                print(
                    " NEW: " +
                    format_port(
                        item["new"]
                    )
                )


                add_event(
                    "LIVE_PROCESS_CHANGED",
                    item
                )


            for service in service_changes[
                "added"
            ]:

                print(
                    "NEW SERVICE: " +
                    service
                )


                add_event(
                    "LIVE_SERVICE_ADDED",
                    {
                        "service": service
                    }
                )


            for service in service_changes[
                "removed"
            ]:

                print(
                    "REMOVED SERVICE: " +
                    service
                )


                add_event(
                    "LIVE_SERVICE_REMOVED",
                    {
                        "service": service
                    }
                )


            print()


        previous = current


# ============================================================
# VERSION
# ============================================================

def command_version():

    print(
        f"ServerGuard Port & Service Monitor "
        f"v{VERSION}"
    )

    return 0


# ============================================================
# MAIN
# ============================================================

def main():

    ensure_directories()


    parser = argparse.ArgumentParser(
        description=
        "ServerGuard Port & Service Monitor"
    )


    parser.add_argument(
        "command",
        nargs="?",
        default="scan"
    )


    parser.add_argument(
        "value",
        nargs="?"
    )


    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL
    )


    args = parser.parse_args()


    command = (
        args.command.lower()
    )


    # --------------------------------------------------------
    # VERSION
    # --------------------------------------------------------

    if command in (
        "--version",
        "version"
    ):

        return command_version()


    # --------------------------------------------------------
    # SCAN
    # --------------------------------------------------------

    if command in (
        "scan",
        "ports"
    ):

        return command_scan()


    # --------------------------------------------------------
    # PORT
    # --------------------------------------------------------

    if command == "port":

        if args.value is None:

            print(
                "Port number required.",
                file=sys.stderr
            )

            return 1


        try:

            port = int(
                args.value
            )

        except ValueError:

            print(
                "Invalid port.",
                file=sys.stderr
            )

            return 1


        if (
            port < 1
            or
            port > 65535
        ):

            print(
                "Port must be between "
                "1 and 65535.",
                file=sys.stderr
            )

            return 1


        return command_port(
            port
        )


    # --------------------------------------------------------
    # SERVICES
    # --------------------------------------------------------

    if command in (
        "services",
        "service"
    ):

        return command_services()


    # --------------------------------------------------------
    # BASELINE
    # --------------------------------------------------------

    if command == "baseline":

        return command_baseline()


    # --------------------------------------------------------
    # CHECK
    # --------------------------------------------------------

    if command == "check":

        return command_check()


    # --------------------------------------------------------
    # EVENTS
    # --------------------------------------------------------

    if command == "events":

        return command_events()


    # --------------------------------------------------------
    # LIVE MONITOR
    # --------------------------------------------------------

    if command in (
        "monitor",
        "live"
    ):

        interval = max(
            5,
            args.interval
        )


        return command_monitor(
            interval
        )


    # --------------------------------------------------------
    # HELP
    # --------------------------------------------------------

    print(
        "ServerGuard Port & Service Monitor"
    )

    print()
    print(
        "Commands:"
    )

    print(
        "  scan"
    )

    print(
        "  port <PORT>"
    )

    print(
        "  services"
    )

    print(
        "  baseline"
    )

    print(
        "  check"
    )

    print(
        "  events"
    )

    print(
        "  monitor"
    )

    print(
        "  version"
    )


    return 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        sys.exit(
            main()
        )

    except KeyboardInterrupt:

        print()

        sys.exit(
            0
        )

    except Exception as error:

        print(
            f"ServerGuard monitor error: {error}",
            file=sys.stderr
        )

        sys.exit(
            1
        )

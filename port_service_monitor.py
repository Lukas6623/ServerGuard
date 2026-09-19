#!/usr/bin/env python3

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time

from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# SERVERGUARD PORT & SERVICE MONITOR
# ============================================================

VERSION = "2.0.0"

BASE_DIR = Path(
    "/opt/serverguard"
)

DATA_DIR = (
    BASE_DIR / "data"
)

STATE_FILE = (
    DATA_DIR / "port_monitor_state.json"
)

PORT_EVENTS_FILE = (
    DATA_DIR / "port_monitor_events.json"
)

NETWORK_EVENTS_FILE = (
    DATA_DIR / "network_monitor_events.json"
)

SERVICE_EVENTS_FILE = (
    DATA_DIR / "service_monitor_events.json"
)

BASELINE_FILE = (
    DATA_DIR / "ports_baseline.json"
)


# ============================================================
# MONITOR SETTINGS
# ============================================================

DEFAULT_INTERVAL = 15

MAX_EVENTS = 2000

MAX_NETWORK_EVENTS = 2000

MAX_SERVICE_EVENTS = 2000

MAX_CONNECTIONS_TO_STORE = 5000


# ============================================================
# GLOBAL STATE
# ============================================================

running = True


# ============================================================
# SIGNAL HANDLERS
# ============================================================

def signal_handler(
    signum,
    frame
):
    global running

    running = False

    print(
        "[MONITOR] Stopping...",
        flush=True
    )


signal.signal(
    signal.SIGTERM,
    signal_handler
)

signal.signal(
    signal.SIGINT,
    signal_handler
)


# ============================================================
# DIRECTORIES
# ============================================================

def create_directories():

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


# ============================================================
# TIME
# ============================================================

def now():

    return datetime.now(
        timezone.utc
    ).isoformat()


def local_time():

    return datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S"
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

            data = json.load(
                file
            )

        return data

    except Exception as error:

        print(
            f"[ERROR] Cannot load {path}: {error}",
            flush=True
        )

        return default


def save_json(
    path,
    data
):

    temporary = path.with_suffix(
        ".tmp"
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

            file.write(
                "\n"
            )

        os.replace(
            temporary,
            path
        )

        return True

    except Exception as error:

        print(
            f"[ERROR] Cannot save {path}: {error}",
            flush=True
        )

        try:

            if temporary.exists():

                temporary.unlink()

        except Exception:
            pass

        return False


# ============================================================
# EVENTS
# ============================================================

def append_event(
    path,
    event,
    maximum
):

    events = load_json(
        path,
        []
    )

    if not isinstance(
        events,
        list
    ):

        events = []

    events.append(
        event
    )

    if len(events) > maximum:

        events = events[
            -maximum:
        ]

    save_json(
        path,
        events
    )


# ============================================================
# COMMAND
# ============================================================

def run_command(
    command,
    timeout=10
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
            result.stdout,
            result.stderr
        )

    except Exception as error:

        return (
            -1,
            "",
            str(error)
        )


# ============================================================
# COMMAND EXISTS
# ============================================================

def command_exists(
    command
):

    result = subprocess.run(
        [
            "sh",
            "-c",
            f"command -v {command} >/dev/null 2>&1"
        ]
    )

    return result.returncode == 0


# ============================================================
# PORT INFORMATION
# ============================================================

def parse_address(
    address
):

    if not address:

        return (
            "",
            0
        )

    address = address.strip()

    # IPv6:
    # [::]:22
    if address.startswith("["):

        closing = address.rfind("]")

        if closing != -1:

            host = address[
                1:closing
            ]

            port_text = address[
                closing + 2:
            ]

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

    # IPv4:
    # 0.0.0.0:22
    if ":" in address:

        host, port_text = address.rsplit(
            ":",
            1
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

    return (
        address,
        0
    )


# ============================================================
# LISTENING PORTS
# ============================================================

def scan_listening_ports():

    ports = []

    command = [
        "ss",
        "-lntup",
        "-H"
    ]

    return_code, output, error = run_command(
        command
    )

    if return_code != 0:

        print(
            f"[ERROR] ss failed: {error.strip()}",
            flush=True
        )

        return ports

    for line in output.splitlines():

        line = line.strip()

        if not line:

            continue

        parts = line.split()

        if len(parts) < 5:

            continue

        protocol = parts[0]

        local_address = parts[4]

        host, port = parse_address(
            local_address
        )

        if port <= 0:

            continue

        process_name = ""

        pid = 0

        username = ""

        process_info = ""

        if len(parts) >= 7:

            process_info = " ".join(
                parts[6:]
            )

        if process_info:

            # users:(("sshd",pid=1234,fd=3))
            if '(" ' in process_info:
                pass

            marker = '("'

            position = process_info.find(
                marker
            )

            if position != -1:

                start = position + 2

                end = process_info.find(
                    '"',
                    start
                )

                if end != -1:

                    process_name = process_info[
                        start:end
                    ]

            pid_marker = "pid="

            pid_position = process_info.find(
                pid_marker
            )

            if pid_position != -1:

                pid_start = (
                    pid_position
                    + len(pid_marker)
                )

                pid_end = process_info.find(
                    ",",
                    pid_start
                )

                if pid_end == -1:

                    pid_end = process_info.find(
                        ")",
                        pid_start
                    )

                if pid_end != -1:

                    pid_text = process_info[
                        pid_start:pid_end
                    ]

                    try:

                        pid = int(
                            pid_text
                        )

                    except ValueError:

                        pid = 0

        if pid > 0:

            username = get_process_user(
                pid
            )

            if not process_name:

                process_name = get_process_name(
                    pid
                )

        service = ""

        if pid > 0:

            service = get_process_service(
                pid
            )

        if not service and process_name:

            service = guess_service(
                process_name
            )

        item = {
            "protocol": protocol,
            "address": host,
            "port": port,
            "process": process_name,
            "pid": pid,
            "user": username,
            "service": service
        }

        ports.append(
            item
        )

    ports.sort(
        key=lambda item: (
            item.get("port", 0),
            item.get("protocol", "")
        )
    )

    return ports


# ============================================================
# PROCESS INFORMATION
# ============================================================

def get_process_user(
    pid
):

    try:

        path = Path(
            f"/proc/{pid}/status"
        )

        if not path.exists():

            return ""

        uid = None

        with path.open(
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            for line in file:

                if line.startswith(
                    "Uid:"
                ):

                    parts = line.split()

                    if len(parts) >= 2:

                        uid = int(
                            parts[1]
                        )

                    break

        if uid is None:

            return ""

        return subprocess.check_output(
            [
                "getent",
                "passwd",
                str(uid)
            ],
            text=True,
            stderr=subprocess.DEVNULL
        ).split(
            ":",
            1
        )[0]

    except Exception:

        return ""


def get_process_name(
    pid
):

    try:

        path = Path(
            f"/proc/{pid}/comm"
        )

        if path.exists():

            return path.read_text(
                encoding="utf-8",
                errors="ignore"
            ).strip()

    except Exception:
        pass

    return ""


def get_process_service(
    pid
):

    try:

        cgroup_path = Path(
            f"/proc/{pid}/cgroup"
        )

        if not cgroup_path.exists():

            return ""

        content = cgroup_path.read_text(
            encoding="utf-8",
            errors="ignore"
        )

        for line in content.splitlines():

            if "system.slice" not in line:

                continue

            value = line.split(
                ":",
                2
            )

            if len(value) != 3:

                continue

            group = value[2]

            if group.endswith(
                ".service"
            ):

                service = group.split(
                    "/"
                )[-1]

                return service

    except Exception:
        pass

    return ""


# ============================================================
# SERVICE GUESS
# ============================================================

def guess_service(
    process_name
):

    known = {
        "sshd": "ssh",
        "nginx": "nginx",
        "apache2": "apache2",
        "mysqld": "mysql",
        "mariadbd": "mariadb",
        "postgres": "postgresql",
        "redis-server": "redis",
        "docker-proxy": "docker",
        "containerd": "containerd",
        "cupsd": "cups",
        "named": "named",
        "dnsmasq": "dnsmasq",
        "vsftpd": "vsftpd"
    }

    return known.get(
        process_name,
        ""
    )


# ============================================================
# NETWORK CONNECTIONS
# ============================================================

def scan_network_connections():

    connections = []

    return_code, output, error = run_command(
        [
            "ss",
            "-ntup",
            "-H"
        ]
    )

    if return_code != 0:

        return connections

    for line in output.splitlines():

        line = line.strip()

        if not line:

            continue

        parts = line.split()

        if len(parts) < 5:

            continue

        protocol = parts[0]

        state = parts[1]

        local_address = parts[4]

        remote_address = parts[5]

        local_host, local_port = parse_address(
            local_address
        )

        remote_host, remote_port = parse_address(
            remote_address
        )

        process_name = ""

        pid = 0

        process_info = ""

        if len(parts) >= 7:

            process_info = " ".join(
                parts[6:]
            )

        marker = '("'

        position = process_info.find(
            marker
        )

        if position != -1:

            start = position + 2

            end = process_info.find(
                '"',
                start
            )

            if end != -1:

                process_name = process_info[
                    start:end
                ]

        pid_marker = "pid="

        pid_position = process_info.find(
            pid_marker
        )

        if pid_position != -1:

            pid_start = (
                pid_position
                + len(pid_marker)
            )

            pid_end = process_info.find(
                ",",
                pid_start
            )

            if pid_end == -1:

                pid_end = process_info.find(
                    ")",
                    pid_start
                )

            if pid_end != -1:

                try:

                    pid = int(
                        process_info[
                            pid_start:pid_end
                        ]
                    )

                except ValueError:

                    pid = 0

        username = ""

        if pid > 0:

            username = get_process_user(
                pid
            )

        item = {
            "protocol": protocol,
            "state": state,
            "local_address": local_host,
            "local_port": local_port,
            "remote_address": remote_host,
            "remote_port": remote_port,
            "process": process_name,
            "pid": pid,
            "user": username
        }

        connections.append(
            item
        )

    if len(connections) > MAX_CONNECTIONS_TO_STORE:

        connections = connections[
            :MAX_CONNECTIONS_TO_STORE
        ]

    return connections


# ============================================================
# CONNECTION KEY
# ============================================================

def connection_key(
    connection
):

    return (
        connection.get("protocol", ""),
        connection.get("local_address", ""),
        connection.get("local_port", 0),
        connection.get("remote_address", ""),
        connection.get("remote_port", 0),
        connection.get("process", ""),
        connection.get("pid", 0)
    )


# ============================================================
# PORT KEY
# ============================================================

def port_key(
    port
):

    return (
        port.get("protocol", ""),
        port.get("address", ""),
        port.get("port", 0)
    )


# ============================================================
# PORT EVENT
# ============================================================

def create_port_event(
    event_type,
    port
):

    return {
        "time": now(),
        "event": event_type,
        "protocol": port.get(
            "protocol",
            ""
        ),
        "address": port.get(
            "address",
            ""
        ),
        "port": port.get(
            "port",
            0
        ),
        "process": port.get(
            "process",
            ""
        ),
        "pid": port.get(
            "pid",
            0
        ),
        "user": port.get(
            "user",
            ""
        ),
        "service": port.get(
            "service",
            ""
        )
    }


# ============================================================
# CONNECTION EVENT
# ============================================================

def create_connection_event(
    event_type,
    connection
):

    return {
        "time": now(),
        "event": event_type,
        "protocol": connection.get(
            "protocol",
            ""
        ),
        "state": connection.get(
            "state",
            ""
        ),
        "local_address": connection.get(
            "local_address",
            ""
        ),
        "local_port": connection.get(
            "local_port",
            0
        ),
        "remote_address": connection.get(
            "remote_address",
            ""
        ),
        "remote_port": connection.get(
            "remote_port",
            0
        ),
        "process": connection.get(
            "process",
            ""
        ),
        "pid": connection.get(
            "pid",
            0
        ),
        "user": connection.get(
            "user",
            ""
        )
    }


# ============================================================
# COMPARE PORTS
# ============================================================

def compare_ports(
    old_ports,
    new_ports,
    initial=False
):

    old_map = {
        port_key(item): item
        for item in old_ports
    }

    new_map = {
        port_key(item): item
        for item in new_ports
    }

    if initial:

        return

    for key, port in new_map.items():

        if key not in old_map:

            event = create_port_event(
                "new_port",
                port
            )

            append_event(
                PORT_EVENTS_FILE,
                event,
                MAX_EVENTS
            )

            print(
                format_port_event(
                    event
                ),
                flush=True
            )

    for key, port in old_map.items():

        if key not in new_map:

            event = create_port_event(
                "port_closed",
                port
            )

            append_event(
                PORT_EVENTS_FILE,
                event,
                MAX_EVENTS
            )

            print(
                format_port_event(
                    event
                ),
                flush=True
            )

    # --------------------------------------------------------
    # Process changed
    # --------------------------------------------------------

    common_keys = (
        set(old_map.keys())
        & set(new_map.keys())
    )

    for key in common_keys:

        old_port = old_map[key]

        new_port = new_map[key]

        old_process = (
            old_port.get(
                "process",
                ""
            ),
            old_port.get(
                "pid",
                0
            )
        )

        new_process = (
            new_port.get(
                "process",
                ""
            ),
            new_port.get(
                "pid",
                0
            )
        )

        if old_process != new_process:

            event = create_port_event(
                "port_process_changed",
                new_port
            )

            event["previous_process"] = old_port.get(
                "process",
                ""
            )

            event["previous_pid"] = old_port.get(
                "pid",
                0
            )

            append_event(
                PORT_EVENTS_FILE,
                event,
                MAX_EVENTS
            )

            print(
                format_port_event(
                    event
                ),
                flush=True
            )


# ============================================================
# COMPARE CONNECTIONS
# ============================================================

def compare_connections(
    old_connections,
    new_connections,
    initial=False
):

    old_map = {
        connection_key(item): item
        for item in old_connections
    }

    new_map = {
        connection_key(item): item
        for item in new_connections
    }

    if initial:

        return

    for key, connection in new_map.items():

        if key not in old_map:

            event = create_connection_event(
                "new_connection",
                connection
            )

            append_event(
                NETWORK_EVENTS_FILE,
                event,
                MAX_NETWORK_EVENTS
            )

            print(
                format_connection_event(
                    event
                ),
                flush=True
            )

    for key, connection in old_map.items():

        if key not in new_map:

            event = create_connection_event(
                "connection_closed",
                connection
            )

            append_event(
                NETWORK_EVENTS_FILE,
                event,
                MAX_NETWORK_EVENTS
            )


# ============================================================
# SERVICE STATUS
# ============================================================

def get_services():

    services = {}

    return_code, output, error = run_command(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--no-pager"
        ]
    )

    if return_code != 0:

        return services

    for line in output.splitlines():

        parts = line.split()

        if len(parts) < 4:

            continue

        unit = parts[0]

        active = parts[2]

        sub = parts[3]

        if not unit.endswith(
            ".service"
        ):

            continue

        services[unit] = {
            "active": active,
            "sub": sub
        }

    return services


# ============================================================
# COMPARE SERVICES
# ============================================================

def compare_services(
    old_services,
    new_services,
    initial=False
):

    if initial:

        return

    all_names = (
        set(old_services.keys())
        | set(new_services.keys())
    )

    for name in all_names:

        old = old_services.get(
            name
        )

        new = new_services.get(
            name
        )

        if old == new:

            continue

        if old is None and new is not None:

            event_type = "service_started"

        elif old is not None and new is None:

            event_type = "service_removed"

        else:

            event_type = "service_changed"

        event = {
            "time": now(),
            "event": event_type,
            "service": name,
            "previous": old,
            "current": new
        }

        append_event(
            SERVICE_EVENTS_FILE,
            event,
            MAX_SERVICE_EVENTS
        )

        print(
            format_service_event(
                event
            ),
            flush=True
        )


# ============================================================
# FORMAT PORT EVENT
# ============================================================

def format_port_event(
    event
):

    event_type = event.get(
        "event",
        ""
    )

    if event_type == "new_port":

        title = "NEW PORT"

    elif event_type == "port_closed":

        title = "PORT CLOSED"

    else:

        title = "PORT PROCESS CHANGED"

    return (
        f"[{title}] "
        f"{event.get('protocol', '')} "
        f"{event.get('address', '')}:"
        f"{event.get('port', 0)} "
        f"process={event.get('process', '')} "
        f"pid={event.get('pid', 0)} "
        f"user={event.get('user', '')} "
        f"service={event.get('service', '')}"
    )


# ============================================================
# FORMAT CONNECTION EVENT
# ============================================================

def format_connection_event(
    event
):

    return (
        "[NEW CONNECTION] "
        f"{event.get('protocol', '')} "
        f"{event.get('remote_address', '')}:"
        f"{event.get('remote_port', 0)} -> "
        f"{event.get('local_address', '')}:"
        f"{event.get('local_port', 0)} "
        f"state={event.get('state', '')} "
        f"process={event.get('process', '')} "
        f"pid={event.get('pid', 0)} "
        f"user={event.get('user', '')}"
    )


# ============================================================
# FORMAT SERVICE EVENT
# ============================================================

def format_service_event(
    event
):

    return (
        f"[SERVICE] "
        f"{event.get('event', '')} "
        f"{event.get('service', '')}"
    )


# ============================================================
# SAVE STATE
# ============================================================

def save_state(
    ports,
    connections,
    services
):

    state = {
        "version": VERSION,
        "updated": now(),
        "ports": ports,
        "connections": connections,
        "services": services
    }

    return save_json(
        STATE_FILE,
        state
    )


# ============================================================
# LOAD STATE
# ============================================================

def load_state():

    state = load_json(
        STATE_FILE,
        {}
    )

    if not isinstance(
        state,
        dict
    ):

        state = {}

    return state


# ============================================================
# BASELINE
# ============================================================

def create_baseline():

    create_directories()

    ports = scan_listening_ports()

    baseline = {
        "created": now(),
        "ports": ports
    }

    if save_json(
        BASELINE_FILE,
        baseline
    ):

        print(
            "Port baseline created.",
            flush=True
        )

        print(
            f"Ports: {len(ports)}",
            flush=True
        )

        return 0

    return 1


def check_baseline():

    baseline = load_json(
        BASELINE_FILE,
        {}
    )

    if not isinstance(
        baseline,
        dict
    ):

        print(
            "Baseline is not available.",
            flush=True
        )

        return 1

    old_ports = baseline.get(
        "ports",
        []
    )

    if not isinstance(
        old_ports,
        list
    ):

        old_ports = []

    current_ports = scan_listening_ports()

    old_map = {
        port_key(item): item
        for item in old_ports
    }

    current_map = {
        port_key(item): item
        for item in current_ports
    }

    added = [
        item
        for key, item in current_map.items()
        if key not in old_map
    ]

    removed = [
        item
        for key, item in old_map.items()
        if key not in current_map
    ]

    print(
        "========================================"
    )

    print(
        "        PORT BASELINE CHECK"
    )

    print(
        "========================================"
    )

    print()

    print(
        f"Baseline ports: {len(old_ports)}"
    )

    print(
        f"Current ports:  {len(current_ports)}"
    )

    print()

    if not added and not removed:

        print(
            "No port changes detected."
        )

        return 0

    if added:

        print(
            "NEW PORTS:"
        )

        for item in added:

            print(
                f"  {item.get('protocol')} "
                f"{item.get('address')}:"
                f"{item.get('port')} "
                f"{item.get('process', '')}"
            )

    if removed:

        print()

        print(
            "CLOSED PORTS:"
        )

        for item in removed:

            print(
                f"  {item.get('protocol')} "
                f"{item.get('address')}:"
                f"{item.get('port')} "
                f"{item.get('process', '')}"
            )

    return 0


# ============================================================
# SHOW PORTS
# ============================================================

def show_ports():

    ports = scan_listening_ports()

    print(
        "========================================"
    )

    print(
        "          LISTENING PORTS"
    )

    print(
        "========================================"
    )

    print()

    if not ports:

        print(
            "No listening ports found."
        )

        return 0

    for item in ports:

        print(
            f"{item.get('protocol', ''):<6} "
            f"{item.get('address', '')}:"
            f"{item.get('port', 0):<6} "
            f"process={item.get('process', '-'):<20} "
            f"pid={item.get('pid', 0):<7} "
            f"user={item.get('user', '-'):<15} "
            f"service={item.get('service', '-')}"
        )

    print()

    print(
        f"Total: {len(ports)}"
    )

    return 0


# ============================================================
# PORT DETAILS
# ============================================================

def show_port(
    port
):

    ports = scan_listening_ports()

    found = []

    for item in ports:

        if item.get(
            "port"
        ) == port:

            found.append(
                item
            )

    print(
        "========================================"
    )

    print(
        f"          PORT {port}"
    )

    print(
        "========================================"
    )

    print()

    if not found:

        print(
            "Port is not listening."
        )

        return 0

    for item in found:

        print(
            f"Protocol: {item.get('protocol')}"
        )

        print(
            f"Address:  {item.get('address')}"
        )

        print(
            f"Port:     {item.get('port')}"
        )

        print(
            f"Process:  {item.get('process') or '-'}"
        )

        print(
            f"PID:      {item.get('pid') or '-'}"
        )

        print(
            f"User:     {item.get('user') or '-'}"
        )

        print(
            f"Service:  {item.get('service') or '-'}"
        )

        print()

    return 0


# ============================================================
# SERVICES
# ============================================================

def show_services():

    services = get_services()

    print(
        "========================================"
    )

    print(
        "          RUNNING SERVICES"
    )

    print(
        "========================================"
    )

    print()

    running_services = []

    for name, status in services.items():

        if (
            status.get("active") == "active"
            and
            status.get("sub") == "running"
        ):

            running_services.append(
                name
            )

    running_services.sort()

    for service in running_services:

        print(
            f"RUNNING  {service}"
        )

    print()

    print(
        f"Running services: "
        f"{len(running_services)}"
    )

    return 0


# ============================================================
# EVENTS
# ============================================================

def show_events(
    event_type="all",
    count=50
):

    if event_type == "ports":

        files = [
            (
                "PORT EVENTS",
                PORT_EVENTS_FILE
            )
        ]

    elif event_type == "network":

        files = [
            (
                "NETWORK EVENTS",
                NETWORK_EVENTS_FILE
            )
        ]

    elif event_type == "services":

        files = [
            (
                "SERVICE EVENTS",
                SERVICE_EVENTS_FILE
            )
        ]

    else:

        files = [
            (
                "PORT EVENTS",
                PORT_EVENTS_FILE
            ),
            (
                "NETWORK EVENTS",
                NETWORK_EVENTS_FILE
            ),
            (
                "SERVICE EVENTS",
                SERVICE_EVENTS_FILE
            )
        ]

    for title, path in files:

        events = load_json(
            path,
            []
        )

        if not isinstance(
            events,
            list
        ):

            events = []

        events = events[
            -count:
        ]

        print(
            "========================================"
        )

        print(
            f"          {title}"
        )

        print(
            "========================================"
        )

        print()

        if not events:

            print(
                "No events."
            )

            print()

            continue

        for event in reversed(
            events
        ):

            print(
                json.dumps(
                    event,
                    ensure_ascii=False
                )
            )

        print()


    return 0


# ============================================================
# VERSION
# ============================================================

def show_version():

    print(
        "ServerGuard Port & Service Monitor"
    )

    print(
        f"Version: {VERSION}"
    )

    print(
        f"State: {STATE_FILE}"
    )

    print(
        f"Port events: {PORT_EVENTS_FILE}"
    )

    print(
        f"Network events: {NETWORK_EVENTS_FILE}"
    )

    print(
        f"Service events: {SERVICE_EVENTS_FILE}"
    )

    return 0


# ============================================================
# MONITOR
# ============================================================

def monitor(
    interval
):

    create_directories()

    print(
        "========================================",
        flush=True
    )

    print(
        "     SERVERGUARD BACKGROUND MONITOR",
        flush=True
    )

    print(
        "========================================",
        flush=True
    )

    print(
        f"Version: {VERSION}",
        flush=True
    )

    print(
        f"Interval: {interval} seconds",
        flush=True
    )

    print(
        "Monitoring: ON",
        flush=True
    )

    print(
        flush=True
    )

    state = load_state()

    old_ports = state.get(
        "ports",
        []
    )

    old_connections = state.get(
        "connections",
        []
    )

    old_services = state.get(
        "services",
        {}
    )

    first_run = not bool(
        state
    )

    if not isinstance(
        old_ports,
        list
    ):

        old_ports = []

    if not isinstance(
        old_connections,
        list
    ):

        old_connections = []

    if not isinstance(
        old_services,
        dict
    ):

        old_services = {}

    print(
        "Initial scan...",
        flush=True
    )

    current_ports = scan_listening_ports()

    current_connections = scan_network_connections()

    current_services = get_services()

    if first_run:

        print(
            "Initial state saved.",
            flush=True
        )

        print(
            f"Listening ports: "
            f"{len(current_ports)}",
            flush=True
        )

        print(
            f"Connections: "
            f"{len(current_connections)}",
            flush=True
        )

        print(
            f"Services: "
            f"{len(current_services)}",
            flush=True
        )

    else:

        compare_ports(
            old_ports,
            current_ports,
            False
        )

        compare_connections(
            old_connections,
            current_connections,
            False
        )

        compare_services(
            old_services,
            current_services,
            False
        )

    save_state(
        current_ports,
        current_connections,
        current_services
    )

    while running:

        for _ in range(
            interval
        ):

            if not running:

                break

            time.sleep(
                1
            )

        if not running:

            break

        try:

            current_ports = scan_listening_ports()

            current_connections = scan_network_connections()

            current_services = get_services()

            compare_ports(
                old_ports,
                current_ports,
                False
            )

            compare_connections(
                old_connections,
                current_connections,
                False
            )

            compare_services(
                old_services,
                current_services,
                False
            )

            save_state(
                current_ports,
                current_connections,
                current_services
            )

            old_ports = current_ports

            old_connections = current_connections

            old_services = current_services

        except Exception as error:

            print(
                f"[MONITOR ERROR] {error}",
                flush=True
            )

    print(
        "Monitoring stopped.",
        flush=True
    )

    return 0


# ============================================================
# HELP
# ============================================================

def show_help():

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
        "      Show listening ports."
    )

    print(
        "  port <PORT>"
    )

    print(
        "      Show information about a port."
    )

    print(
        "  services"
    )

    print(
        "      Show running systemd services."
    )

    print(
        "  baseline"
    )

    print(
        "      Create port baseline."
    )

    print(
        "  check"
    )

    print(
        "      Compare current ports with baseline."
    )

    print(
        "  events"
    )

    print(
        "      Show stored monitoring events."
    )

    print(
        "  monitor"
    )

    print(
        "      Start permanent background monitoring."
    )

    print(
        "  version"
    )

    print(
        "      Show monitor version."
    )

    print()

    print(
        "Options:"
    )

    print(
        "  --interval SECONDS"
    )

    print(
        f"      Monitor interval. Default: "
        f"{DEFAULT_INTERVAL}"
    )

    print()

    return 0


# ============================================================
# MAIN
# ============================================================

def main():

    create_directories()

    parser = argparse.ArgumentParser(
        description=(
            "ServerGuard Port & Service Monitor"
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

    if args.interval < 1:

        print(
            "Interval must be at least 1 second."
        )

        return 1

    command = (
        args.command
        .strip()
        .lower()
    )

    if not command:

        return show_help()

    if command == "scan":

        return show_ports()

    if command == "port":

        if args.value is None:

            print(
                "Usage: port_service_monitor.py "
                "port <PORT>"
            )

            return 1

        try:

            port = int(
                args.value
            )

        except ValueError:

            print(
                "Invalid port."
            )

            return 1

        if port < 1 or port > 65535:

            print(
                "Port must be between "
                "1 and 65535."
            )

            return 1

        return show_port(
            port
        )

    if command == "services":

        return show_services()

    if command == "baseline":

        return create_baseline()

    if command == "check":

        return check_baseline()

    if command == "events":

        return show_events()

    if command == "monitor":

        return monitor(
            args.interval
        )

    if command == "version":

        return show_version()

    print(
        f"Unknown command: {command}"
    )

    print()

    return show_help()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    sys.exit(
        main()
    )

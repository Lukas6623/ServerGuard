
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ipaddress
import json
import logging
import socket
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
SERVER_INFO_FILE = BASE_DIR / "data" / "server_info.json"

MODULE_NAME = "network_monitor"
MODULE_VERSION = "1.2.0"

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s: %(message)s"
)

SERVICE_PORTS = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-submission",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    2049: "NFS",
    2375: "Docker API",
    2376: "Docker API TLS",
    3000: "Development HTTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5672: "RabbitMQ",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    6443: "Kubernetes API",
    8000: "HTTP-alt",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9000: "Application service",
    9200: "Elasticsearch",
    9300: "Elasticsearch transport",
    11211: "Memcached",
    27017: "MongoDB",
}

HIGH_RISK_PORTS = {
    21, 23, 135, 139, 445, 1433, 1521, 2049,
    2375, 3306, 3389, 5432, 5900, 5984, 6379,
    6443, 9200, 9300, 11211, 27017,
}

DEVELOPMENT_PORTS = {
    3000, 5000, 5001, 8000, 8080, 8081, 9000,
}


def load_server_info() -> dict[str, Any]:
    if not SERVER_INFO_FILE.is_file():
        raise FileNotFoundError(
            f"Server profile not found: {SERVER_INFO_FILE}"
        )

    with SERVER_INFO_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(
            "The server profile must contain a JSON object."
        )

    network = data.get("network", {})

    if network is not None and not isinstance(network, dict):
        raise ValueError(
            "The 'network' field must be a JSON object."
        )

    return data


def get_network_list(
    server_info: dict[str, Any],
    key: str
) -> list[dict[str, Any]]:
    network = server_info.get("network", {})

    if not isinstance(network, dict):
        return []

    value = network.get(key, [])

    if not isinstance(value, list):
        logging.warning(
            "Ignoring invalid network.%s: expected a list.",
            key
        )
        return []

    return [
        item for item in value
        if isinstance(item, dict)
    ]


def analyze_ip(address: str) -> dict[str, Any]:
    original = str(address or "").strip()
    candidate = original

    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]

    if "/" in candidate:
        candidate = candidate.split("/", 1)[0]

    try:
        ip = ipaddress.ip_address(candidate)

        return {
            "address": str(ip),
            "version": ip.version,
            "valid": True,
            "private": ip.is_private,
            "loopback": ip.is_loopback,
            "link_local": ip.is_link_local,
            "global": ip.is_global,
            "multicast": ip.is_multicast,
            "reserved": ip.is_reserved,
            "unspecified": ip.is_unspecified,
        }

    except ValueError:
        return {
            "address": original,
            "version": None,
            "valid": False,
            "private": False,
            "loopback": False,
            "link_local": False,
            "global": False,
            "multicast": False,
            "reserved": False,
            "unspecified": False,
        }


def extract_ip(address: str) -> str:
    value = str(address or "").strip()

    if not value:
        return ""

    if value.startswith("["):
        closing = value.find("]")

        if closing != -1:
            return value[1:closing]

    try:
        ipaddress.IPv6Address(value)
        return value
    except ValueError:
        pass

    if value.count(":") == 1:
        host, separator, port = value.rpartition(":")

        if separator and port.isdigit():
            return host

    return value


def extract_port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.strip().isdigit():
        port = int(value.strip())
    else:
        return None

    if 0 <= port <= 65535:
        return port

    return None


def get_address_port(address: str) -> int | None:
    value = str(address or "").strip()

    if value.startswith("["):
        closing = value.find("]")

        if closing != -1:
            suffix = value[closing + 1:]

            if suffix.startswith(":"):
                return extract_port(suffix[1:])

        return None

    if value.count(":") != 1:
        return None

    _, _, port_text = value.rpartition(":")
    return extract_port(port_text)


def get_service_name(port: Any) -> str:
    port_number = extract_port(port)

    if port_number is None:
        return "Unknown"

    if port_number in SERVICE_PORTS:
        return SERVICE_PORTS[port_number]

    try:
        return socket.getservbyport(port_number)
    except (OSError, OverflowError):
        return "Unknown"


def is_publicly_bound(address: str) -> bool:
    value = str(address or "").strip()

    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]

    if value in ("0.0.0.0", "::", "*"):
        return True

    info = analyze_ip(value)

    if not info["valid"]:
        return False

    return bool(info["global"])


def determine_port_risk(
    port: Any,
    public_access: bool,
    service: str
) -> str:
    port_number = extract_port(port)

    if not public_access:
        return "local"

    if port_number is None:
        return "unknown"

    if port_number in HIGH_RISK_PORTS:
        return "high"

    if port_number == 22:
        return "monitor"

    if port_number in DEVELOPMENT_PORTS:
        return "review"

    if port_number in (80, 443, 8443):
        return "normal"

    return "review"


def analyze_listening_ports(
    server_info: dict[str, Any]
) -> list[dict[str, Any]]:
    ports = get_network_list(server_info, "listening_ports")
    result = []

    for item in ports:
        address = str(item.get("address") or "").strip()
        port = extract_port(item.get("port"))
        protocol = str(item.get("protocol") or "unknown").lower()

        process = item.get("process")
        pid = item.get("pid")

        if protocol not in {"tcp", "tcp6", "udp", "udp6", "unknown"}:
            protocol = "unknown"

        public_access = is_publicly_bound(address)
        service = get_service_name(port)

        risk = determine_port_risk(
            port,
            public_access,
            service
        )

        result.append({
            "protocol": protocol,
            "address": address,
            "port": port,
            "service": service,
            "process": process,
            "pid": pid,
            "public_access": public_access,
            "risk": risk,
        })

    return result


def analyze_connections(
    server_info: dict[str, Any]
) -> list[dict[str, Any]]:
    connections = get_network_list(
        server_info,
        "active_connections"
    )

    result = []

    for connection in connections:
        remote = str(connection.get("remote") or "").strip()
        local = str(connection.get("local") or "").strip()

        remote_ip = extract_ip(remote)
        remote_info = analyze_ip(remote_ip)

        if remote_info["global"]:
            connection_type = "external"
        elif remote_info["valid"]:
            connection_type = "internal"
        else:
            connection_type = "unknown"

        result.append({
            "state": connection.get("state"),
            "local": local,
            "remote": remote,
            "local_ip": extract_ip(local),
            "local_port": get_address_port(local),
            "remote_ip": remote_ip,
            "remote_port": get_address_port(remote),
            "remote_type": connection_type,
            "remote_private": remote_info["private"],
            "remote_global": remote_info["global"],
            "process": connection.get("process"),
            "pid": connection.get("pid"),
        })

    return result


def get_ssh_connections(
    connections: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    ssh_connections = []

    for connection in connections:
        local_port = connection.get("local_port")
        process = str(connection.get("process") or "").lower()

        if local_port == 22 or "sshd" in process:
            ssh_connections.append(connection)

    return ssh_connections


def get_external_connections(
    connections: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    return [
        connection
        for connection in connections
        if connection.get("remote_global", False)
    ]


def check_postgresql(
    listening_ports: list[dict[str, Any]]
) -> dict[str, Any]:
    postgres = [
        item
        for item in listening_ports
        if item.get("port") == 5432
    ]

    public = any(
        item.get("public_access", False)
        for item in postgres
    )

    return {
        "installed_or_listening": bool(postgres),
        "public": public,
        "instances": postgres,
    }


def security_analysis(
    listening_ports: list[dict[str, Any]],
    connections: list[dict[str, Any]]
) -> dict[str, Any]:
    dangerous_services = [
        {
            "port": item["port"],
            "service": item["service"],
            "address": item["address"],
            "protocol": item["protocol"],
            "process": item["process"],
            "pid": item["pid"],
            "risk": item["risk"],
        }
        for item in listening_ports
        if item["risk"] == "high"
    ]

    review_services = [
        {
            "port": item["port"],
            "service": item["service"],
            "address": item["address"],
            "process": item["process"],
            "pid": item["pid"],
            "risk": item["risk"],
        }
        for item in listening_ports
        if item["risk"] in {"review", "unknown"}
    ]

    ssh_connections = get_ssh_connections(connections)
    external_connections = get_external_connections(connections)
    postgres = check_postgresql(listening_ports)

    problems = []

    if postgres["public"]:
        problems.append(
            "PostgreSQL listens on a wildcard or globally routable address"
        )

    for service in dangerous_services:
        problems.append(
            f"Review publicly bound service: "
            f"{service['service']} on port {service['port']}"
        )

    for service in review_services:
        if service["risk"] == "review":
            problems.append(
                f"Review public service configuration: "
                f"{service['service']} on port {service['port']}"
            )

    if len(ssh_connections) > 10:
        problems.append(
            "Large number of active SSH connections"
        )

    return {
        "status": "warning" if problems else "safe",
        "dangerous_public_services": dangerous_services,
        "services_requiring_review": review_services,
        "postgresql": postgres,
        "active_ssh_connections": len(ssh_connections),
        "external_connections": len(external_connections),
        "problems": problems,
    }


def scan() -> dict[str, Any]:
    server_info = load_server_info()

    listening_ports = analyze_listening_ports(server_info)
    connections = analyze_connections(server_info)

    security = security_analysis(
        listening_ports,
        connections
    )

    server = server_info.get("server", {})

    if not isinstance(server, dict):
        server = {}

    return {
        "module": MODULE_NAME,
        "version": MODULE_VERSION,
        "status": "ok",
        "server": {
            "hostname": server.get("hostname"),
            "addresses": server.get("addresses", []),
        },
        "listening_services": listening_ports,
        "active_connections": connections,
        "security_analysis": security,
    }


def main() -> int:
    print()
    print("=" * 60)
    print("SERVERGUARD NETWORK MONITOR")
    print(f"Version {MODULE_VERSION}")
    print("=" * 60)
    print()

    try:
        result = scan()
        exit_code = 0

    except (OSError, ValueError, json.JSONDecodeError) as error:
        result = {
            "module": MODULE_NAME,
            "version": MODULE_VERSION,
            "status": "error",
            "error": str(error),
        }
        exit_code = 1

    except Exception:
        logging.exception("Unexpected network monitor failure")
        result = {
            "module": MODULE_NAME,
            "version": MODULE_VERSION,
            "status": "error",
            "error": "Unexpected internal error. Check the application log.",
        }
        exit_code = 1

    print(
        json.dumps(
            result,
            indent=4,
            ensure_ascii=False
        )
    )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

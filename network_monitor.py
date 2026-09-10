#!/usr/bin/env python3

import json
import ipaddress
from pathlib import Path


# ============================================================
# SERVERGUARD NETWORK MONITOR
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
SERVER_INFO_FILE = BASE_DIR / "data" / "server_info.json"


# ============================================================
# LOAD SERVER PROFILE
# ============================================================

def load_server_info():

    if not SERVER_INFO_FILE.exists():
        raise FileNotFoundError(
            f"Server profile not found: {SERVER_INFO_FILE}"
        )

    with open(
        SERVER_INFO_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ============================================================
# IP ANALYSIS
# ============================================================

def analyze_ip(address):

    # Remove IPv6 brackets
    address = address.strip("[]")

    # Remove CIDR
    if "/" in address:
        address = address.split("/", 1)[0]

    try:

        ip = ipaddress.ip_address(address)

        return {
            "address": address,
            "version": ip.version,
            "private": ip.is_private,
            "loopback": ip.is_loopback,
            "link_local": ip.is_link_local,
            "global": ip.is_global,
            "multicast": ip.is_multicast,
            "reserved": ip.is_reserved
        }

    except ValueError:

        return {
            "address": address,
            "version": None,
            "private": False,
            "loopback": False,
            "link_local": False,
            "global": False,
            "multicast": False,
            "reserved": False
        }


# ============================================================
# LISTENING PORT ANALYSIS
# ============================================================

def analyze_listening_ports(server_info):

    ports = server_info.get(
        "network",
        {}
    ).get(
        "listening_ports",
        []
    )

    result = []

    for item in ports:

        address = item.get(
            "address",
            ""
        )

        port = item.get(
            "port"
        )

        protocol = item.get(
            "protocol",
            ""
        )

        process = item.get(
            "process"
        )

        pid = item.get(
            "pid"
        )

        ip_info = analyze_ip(address)

        public_access = False

        if address in (
            "0.0.0.0",
            "::"
        ):
            public_access = True

        elif ip_info["global"]:
            public_access = True

        service = get_service_name(
            port
        )

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

            "risk": risk

        })

    return result


# ============================================================
# SERVICE NAME
# ============================================================

def get_service_name(port):

    services = {

        20: "FTP-data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-alt",
        8443: "HTTPS-alt"

    }

    return services.get(
        port,
        "Unknown"
    )


# ============================================================
# PORT RISK
# ============================================================

def determine_port_risk(
    port,
    public_access,
    service
):

    if not public_access:
        return "safe"

    # SSH is expected to be public,
    # but still requires monitoring.
    if port == 22:
        return "monitor"

    dangerous_ports = {

        21,      # FTP
        23,      # Telnet
        25,      # SMTP
        445,     # SMB
        3306,    # MySQL
        5432,    # PostgreSQL
        6379     # Redis

    }

    if port in dangerous_ports:
        return "high"

    if port in (
        80,
        443,
        8080,
        8443
    ):
        return "normal"

    return "unknown"


# ============================================================
# ACTIVE CONNECTION ANALYSIS
# ============================================================

def analyze_connections(server_info):

    connections = server_info.get(
        "network",
        {}
    ).get(
        "active_connections",
        []
    )

    result = []

    for connection in connections:

        remote = connection.get(
            "remote",
            ""
        )

        local = connection.get(
            "local",
            ""
        )

        process = connection.get(
            "process"
        )

        pid = connection.get(
            "pid"
        )

        remote_ip = extract_ip(
            remote
        )

        remote_info = analyze_ip(
            remote_ip
        )

        connection_type = "internal"

        if remote_info["global"]:
            connection_type = "external"

        result.append({

            "state": connection.get(
                "state"
            ),

            "local": local,

            "remote": remote,

            "remote_ip": remote_ip,

            "remote_type": connection_type,

            "remote_private": remote_info[
                "private"
            ],

            "remote_global": remote_info[
                "global"
            ],

            "process": process,

            "pid": pid

        })

    return result


# ============================================================
# EXTRACT IP FROM ADDRESS
# ============================================================

def extract_ip(address):

    address = address.strip()

    # IPv6:
    # [2001:db8::1]:443
    if address.startswith("["):

        closing = address.find("]")

        if closing != -1:

            return address[
                1:closing
            ]

    # IPv4:
    # 1.2.3.4:22
    if ":" in address:

        # IPv6 without brackets
        if address.count(":") > 1:
            return address

        return address.rsplit(
            ":",
            1
        )[0]

    return address


# ============================================================
# SSH CONNECTIONS
# ============================================================

def get_ssh_connections(
    connections
):

    ssh_connections = []

    for connection in connections:

        local = connection.get(
            "local",
            ""
        )

        if local.endswith(":22"):

            ssh_connections.append(
                connection
            )

    return ssh_connections


# ============================================================
# EXTERNAL CONNECTIONS
# ============================================================

def get_external_connections(
    connections
):

    return [
        connection
        for connection in connections
        if connection.get(
            "remote_global",
            False
        )
    ]


# ============================================================
# POSTGRESQL CHECK
# ============================================================

def check_postgresql(
    listening_ports
):

    postgres = []

    for port in listening_ports:

        if port.get("port") == 5432:

            postgres.append(
                port
            )

    public = any(
        item.get(
            "public_access",
            False
        )
        for item in postgres
    )

    return {
        "installed_or_listening": bool(
            postgres
        ),
        "public": public,
        "instances": postgres
    }


# ============================================================
# SECURITY ANALYSIS
# ============================================================

def security_analysis(
    listening_ports,
    connections
):

    dangerous_services = []

    for item in listening_ports:

        if item["risk"] == "high":

            dangerous_services.append({

                "port": item["port"],

                "service": item["service"],

                "address": item["address"],

                "process": item["process"],

                "pid": item["pid"]

            })

    ssh_connections = get_ssh_connections(
        connections
    )

    external_connections = (
        get_external_connections(
            connections
        )
    )

    postgres = check_postgresql(
        listening_ports
    )

    problems = []

    if postgres["public"]:
        problems.append(
            "PostgreSQL is publicly accessible"
        )

    for service in dangerous_services:

        if service["port"] != 5432:
            problems.append(
                f"Potentially dangerous public "
                f"service: {service['service']} "
                f"on port {service['port']}"
            )

    if len(ssh_connections) > 10:

        problems.append(
            "Large number of active SSH connections"
        )

    if problems:

        status = "warning"

    else:

        status = "safe"

    return {

        "status": status,

        "dangerous_public_services":
            dangerous_services,

        "postgresql": postgres,

        "active_ssh_connections":
            len(ssh_connections),

        "external_connections":
            len(external_connections),

        "problems":
            problems

    }


# ============================================================
# MAIN SCAN
# ============================================================

def scan():

    server_info = load_server_info()

    listening_ports = (
        analyze_listening_ports(
            server_info
        )
    )

    connections = (
        analyze_connections(
            server_info
        )
    )

    security = security_analysis(
        listening_ports,
        connections
    )

    return {

        "module": "network_monitor",

        "status": "ok",

        "server": {

            "hostname":
                server_info.get(
                    "server",
                    {}
                ).get(
                    "hostname"
                ),

            "addresses":
                server_info.get(
                    "server",
                    {}
                ).get(
                    "addresses",
                    []
                )

        },

        "listening_services":
            listening_ports,

        "active_connections":
            connections,

        "security_analysis":
            security

    }


# ============================================================
# MAIN
# ============================================================

def main():

    print()

    print("=" * 60)
    print("SERVERGUARD NETWORK MONITOR")
    print("=" * 60)

    print()

    try:

        result = scan()

        print(
            json.dumps(
                result,
                indent=4,
                ensure_ascii=False
            )
        )

    except Exception as error:

        print(
            json.dumps(
                {
                    "module":
                        "network_monitor",

                    "status":
                        "error",

                    "error":
                        str(error)
                },
                indent=4,
                ensure_ascii=False
            )
        )


if __name__ == "__main__":
    main()

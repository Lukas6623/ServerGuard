#!/usr/bin/env python3

import json
import os
import platform
import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# SERVERGUARD SERVER INFORMATION
# ============================================================

AGENT_NAME = "ServerGuard Agent"
AGENT_VERSION = "0.2.0"

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SERVER_INFO_FILE = DATA_DIR / "server_info.json"


# ============================================================
# COMMAND EXECUTION
# ============================================================

def run_command(command):
    """
    Execute shell command and return stdout.
    Never raises an exception.
    """

    try:
        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10
        )

        return result.stdout.strip()

    except Exception:
        return ""


def command_exists(command):
    return shutil.which(command) is not None


# ============================================================
# FILE READING
# ============================================================

def read_file(path):
    try:
        return Path(path).read_text(
            encoding="utf-8",
            errors="ignore"
        )
    except Exception:
        return ""


# ============================================================
# OS INFORMATION
# ============================================================

def get_os_info():
    info = {
        "name": platform.system(),
        "distribution": "",
        "version": "",
        "version_id": "",
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "hostname": socket.gethostname(),
        "fqdn": ""
    }

    if platform.system() == "Linux":

        os_release = read_file("/etc/os-release")

        for line in os_release.splitlines():
            if "=" not in line:
                continue

            key, value = line.split("=", 1)

            value = value.strip().strip('"')

            if key == "NAME":
                info["distribution"] = value

            elif key == "PRETTY_NAME":
                info["version"] = value

            elif key == "VERSION_ID":
                info["version_id"] = value

        fqdn = run_command("hostname -f")

        if fqdn and fqdn != "localhost":
            info["fqdn"] = fqdn
        else:
            info["fqdn"] = socket.getfqdn()

    else:
        info["version"] = platform.version()
        info["fqdn"] = socket.getfqdn()

    return info


# ============================================================
# SERVER INFORMATION
# ============================================================

def get_server_info():
    hostname = socket.gethostname()

    fqdn = socket.getfqdn()

    if not fqdn or fqdn == "localhost":
        fqdn = hostname

    return {
        "hostname": hostname,
        "fqdn": fqdn
    }


# ============================================================
# CPU INFORMATION
# ============================================================

def get_cpu_info():

    cpu_model = ""

    if platform.system() == "Linux":
        cpuinfo = read_file("/proc/cpuinfo")

        for line in cpuinfo.splitlines():
            if line.lower().startswith("model name"):
                if ":" in line:
                    cpu_model = line.split(":", 1)[1].strip()
                    break

    if not cpu_model:
        cpu_model = platform.processor()

    logical_processors = os.cpu_count() or 0

    physical_cores = None

    if platform.system() == "Linux":

        output = run_command(
            "lscpu 2>/dev/null | grep '^Core(s) per socket:'"
        )

        if output:
            match = re.search(r":\s*(\d+)", output)

            if match:
                cores_per_socket = int(match.group(1))

                sockets_output = run_command(
                    "lscpu 2>/dev/null | grep '^Socket(s):'"
                )

                socket_match = re.search(
                    r":\s*(\d+)",
                    sockets_output
                )

                if socket_match:
                    sockets = int(socket_match.group(1))
                    physical_cores = cores_per_socket * sockets

    return {
        "model": cpu_model,
        "logical_processors": logical_processors,
        "physical_cores": physical_cores
    }


# ============================================================
# MEMORY INFORMATION
# ============================================================

def get_memory_info():

    if platform.system() == "Linux":

        meminfo = read_file("/proc/meminfo")

        values = {}

        for line in meminfo.splitlines():

            parts = line.split()

            if len(parts) >= 2:

                key = parts[0].rstrip(":")

                try:
                    value_kb = int(parts[1])
                    values[key] = value_kb
                except ValueError:
                    pass

        total_kb = values.get("MemTotal", 0)
        available_kb = values.get("MemAvailable", 0)

        used_kb = max(total_kb - available_kb, 0)

        return {
            "total_mb": round(total_kb / 1024),
            "used_mb": round(used_kb / 1024),
            "available_mb": round(available_kb / 1024),
            "swap_total_mb": round(
                values.get("SwapTotal", 0) / 1024
            ),
            "swap_free_mb": round(
                values.get("SwapFree", 0) / 1024
            )
        }

    return {
        "total_mb": None,
        "used_mb": None,
        "available_mb": None,
        "swap_total_mb": None,
        "swap_free_mb": None
    }


# ============================================================
# DISK INFORMATION
# ============================================================

def get_disk_info():

    disks = []

    output = run_command(
        "df -P -k -x tmpfs -x devtmpfs 2>/dev/null"
    )

    if not output:
        return disks

    lines = output.splitlines()

    for line in lines[1:]:

        parts = line.split()

        if len(parts) < 6:
            continue

        filesystem = parts[0]
        total_kb = parts[1]
        used_kb = parts[2]
        free_kb = parts[3]
        usage = parts[4]
        mount = parts[5]

        if not total_kb.isdigit():
            continue

        try:

            total_gb = int(total_kb) / 1024 / 1024
            used_gb = int(used_kb) / 1024 / 1024
            free_gb = int(free_kb) / 1024 / 1024

            usage_percent = float(
                usage.rstrip("%")
            )

            disks.append({
                "filesystem": filesystem,
                "mount": mount,
                "total_gb": round(total_gb, 2),
                "used_gb": round(used_gb, 2),
                "free_gb": round(free_gb, 2),
                "usage_percent": usage_percent
            })

        except Exception:
            continue

    return disks


# ============================================================
# NETWORK INTERFACES
# ============================================================

def get_network_interfaces():

    interfaces = []

    output = run_command(
        "ip -o addr show 2>/dev/null"
    )

    if not output:
        return interfaces

    for line in output.splitlines():

        parts = line.split()

        if len(parts) < 4:
            continue

        interface = parts[1]

        if parts[2] not in ("inet", "inet6"):
            continue

        address = parts[3]

        interfaces.append({
            "interface": interface,
            "family": parts[2],
            "address": address
        })

    return interfaces


# ============================================================
# SERVER ADDRESSES
# ============================================================

def get_host_addresses(network_interfaces):

    addresses = []

    for item in network_interfaces:

        address = item.get("address", "")

        if "/" in address:
            address = address.split("/", 1)[0]

        if address and address not in addresses:
            addresses.append(address)

    return addresses


# ============================================================
# LISTENING PORTS
# ============================================================

def get_listening_ports():

    ports = []

    output = run_command(
        "ss -lntup 2>/dev/null"
    )

    if not output:
        return ports

    for line in output.splitlines():

        if not line.startswith("tcp"):
            continue

        parts = line.split()

        if len(parts) < 5:
            continue

        protocol = parts[0]

        local_address = parts[4]

        process_info = ""

        if "users:" in line:
            process_info = line[line.find("users:"):]

        address = local_address
        port = ""

        # IPv6: [::]:22
        if local_address.startswith("["):

            match = re.match(
                r"\[(.*?)\]:(\d+)$",
                local_address
            )

            if match:
                address = match.group(1)
                port = match.group(2)

        else:

            if ":" in local_address:

                address, port = local_address.rsplit(":", 1)

        if not port.isdigit():
            continue

        process_name = None
        pid = None

        match = re.search(
            r'users:\(\("([^"]+)",pid=(\d+)',
            process_info
        )

        if match:

            process_name = match.group(1)
            pid = match.group(2)

        ports.append({
            "protocol": protocol,
            "address": address,
            "port": int(port),
            "process": process_name,
            "pid": pid
        })

    return ports


# ============================================================
# ACTIVE CONNECTIONS
# ============================================================

def get_active_connections():

    connections = []

    output = run_command(
        "ss -tnp 2>/dev/null"
    )

    if not output:
        return connections

    for line in output.splitlines():

        if not line.startswith("ESTAB"):
            continue

        parts = line.split()

        if len(parts) < 5:
            continue

        local_address = parts[3]
        remote_address = parts[4]

        process_name = None
        pid = None

        match = re.search(
            r'users:\(\("([^"]+)",pid=(\d+)',
            line
        )

        if match:
            process_name = match.group(1)
            pid = match.group(2)

        connections.append({
            "state": "ESTABLISHED",
            "local": local_address,
            "remote": remote_address,
            "process": process_name,
            "pid": pid
        })

    return connections


# ============================================================
# PROCESSES
# ============================================================

def get_processes():

    processes = []

    output = run_command(
        "ps -eo pid=,ppid=,user=,stat=,comm=,args= --sort=pid"
    )

    if not output:
        return processes

    for line in output.splitlines():

        parts = line.split(None, 5)

        if len(parts) < 5:
            continue

        pid = parts[0]
        ppid = parts[1]
        user = parts[2]
        status = parts[3]
        name = parts[4]

        command = parts[5] if len(parts) >= 6 else ""

        processes.append({
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "user": user,
            "status": status,
            "command": command
        })

    return processes


# ============================================================
# USERS
# ============================================================

def get_users():

    users = []

    passwd = read_file("/etc/passwd")

    for line in passwd.splitlines():

        parts = line.split(":")

        if len(parts) < 7:
            continue

        username = parts[0]
        uid = parts[2]
        home = parts[5]
        shell = parts[6]

        try:
            uid_number = int(uid)
        except ValueError:
            continue

        login_shells = [
            "/bin/bash",
            "/bin/sh",
            "/bin/zsh",
            "/bin/fish",
            "/usr/bin/bash",
            "/usr/bin/zsh"
        ]

        login_capable = shell in login_shells

        if uid_number >= 1000:
            user_type = "human"
        elif uid_number == 0:
            user_type = "root"
        else:
            user_type = "system"

        users.append({
            "username": username,
            "uid": uid_number,
            "home": home,
            "shell": shell,
            "type": user_type,
            "login_capable": login_capable
        })

    return users


# ============================================================
# SUDO USERS
# ============================================================

def get_sudo_users():

    sudo_users = []

    if not command_exists("getent"):
        return sudo_users

    output = run_command(
        "getent group sudo 2>/dev/null"
    )

    if output and ":" in output:

        parts = output.split(":")

        if len(parts) >= 4:

            members = parts[3].strip()

            if members:

                for username in members.split(","):

                    username = username.strip()

                    if username:
                        sudo_users.append(username)

    return sudo_users


# ============================================================
# SSH INFORMATION
# ============================================================

def get_ssh_info():

    installed = command_exists("sshd")

    if not installed:

        ssh_path = shutil.which("ssh")

        installed = ssh_path is not None

    service_active = False

    if command_exists("systemctl"):

        status = run_command(
            "systemctl is-active ssh 2>/dev/null"
        )

        if status == "active":
            service_active = True
        else:

            status = run_command(
                "systemctl is-active sshd 2>/dev/null"
            )

            service_active = status == "active"

    port = 22

    ssh_config = read_file(
        "/etc/ssh/sshd_config"
    )

    for line in ssh_config.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        match = re.match(
            r"Port\s+(\d+)",
            line,
            re.IGNORECASE
        )

        if match:
            port = int(match.group(1))
            break

    return {
        "installed": installed,
        "service_active": service_active,
        "port": port
    }


# ============================================================
# FIREWALL
# ============================================================

def get_firewall_info():

    result = {
        "detected": False,
        "type": None,
        "active": False
    }

    # UFW
    if command_exists("ufw"):

        result["detected"] = True
        result["type"] = "ufw"

        status = run_command(
            "ufw status 2>/dev/null"
        )

        if status.startswith("Status: active"):
            result["active"] = True

        return result

    # firewalld
    if command_exists("firewall-cmd"):

        result["detected"] = True
        result["type"] = "firewalld"

        status = run_command(
            "firewall-cmd --state 2>/dev/null"
        )

        result["active"] = status == "running"

        return result

    # nftables
    if command_exists("nft"):

        result["detected"] = True
        result["type"] = "nftables"

        rules = run_command(
            "nft list ruleset 2>/dev/null"
        )

        result["active"] = bool(rules)

        return result

    return result


# ============================================================
# SYSTEMD SERVICES
# ============================================================

def get_services():

    services = []

    if not command_exists("systemctl"):
        return services

    output = run_command(
        "systemctl list-units --type=service "
        "--all --no-legend --no-pager 2>/dev/null"
    )

    if not output:
        return services

    for line in output.splitlines():

        parts = line.split(None, 4)

        if len(parts) < 4:
            continue

        service_name = parts[0]
        load_state = parts[1]
        active_state = parts[2]
        sub_state = parts[3]

        description = parts[4] if len(parts) >= 5 else ""

        services.append({
            "name": service_name,
            "load": load_state,
            "active": active_state,
            "sub": sub_state,
            "description": description
        })

    return services


# ============================================================
# CRON
# ============================================================

def get_cron_info():

    result = {
        "installed": command_exists("cron"),
        "service_active": False,
        "system_crontab": False,
        "user_crontabs": []
    }

    if command_exists("systemctl"):

        status = run_command(
            "systemctl is-active cron 2>/dev/null"
        )

        result["service_active"] = status == "active"

    system_crontab = read_file("/etc/crontab")

    result["system_crontab"] = bool(
        system_crontab.strip()
    )

    return result


# ============================================================
# SOFTWARE
# ============================================================

def get_software_info():

    software = {}

    programs = [
        "python3",
        "python",
        "gcc",
        "g++",
        "git",
        "curl",
        "wget",
        "docker",
        "postgres",
        "psql",
        "mysql",
        "mysqld",
        "nginx",
        "apache2",
        "redis-server",
        "node",
        "npm"
    ]

    for program in programs:

        path = shutil.which(program)

        key = program

        if program == "python3":
            key = "python3"

        elif program == "postgres":
            key = "postgresql"

        elif program == "psql":
            continue

        elif program == "mysqld":
            continue

        elif program == "apache2":
            key = "apache"

        elif program == "redis-server":
            key = "redis"

        if path:

            version = ""

            version_output = run_command(
                f"{program} --version 2>/dev/null"
            )

            if version_output:
                version = version_output.splitlines()[0]

            software[key] = {
                "installed": True,
                "path": path,
                "version": version
            }

        elif key not in software:

            software[key] = {
                "installed": False,
                "path": None,
                "version": None
            }

    return software


# ============================================================
# UPTIME
# ============================================================

def get_uptime():

    uptime_seconds = 0

    uptime_file = read_file(
        "/proc/uptime"
    )

    if uptime_file:

        try:
            uptime_seconds = int(
                float(
                    uptime_file.split()[0]
                )
            )
        except Exception:
            pass

    return {
        "seconds": uptime_seconds,
        "minutes": round(uptime_seconds / 60, 2),
        "hours": round(uptime_seconds / 3600, 2),
        "days": round(uptime_seconds / 86400, 2)
    }


# ============================================================
# KERNEL SECURITY
# ============================================================

def get_kernel_security():

    result = {
        "secure_boot": None,
        "aslr": None
    }

    # ASLR
    aslr = read_file(
        "/proc/sys/kernel/randomize_va_space"
    ).strip()

    if aslr:

        try:
            value = int(aslr)

            result["aslr"] = {
                "value": value,
                "enabled": value > 0
            }

        except ValueError:
            pass

    # Secure Boot
    if command_exists("mokutil"):

        output = run_command(
            "mokutil --sb-state 2>/dev/null"
        )

        if "SecureBoot enabled" in output:
            result["secure_boot"] = True

        elif "SecureBoot disabled" in output:
            result["secure_boot"] = False

    return result


# ============================================================
# PACKAGE INFORMATION
# ============================================================

def get_package_info():

    result = {
        "manager": None,
        "package_count": None
    }

    if command_exists("dpkg"):

        result["manager"] = "apt/dpkg"

        output = run_command(
            "dpkg-query -f '${binary:Package}\\n' -W 2>/dev/null"
        )

        if output:
            result["package_count"] = len(
                output.splitlines()
            )

    elif command_exists("rpm"):

        result["manager"] = "rpm"

        output = run_command(
            "rpm -qa 2>/dev/null"
        )

        if output:
            result["package_count"] = len(
                output.splitlines()
            )

    return result


# ============================================================
# COMPLETE SERVER PROFILE
# ============================================================

def collect_server_info():

    network_interfaces = get_network_interfaces()

    addresses = get_host_addresses(
        network_interfaces
    )

    ssh_info = get_ssh_info()

    firewall_info = get_firewall_info()

    users = get_users()

    sudo_users = get_sudo_users()

    processes = get_processes()

    listening_ports = get_listening_ports()

    active_connections = get_active_connections()

    services = get_services()

    cron_info = get_cron_info()

    software = get_software_info()

    profile = {

        "agent": {
            "name": AGENT_NAME,
            "version": AGENT_VERSION,
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat()
        },

        "server": {
            **get_server_info(),
            "addresses": addresses
        },

        "os": get_os_info(),

        "hardware": {
            "cpu": get_cpu_info(),
            "memory": get_memory_info(),
            "disks": get_disk_info()
        },

        "network": {

            "interfaces": network_interfaces,

            "listening_ports": listening_ports,

            "active_connections": active_connections
        },

        "processes": processes,

        "users": {
            "all": users,
            "sudo": sudo_users,

            "human_users": [
                user["username"]
                for user in users
                if user["type"] == "human"
            ],

            "login_capable": [
                user["username"]
                for user in users
                if user["login_capable"]
            ]
        },

        "security": {

            "ssh": ssh_info,

            "firewall": firewall_info,

            "kernel": get_kernel_security(),

            "cron": cron_info
        },

        "services": services,

        "software": software,

        "packages": get_package_info(),

        "system": {
            "uptime": get_uptime()
        }
    }

    return profile


# ============================================================
# SAVE PROFILE
# ============================================================

def save_server_info(data):

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        SERVER_INFO_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4,
            ensure_ascii=False
        )


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 60)
    print("SERVERGUARD AGENT")
    print("=" * 60)
    print()

    print("[*] Collecting server information...")

    data = collect_server_info()

    print("[*] Saving server profile...")

    save_server_info(data)

    print()
    print("[OK] Server information collected.")
    print(f"[OK] Saved to: {SERVER_INFO_FILE}")
    print()

    print(json.dumps(
        data,
        indent=4,
        ensure_ascii=False
    ))

    print()
    print("=" * 60)
    print("ServerGuard Agent completed.")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()


#!/usr/bin/env python3

import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


AGENT_NAME = "ServerGuard Agent"
AGENT_VERSION = "0.2.0"

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SERVER_INFO_FILE = DATA_DIR / "server_info.json"


def run_command(command, timeout=10):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
            check=False
        )
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def command_exists(command):
    return shutil.which(command) is not None


def read_file(path):
    try:
        return Path(path).read_text(
            encoding="utf-8",
            errors="replace"
        )
    except (OSError, UnicodeError):
        return ""


def parse_integer(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def get_os_info():
    system = platform.system()

    info = {
        "name": system,
        "distribution": "",
        "version": "",
        "version_id": "",
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn()
    }

    if system == "Linux":
        values = {}

        for line in read_file("/etc/os-release").splitlines():
            if "=" not in line:
                continue

            key, value = line.split("=", 1)

            try:
                parsed = shlex.split(value)
                values[key] = parsed[0] if parsed else ""
            except ValueError:
                values[key] = value.strip('"')

        info["distribution"] = values.get("NAME", "")
        info["version"] = values.get(
            "PRETTY_NAME",
            values.get("VERSION", "")
        )
        info["version_id"] = values.get("VERSION_ID", "")

        fqdn = run_command(["hostname", "-f"])
        if fqdn and fqdn != "localhost":
            info["fqdn"] = fqdn

    else:
        info["version"] = platform.version()

    return info


def get_server_info():
    hostname = socket.gethostname()
    fqdn = socket.getfqdn()

    if not fqdn or fqdn == "localhost":
        fqdn = hostname

    return {
        "hostname": hostname,
        "fqdn": fqdn
    }


def get_cpu_info():
    cpu_model = ""
    physical_cores = None

    if platform.system() == "Linux":
        cpuinfo = read_file("/proc/cpuinfo")

        for line in cpuinfo.splitlines():
            if line.lower().startswith("model name"):
                if ":" in line:
                    cpu_model = line.split(":", 1)[1].strip()
                    break

        if command_exists("lscpu"):
            output = run_command([
                "lscpu",
                "-p=CORE,SOCKET"
            ])

            core_pairs = set()

            for line in output.splitlines():
                if not line or line.startswith("#"):
                    continue

                parts = line.split(",")

                if len(parts) != 2:
                    continue

                if parts[0].isdigit() and parts[1].isdigit():
                    core_pairs.add((parts[0], parts[1]))

            if core_pairs:
                physical_cores = len(core_pairs)

    if not cpu_model:
        cpu_model = platform.processor()

    return {
        "model": cpu_model,
        "logical_processors": os.cpu_count() or 0,
        "physical_cores": physical_cores
    }


def get_memory_info():
    if platform.system() != "Linux":
        return {
            "total_mb": None,
            "used_mb": None,
            "available_mb": None,
            "swap_total_mb": None,
            "swap_free_mb": None
        }

    values = {}

    for line in read_file("/proc/meminfo").splitlines():
        parts = line.split()

        if len(parts) < 2:
            continue

        value = parse_integer(parts[1])

        if value is not None:
            values[parts[0].rstrip(":")] = value

    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", 0)

    return {
        "total_mb": round(total / 1024),
        "used_mb": round(max(total - available, 0) / 1024),
        "available_mb": round(available / 1024),
        "swap_total_mb": round(values.get("SwapTotal", 0) / 1024),
        "swap_free_mb": round(values.get("SwapFree", 0) / 1024)
    }


def get_disk_info():
    if not command_exists("df"):
        return []

    output = run_command([
        "df", "-P", "-k",
        "-x", "tmpfs",
        "-x", "devtmpfs"
    ])

    disks = []

    for line in output.splitlines()[1:]:
        parts = line.split()

        if len(parts) < 6:
            continue

        try:
            total_kb = int(parts[1])
            used_kb = int(parts[2])
            free_kb = int(parts[3])
            usage = float(parts[4].rstrip("%"))
        except ValueError:
            continue

        disks.append({
            "filesystem": parts[0],
            "mount": parts[5],
            "total_gb": round(total_kb / 1024 / 1024, 2),
            "used_gb": round(used_kb / 1024 / 1024, 2),
            "free_gb": round(free_kb / 1024 / 1024, 2),
            "usage_percent": usage
        })

    return disks


def get_network_interfaces():
    if not command_exists("ip"):
        return []

    output = run_command(["ip", "-o", "addr", "show"])
    interfaces = []

    for line in output.splitlines():
        parts = line.split()

        if len(parts) < 4 or parts[2] not in ("inet", "inet6"):
            continue

        interfaces.append({
            "interface": parts[1],
            "family": parts[2],
            "address": parts[3]
        })

    return interfaces


def get_host_addresses(network_interfaces):
    addresses = []

    for item in network_interfaces:
        address = item.get("address", "").split("/", 1)[0]

        if address and address not in addresses:
            addresses.append(address)

    return addresses


def parse_socket_process(line):
    match = re.search(
        r'users:\(\("([^"]+)",pid=(\d+)',
        line
    )

    if not match:
        return None, None

    return match.group(1), match.group(2)


def parse_address_port(value):
    if value.startswith("["):
        match = re.match(r"\[(.*?)\]:(\d+)$", value)

        if match:
            return match.group(1), int(match.group(2))

        return value, None

    if ":" not in value:
        return value, None

    address, port = value.rsplit(":", 1)

    if port.isdigit():
        return address, int(port)

    return value, None


def get_listening_ports():
    if not command_exists("ss"):
        return []

    output = run_command(["ss", "-lntup"])
    ports = []

    for line in output.splitlines():
        parts = line.split()

        if len(parts) < 5 or parts[0] not in ("tcp", "tcp6", "udp", "udp6"):
            continue

        protocol = parts[0]
        local_address, port = parse_address_port(parts[4])

        if port is None:
            continue

        process_name, pid = parse_socket_process(line)

        ports.append({
            "protocol": protocol,
            "address": local_address,
            "port": port,
            "process": process_name,
            "pid": pid
        })

    return ports


def get_active_connections():
    if not command_exists("ss"):
        return []

    output = run_command(["ss", "-tnp"])
    connections = []

    for line in output.splitlines():
        parts = line.split()

        if len(parts) < 5 or parts[0] != "ESTAB":
            continue

        process_name, pid = parse_socket_process(line)

        connections.append({
            "state": "ESTABLISHED",
            "local": parts[3],
            "remote": parts[4],
            "process": process_name,
            "pid": pid
        })

    return connections


def get_processes():
    if not command_exists("ps"):
        return []

    output = run_command([
        "ps", "-eo",
        "pid=,ppid=,user=,stat=,comm=,args=",
        "--sort=pid"
    ])

    processes = []

    for line in output.splitlines():
        parts = line.split(None, 5)

        if len(parts) < 5:
            continue

        processes.append({
            "pid": parts[0],
            "ppid": parts[1],
            "user": parts[2],
            "status": parts[3],
            "name": parts[4],
            "command": parts[5] if len(parts) > 5 else ""
        })

    return processes


def get_users():
    users = []
    valid_shells = {
        line.strip()
        for line in read_file("/etc/shells").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    for line in read_file("/etc/passwd").splitlines():
        parts = line.split(":")

        if len(parts) < 7:
            continue

        username, uid, home, shell = (
            parts[0], parts[2], parts[5], parts[6]
        )

        uid_number = parse_integer(uid)

        if uid_number is None:
            continue

        if uid_number == 0:
            user_type = "root"
        elif uid_number >= 1000:
            user_type = "human"
        else:
            user_type = "system"

        login_capable = (
            shell in valid_shells
            and not shell.endswith("/nologin")
            and not shell.endswith("/false")
        )

        users.append({
            "username": username,
            "uid": uid_number,
            "home": home,
            "shell": shell,
            "type": user_type,
            "login_capable": login_capable
        })

    return users


def get_sudo_users():
    if not command_exists("getent"):
        return []

    output = run_command(["getent", "group", "sudo"])

    if not output:
        return []

    parts = output.split(":")

    if len(parts) < 4 or not parts[3].strip():
        return []

    return [
        username.strip()
        for username in parts[3].split(",")
        if username.strip()
    ]


def get_ssh_info():
    installed = command_exists("sshd")
    service_active = False
    port = 22

    if command_exists("systemctl"):
        for service in ("ssh", "sshd"):
            status = run_command([
                "systemctl", "is-active", service
            ])

            if status == "active":
                service_active = True
                break

    if installed:
        effective_config = run_command(["sshd", "-T"])

        for line in effective_config.splitlines():
            match = re.match(r"port\s+(\d+)", line, re.IGNORECASE)

            if match:
                port = int(match.group(1))
                break

    if port == 22:
        for line in read_file("/etc/ssh/sshd_config").splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            match = re.match(r"Port\s+(\d+)", line, re.IGNORECASE)

            if match:
                port = int(match.group(1))
                break

    return {
        "installed": installed,
        "service_active": service_active,
        "port": port
    }


def get_firewall_info():
    result = {
        "detected": False,
        "type": None,
        "active": False
    }

    if command_exists("ufw"):
        result["detected"] = True
        result["type"] = "ufw"
        result["active"] = run_command(["ufw", "status"]).startswith(
            "Status: active"
        )
        return result

    if command_exists("firewall-cmd"):
        result["detected"] = True
        result["type"] = "firewalld"
        result["active"] = run_command(
            ["firewall-cmd", "--state"]
        ) == "running"
        return result

    if command_exists("nft"):
        result["detected"] = True
        result["type"] = "nftables"
        result["active"] = bool(
            run_command(["nft", "list", "ruleset"])
        )
        return result

    if command_exists("iptables"):
        result["detected"] = True
        result["type"] = "iptables"
        result["active"] = bool(
            run_command(["iptables", "-S"])
        )
        return result

    return result


def get_services():
    if not command_exists("systemctl"):
        return []

    output = run_command([
        "systemctl", "list-units",
        "--type=service",
        "--all",
        "--no-legend",
        "--no-pager"
    ])

    services = []

    for line in output.splitlines():
        parts = line.split(None, 4)

        if len(parts) < 4:
            continue

        services.append({
            "name": parts[0],
            "load": parts[1],
            "active": parts[2],
            "sub": parts[3],
            "description": parts[4] if len(parts) > 4 else ""
        })

    return services


def get_cron_info():
    installed = (
        command_exists("cron")
        or command_exists("crond")
        or command_exists("crontab")
    )

    service_active = False

    if command_exists("systemctl"):
        for service in ("cron", "crond"):
            if run_command(["systemctl", "is-active", service]) == "active":
                service_active = True
                break

    return {
        "installed": installed,
        "service_active": service_active,
        "system_crontab": bool(read_file("/etc/crontab").strip()),
        "user_crontabs": []
    }


def get_software_info():
    programs = {
        "python3": "python3",
        "python": "python",
        "gcc": "gcc",
        "g++": "g++",
        "git": "git",
        "curl": "curl",
        "wget": "wget",
        "docker": "docker",
        "postgres": "postgresql",
        "mysql": "mysql",
        "nginx": "nginx",
        "apache2": "apache",
        "redis-server": "redis",
        "node": "node",
        "npm": "npm"
    }

    software = {}

    for executable, key in programs.items():
        path = shutil.which(executable)

        if not path:
            software[key] = {
                "installed": False,
                "path": None,
                "version": None
            }
            continue

        version_output = run_command([path, "--version"])
        version = version_output.splitlines()[0] if version_output else ""

        software[key] = {
            "installed": True,
            "path": path,
            "version": version
        }

    return software


def get_uptime():
    uptime_seconds = 0
    uptime_file = read_file("/proc/uptime")

    if uptime_file:
        try:
            uptime_seconds = int(float(uptime_file.split()[0]))
        except (ValueError, IndexError):
            pass

    return {
        "seconds": uptime_seconds,
        "minutes": round(uptime_seconds / 60, 2),
        "hours": round(uptime_seconds / 3600, 2),
        "days": round(uptime_seconds / 86400, 2)
    }


def get_kernel_security():
    result = {
        "secure_boot": None,
        "aslr": None
    }

    aslr = read_file(
        "/proc/sys/kernel/randomize_va_space"
    ).strip()

    if aslr:
        value = parse_integer(aslr)

        if value is not None:
            result["aslr"] = {
                "value": value,
                "enabled": value > 0
            }

    if command_exists("mokutil"):
        output = run_command(["mokutil", "--sb-state"])

        if "SecureBoot enabled" in output:
            result["secure_boot"] = True
        elif "SecureBoot disabled" in output:
            result["secure_boot"] = False

    return result


def get_package_info():
    result = {
        "manager": None,
        "package_count": None
    }

    if command_exists("dpkg-query"):
        result["manager"] = "apt/dpkg"
        output = run_command([
            "dpkg-query",
            "-f=${binary:Package}\\n",
            "-W"
        ])

    elif command_exists("rpm"):
        result["manager"] = "rpm"
        output = run_command(["rpm", "-qa"])

    else:
        return result

    if output:
        result["package_count"] = len(output.splitlines())

    return result


def collect_server_info():
    network_interfaces = get_network_interfaces()
    users = get_users()

    return {
        "agent": {
            "name": AGENT_NAME,
            "version": AGENT_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        "server": {
            **get_server_info(),
            "addresses": get_host_addresses(network_interfaces)
        },
        "os": get_os_info(),
        "hardware": {
            "cpu": get_cpu_info(),
            "memory": get_memory_info(),
            "disks": get_disk_info()
        },
        "network": {
            "interfaces": network_interfaces,
            "listening_ports": get_listening_ports(),
            "active_connections": get_active_connections()
        },
        "processes": get_processes(),
        "users": {
            "all": users,
            "sudo": get_sudo_users(),
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
            "ssh": get_ssh_info(),
            "firewall": get_firewall_info(),
            "kernel": get_kernel_security(),
            "cron": get_cron_info()
        },
        "services": get_services(),
        "software": get_software_info(),
        "packages": get_package_info(),
        "system": {
            "uptime": get_uptime()
        }
    }


def save_server_info(data):
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=DATA_DIR,
            prefix=".server_info_",
            suffix=".tmp",
            delete=False
        ) as file:
            temporary_path = Path(file.name)

            json.dump(
                data,
                file,
                indent=4,
                ensure_ascii=False
            )
            file.write("\n")

        try:
            os.chmod(temporary_path, 0o600)
        except OSError:
            pass

        temporary_path.replace(SERVER_INFO_FILE)

        try:
            os.chmod(SERVER_INFO_FILE, 0o600)
        except OSError:
            pass

    finally:
        if temporary_path and temporary_path.exists():
            try:
                temporary_path.unlink()
            except OSError:
                pass


def main():
    print()
    print("=" * 48)
    print(AGENT_NAME.upper())
    print("=" * 48)

    print("[*] Collecting server information...")
    data = collect_server_info()

    print("[*] Saving server profile...")
    save_server_info(data)

    print(f"[OK] Saved to: {SERVER_INFO_FILE}")
    print()
    print(json.dumps(data, indent=2, ensure_ascii=False))
    print()
    print("[OK] Collection completed.")


if __name__ == "__main__":
    main()

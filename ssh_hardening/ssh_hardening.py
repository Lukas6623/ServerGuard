
#!/usr/bin/env python3
"""
ServerGuard Firewall Manager
CLI utility for managing UFW. It is not a systemd daemon.
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

APP_NAME = "ServerGuard Firewall Manager"
VERSION = "3.1.0"

UFW = shutil.which("ufw") or "/usr/sbin/ufw"
SSH_CONFIG = Path("/etc/ssh/sshd_config")
MODULE_PATH = Path("/opt/serverguard/firewall_manager.py")
PROTECTED_FILE = Path("/etc/serverguard/firewall_protected_ports.json")


def run_command(args, check=False):
    try:
        result = subprocess.run(
            args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1)

    if check and result.returncode != 0:
        print(result.stdout)
        raise SystemExit(result.returncode)

    return result


def require_root():
    if os.geteuid() != 0:
        print("ERROR: run this command with sudo.")
        raise SystemExit(1)


def require_ufw():
    if not shutil.which("ufw") and not Path(UFW).is_file():
        print("ERROR: ufw is not installed.")
        print("Install it with: sudo apt install ufw")
        raise SystemExit(1)


def ufw(args, check=True):
    require_ufw()
    return run_command([UFW, *args], check=check)


def valid_port_spec(value):
    match = re.fullmatch(
        r"(\d{1,5})(?::(\d{1,5}))?(?:/(tcp|udp))?",
        value.lower(),
    )
    if not match:
        raise argparse.ArgumentTypeError(
            "Use PORT, PORT/tcp, PORT/udp or START:END/tcp."
        )

    start = int(match.group(1))
    end = int(match.group(2) or start)
    proto = match.group(3)

    if not (1 <= start <= 65535 and 1 <= end <= 65535):
        raise argparse.ArgumentTypeError("Ports must be between 1 and 65535.")

    if end < start:
        raise argparse.ArgumentTypeError("Range end must be >= range start.")

    if end != start and not proto:
        raise argparse.ArgumentTypeError(
            "Port ranges must specify /tcp or /udp."
        )

    if end - start > 2000:
        raise argparse.ArgumentTypeError("Port range is too large.")

    return value.lower()


def valid_source(value):
    if value.lower() == "any":
        return "any"

    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid IP address or CIDR.")


def ssh_ports():
    ports = {22}

    try:
        text = SSH_CONFIG.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            match = re.match(r"(?i)^Port\s+(\d+)\s*$", line)
            if match:
                port = int(match.group(1))
                if 1 <= port <= 65535:
                    ports.add(port)
    except OSError:
        pass

    return ports


def parse_port_number(spec):
    match = re.match(r"^(\d+)(?:/(\w+))?$", spec)
    if not match:
        return None, None

    return int(match.group(1)), (match.group(2) or "").lower()


def load_protected():
    try:
        data = json.loads(PROTECTED_FILE.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return set(str(x).lower() for x in data)
    except (OSError, json.JSONDecodeError):
        pass

    return set()


def save_protected(values):
    require_root()
    PROTECTED_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp = PROTECTED_FILE.with_suffix(".tmp")
    temp.write_text(
        json.dumps(sorted(values), indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(temp, 0o600)
    os.replace(temp, PROTECTED_FILE)


def protected_match(spec):
    protected = load_protected()
    protected.update(f"{p}/tcp" for p in ssh_ports())

    port, proto = parse_port_number(spec)
    if port is None:
        return False

    for item in protected:
        pnum, pproto = parse_port_number(item)
        if pnum == port and (not pproto or not proto or pproto == proto):
            return True

    return False


def guard_protected(spec, force):
    if protected_match(spec) and not force:
        print(
            f"REFUSED: {spec} is protected (including configured SSH ports)."
        )
        print("If you understand the risk, repeat with --force.")
        raise SystemExit(3)


def cmd_version(_):
    print(f"{APP_NAME} {VERSION}")


def cmd_status(_):
    result = ufw(["status", "verbose"], check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)


def cmd_rules(_):
    result = ufw(["status", "numbered"], check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)


def cmd_listening(_):
    command = shutil.which("ss")
    if not command:
        print("ERROR: ss is not installed (package: iproute2).")
        raise SystemExit(1)

    result = run_command([command, "-lntup"], check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)


def cmd_allow(args):
    require_root()
    require_ufw()

    if args.from_ip:
        source = args.from_ip
        cmd = ["allow", "from", source, "to", "any", "port", args.port]
    else:
        cmd = ["allow", args.port]

    result = ufw(cmd, check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)


def cmd_close(args):
    require_root()
    guard_protected(args.port, args.force)

    command = ["delete", "allow"]
    if args.from_ip:
        command += ["from", args.from_ip, "to", "any", "port", args.port]
    else:
        command.append(args.port)

    result = ufw(command, check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)


def cmd_deny(args):
    require_root()
    guard_protected(args.port, args.force)

    command = ["deny"]
    if args.from_ip:
        command += ["from", args.from_ip, "to", "any", "port", args.port]
    else:
        command.append(args.port)

    result = ufw(command, check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)


def cmd_unblock(args):
    require_root()
    guard_protected(args.port, args.force)

    command = ["delete", "deny"]
    if args.from_ip:
        command += ["from", args.from_ip, "to", "any", "port", args.port]
    else:
        command.append(args.port)

    result = ufw(command, check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)


def cmd_limit(args):
    require_root()
    guard_protected(args.port, args.force)

    command = ["limit"]
    if args.from_ip:
        command += ["from", args.from_ip, "to", "any", "port", args.port]
    else:
        command.append(args.port)

    result = ufw(command, check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)


def cmd_enable(_):
    require_root()
    result = ufw(["--force", "enable"], check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)


def cmd_disable(args):
    require_root()
    if not args.force:
        print("Refusing to disable UFW without --force.")
        raise SystemExit(2)

    result = ufw(["--force", "disable"], check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)


def cmd_reload(_):
    require_root()
    result = ufw(["reload"], check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)


def cmd_init(args):
    require_root()
    require_ufw()

    # Add the current SSH port before enabling UFW to reduce lockout risk.
    ssh_port = args.ssh_port
    result = ufw(["allow", f"{ssh_port}/tcp"], check=False)
    print(result.stdout, end="")

    if result.returncode:
        raise SystemExit(result.returncode)

    result = ufw(["--force", "enable"], check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)

    print(f"UFW initialized. SSH TCP port {ssh_port} was allowed.")


def cmd_delete(args):
    require_root()

    if not args.number.isdigit() or int(args.number) < 1:
        print("ERROR: rule number must be a positive integer.")
        raise SystemExit(2)

    result = ufw(["--force", "delete", args.number], check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)


def cmd_default(args):
    require_root()

    directions = {
        "incoming": "incoming",
        "outgoing": "outgoing",
        "routed": "routed",
    }
    policies = {"allow", "deny", "reject"}

    if args.direction not in directions or args.policy not in policies:
        print("ERROR: invalid direction or policy.")
        raise SystemExit(2)

    result = ufw(["default", args.policy, directions[args.direction]], check=False)
    print(result.stdout, end="")
    if result.returncode:
        raise SystemExit(result.returncode)


def cmd_protect(args):
    require_root()
    values = load_protected()

    if args.protect_action == "list":
        values.update(f"{p}/tcp" for p in ssh_ports())
        print("Protected ports:")
        for item in sorted(values):
            print(f"  {item}")
        return

    if not args.port:
        print("ERROR: specify a port such as 22/tcp.")
        raise SystemExit(2)

    if args.protect_action == "add":
        values.add(args.port.lower())
        save_protected(values)
        print(f"Protected port added: {args.port}")
    elif args.protect_action == "remove":
        # The SSH port is always protected automatically.
        port, proto = parse_port_number(args.port)
        if port in ssh_ports():
            print("ERROR: configured SSH ports cannot be removed from protection.")
            raise SystemExit(2)
        values.discard(args.port.lower())
        save_protected(values)
        print(f"Protected port removed: {args.port}")


def build_parser():
    parser = argparse.ArgumentParser(description=APP_NAME)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("version")
    p.set_defaults(func=cmd_version)

    p = sub.add_parser("status")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("rules")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("listening")
    p.set_defaults(func=cmd_listening)

    p = sub.add_parser("allow")
    p.add_argument("port", type=valid_port_spec)
    p.add_argument("--from", dest="from_ip", type=valid_source)
    p.set_defaults(func=cmd_allow)

    for name, func in (
        ("close", cmd_close),
        ("deny", cmd_deny),
        ("unblock", cmd_unblock),
        ("limit", cmd_limit),
    ):
        p = sub.add_parser(name)
        p.add_argument("port", type=valid_port_spec)
        p.add_argument("--from", dest="from_ip", type=valid_source)
        p.add_argument("--force", action="store_true")
        p.set_defaults(func=func)

    p = sub.add_parser("enable")
    p.set_defaults(func=cmd_enable)

    p = sub.add_parser("disable")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_disable)

    p = sub.add_parser("reload")
    p.set_defaults(func=cmd_reload)

    p = sub.add_parser("init")
    p.add_argument("--ssh-port", type=int, default=22)
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("delete")
    p.add_argument("number")
    p.set_defaults(func=cmd_delete)

    p = sub.add_parser("default")
    p.add_argument("direction", choices=("incoming", "outgoing", "routed"))
    p.add_argument("policy", choices=("allow", "deny", "reject"))
    p.set_defaults(func=cmd_default)

    p = sub.add_parser("protect")
    protect_sub = p.add_subparsers(dest="protect_action", required=True)

    protect_sub.add_parser("list")
    for action in ("add", "remove"):
        sp = protect_sub.add_parser(action)
        sp.add_argument("port", type=valid_port_spec)

    p.set_defaults(func=cmd_protect)

    return parser


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

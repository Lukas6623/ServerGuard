
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

APP_NAME = "ServerGuard Firewall Manager"
VERSION = "3.0"
UFW = shutil.which("ufw") or "/usr/sbin/ufw"
SSH_CONFIG = Path("/etc/ssh/sshd_config")


class FirewallError(Exception):
    pass


def run_command(
    command: list[str],
    *,
    check: bool = True,
    timeout: int = 30,
) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise FirewallError(f"Command not found: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise FirewallError(
            f"Command timed out: {' '.join(command)}"
        ) from exc

    if check and result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise FirewallError(
            message or f"Command failed with exit code {result.returncode}"
        )

    return result


def require_root() -> None:
    if os.geteuid() != 0:
        raise FirewallError("Root privileges are required. Run this command with sudo.")


def require_ufw() -> None:
    if not shutil.which("ufw") and not Path(UFW).is_file():
        raise FirewallError("UFW was not found. Install it with: sudo apt install ufw")


def validate_source(value: str) -> str:
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid IP address or subnet: {value}"
        ) from exc


def parse_port_spec(value: str) -> tuple[str, Optional[str]]:
    match = re.fullmatch(
        r"(\d{1,5}(?::\d{1,5})?)(?:/(tcp|udp))?",
        value.lower(),
    )

    if not match:
        raise argparse.ArgumentTypeError(
            f"Invalid port specification: {value}. "
            "Examples: 22, 443/tcp, 8000:8100/tcp."
        )

    port_part, protocol = match.groups()

    if ":" in port_part:
        if protocol is None:
            raise argparse.ArgumentTypeError(
                "A protocol is required for port ranges, "
                "for example 8000:8100/tcp."
            )

        start, end = map(int, port_part.split(":"))

        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            raise argparse.ArgumentTypeError(
                "Port numbers must be between 1 and 65535."
            )

        if start > end:
            raise argparse.ArgumentTypeError(
                "The starting port cannot exceed the ending port."
            )
    else:
        port = int(port_part)

        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError(
                "Port numbers must be between 1 and 65535."
            )

    return port_part, protocol


def get_ufw_status() -> str:
    result = run_command([UFW, "status"])
    return result.stdout.strip()


def is_ufw_active() -> bool:
    return bool(
        re.search(r"^Status:\s+active\b", get_ufw_status(), re.I | re.M)
    )


def get_numbered_rules() -> list[dict]:
    result = run_command([UFW, "status", "numbered"])
    rules: list[dict] = []

    for line in result.stdout.splitlines():
        match = re.match(
            r"^\s*\[\s*(\d+)\]\s+(\S+)\s+(.*?)\s*$",
            line,
        )
        if not match:
            continue

        number = int(match.group(1))
        port_token = match.group(2)
        remainder = match.group(3)

        if not re.search(r"\bALLOW\s+IN\b", remainder, re.I):
            continue

        remainder = re.sub(r"^\(v6\)\s+", "", remainder, flags=re.I)
        after_allow = re.split(
            r"\bALLOW\s+IN\b",
            remainder,
            maxsplit=1,
            flags=re.I,
        )

        source_display = after_allow[1].strip() if len(after_allow) > 1 else ""
        source_display = re.sub(r"\s+#.*$", "", source_display).strip()
        source_token = source_display.split()[0] if source_display else ""
        port_token = re.sub(r"\s*\(v6\)$", "", port_token, flags=re.I)

        rules.append({
            "number": number,
            "port_token": port_token,
            "source": source_token,
            "line": line.strip(),
        })

    return rules


def token_matches_port(
    token: str,
    requested_port: str,
    requested_protocol: Optional[str],
) -> bool:
    token = token.strip().lower()

    match = re.fullmatch(
        r"(\d{1,5}(?::\d{1,5})?)(?:/(tcp|udp))?",
        token,
    )
    if not match:
        return False

    existing_port, existing_protocol = match.groups()

    if existing_port != requested_port:
        return False

    if requested_protocol is not None:
        return existing_protocol == requested_protocol

    return True


def normalize_source_for_comparison(value: str) -> Optional[str]:
    if not value or value.lower() == "anywhere":
        return value.lower() if value else None

    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value.lower()


def detect_ssh_ports() -> set[int]:
    ports: set[int] = set()
    sshd = shutil.which("sshd")

    if sshd:
        result = run_command([sshd, "-T"], check=False, timeout=10)

        if result.returncode == 0:
            for line in result.stdout.splitlines():
                match = re.match(r"^\s*port\s+(\d+)\s*$", line, re.I)
                if match:
                    port = int(match.group(1))
                    if 1 <= port <= 65535:
                        ports.add(port)

    if not ports and SSH_CONFIG.is_file():
        try:
            for line in SSH_CONFIG.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines():
                stripped = line.strip()

                if not stripped or stripped.startswith("#"):
                    continue

                match = re.match(r"^Port\s+(\d+)\s*$", stripped, re.I)
                if match:
                    port = int(match.group(1))
                    if 1 <= port <= 65535:
                        ports.add(port)
        except OSError:
            pass

    if not ports:
        ports.add(22)

    return ports


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"{APP_NAME} v{VERSION}")
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    require_ufw()
    print(get_ufw_status())
    return 0


def cmd_rules(_args: argparse.Namespace) -> int:
    require_ufw()
    result = run_command([UFW, "status", "numbered"])
    print(result.stdout.rstrip())
    return 0


def cmd_listening(_args: argparse.Namespace) -> int:
    ss = shutil.which("ss")

    if not ss:
        raise FirewallError("The ss command was not found. Install iproute2.")

    result = run_command([ss, "-H", "-lntup"], check=False, timeout=15)

    if result.returncode != 0:
        raise FirewallError(result.stderr.strip() or "Failed to execute ss.")

    if result.stdout.strip():
        print(result.stdout.rstrip())
    else:
        print("No listening sockets were found.")

    print(
        "\nAn open firewall port does not guarantee that an application "
        "is listening on that port."
    )
    return 0


def cmd_allow(args: argparse.Namespace) -> int:
    require_root()
    require_ufw()

    port, protocol = parse_port_spec(args.port)

    if args.source:
        source = validate_source(args.source)
        command = [
            UFW,
            "allow",
            "from",
            source,
            "to",
            "any",
            "port",
            port,
        ]

        if protocol:
            command.extend(["proto", protocol])
    else:
        target = port + (f"/{protocol}" if protocol else "")
        command = [UFW, "allow", target]

    print("Executing:", " ".join(command))
    result = run_command(command)

    if result.stdout.strip():
        print(result.stdout.strip())

    print("Allow rule added.")
    return 0


def cmd_close(args: argparse.Namespace) -> int:
    require_root()
    require_ufw()

    port, protocol = parse_port_spec(args.port)

    if not is_ufw_active():
        print("UFW is inactive. No rules were changed.")
        return 0

    source_filter = (
        normalize_source_for_comparison(validate_source(args.source))
        if args.source
        else None
    )

    matches: list[dict] = []

    for rule in get_numbered_rules():
        if not token_matches_port(rule["port_token"], port, protocol):
            continue

        if source_filter is not None:
            existing_source = normalize_source_for_comparison(rule["source"])

            if existing_source != source_filter:
                continue

        matches.append(rule)

    if not matches:
        print("No matching inbound allow rules were found.")
        print("No other rules were changed.")
        return 0

    if args.source:
        print(
            f"The following inbound allow rules for "
            f"{validate_source(args.source)} will be removed:"
        )
    else:
        print(
            f"All matching inbound allow rules for {args.port} "
            "will be removed. DENY and REJECT rules will remain unchanged:"
        )

    for rule in matches:
        print(f"  {rule['line']}")

    ssh_ports = detect_ssh_ports()
    requested_start = int(port.split(":")[0])
    requested_end = int(port.split(":")[-1])

    overlaps_ssh = any(
        requested_start <= ssh_port <= requested_end
        for ssh_port in ssh_ports
    )

    if overlaps_ssh and not args.force:
        raise FirewallError(
            "This port may be used by SSH. To continue and risk losing "
            "remote access, repeat the command with --force."
        )

    if not args.yes:
        try:
            answer = input("Remove the listed rules? [y/N]: ").strip().lower()
        except EOFError:
            answer = ""

        if answer not in ("y", "yes"):
            print("Cancelled. No rules were changed.")
            return 0

    for rule in sorted(matches, key=lambda item: item["number"], reverse=True):
        run_command([UFW, "--force", "delete", str(rule["number"])])
        print(f"Removed rule #{rule['number']}.")

    print("Operation completed.")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    require_root()
    require_ufw()

    active = is_ufw_active()
    ssh_ports = detect_ssh_ports()

    if active:
        print("UFW is already active. Existing rules will be preserved.")
    else:
        print("UFW is inactive.")
        print("The incoming policy will be set to deny.")
        print("The outgoing policy will be set to allow.")
        print("SSH allow rules will be added.")
        print("Existing UFW rules will not be reset.")

        if not args.yes:
            try:
                answer = input("Continue with initial setup? [y/N]: ").strip().lower()
            except EOFError:
                answer = ""

            if answer not in ("y", "yes"):
                print("Setup cancelled.")
                return 0

        run_command([UFW, "default", "deny", "incoming"])
        run_command([UFW, "default", "allow", "outgoing"])

    existing_rules = get_numbered_rules()

    for ssh_port in sorted(ssh_ports):
        already_allowed = any(
            token_matches_port(rule["port_token"], str(ssh_port), "tcp")
            and rule["source"].lower() == "anywhere"
            for rule in existing_rules
        )

        if not already_allowed:
            run_command([UFW, "allow", f"{ssh_port}/tcp"])
            print(f"SSH allowed on {ssh_port}/tcp")

    if not active:
        print(
            "\nVerify that the SSH port is correct and remote access "
            "will remain available before enabling UFW."
        )
        run_command([UFW, "--force", "enable"])
        print("UFW enabled.")
    else:
        print("UFW was already active. Existing rules were preserved.")

    print("\nCurrent status:")
    print(get_ufw_status())
    return 0


def cmd_enable(args: argparse.Namespace) -> int:
    require_root()
    require_ufw()

    if is_ufw_active():
        print("UFW is already active.")
        return 0

    ssh_ports = detect_ssh_ports()
    print("Detected SSH ports:", ", ".join(map(str, sorted(ssh_ports))))
    print("Verify the SSH ports before enabling the firewall.")

    if not args.yes:
        try:
            answer = input(
                "Enable UFW without resetting rules? [y/N]: "
            ).strip().lower()
        except EOFError:
            answer = ""

        if answer not in ("y", "yes"):
            print("Cancelled.")
            return 0

    run_command([UFW, "--force", "enable"])
    print("UFW enabled.")
    print(get_ufw_status())
    return 0


def cmd_reload(_args: argparse.Namespace) -> int:
    require_root()
    require_ufw()

    run_command([UFW, "reload"])
    print("UFW rules reloaded.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "ServerGuard Firewall Manager: manage inbound UFW allow rules."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sub = subparsers.add_parser("version", help="Show version")
    sub.set_defaults(func=cmd_version)

    sub = subparsers.add_parser("status", help="Show UFW status")
    sub.set_defaults(func=cmd_status)

    sub = subparsers.add_parser("rules", help="List UFW rules")
    sub.set_defaults(func=cmd_rules)

    sub = subparsers.add_parser("listening", help="List listening network ports")
    sub.set_defaults(func=cmd_listening)

    sub = subparsers.add_parser(
        "allow",
        help="Allow a port for all addresses or a specific source",
    )
    sub.add_argument(
        "port",
        help="Port or range, e.g. 443/tcp or 8000:8100/tcp",
    )
    sub.add_argument(
        "--from",
        dest="source",
        help="Source IP address or subnet",
    )
    sub.set_defaults(func=cmd_allow)

    sub = subparsers.add_parser(
        "close",
        help="Remove matching inbound allow rules",
    )
    sub.add_argument(
        "port",
        help="Port or range, e.g. 443/tcp or 8000:8100/tcp",
    )
    sub.add_argument(
        "--from",
        dest="source",
        help="Remove allow rules only for this source IP or subnet",
    )
    sub.add_argument(
        "--force",
        action="store_true",
        help="Allow closing a port that may be used by SSH",
    )
    sub.add_argument(
        "--yes",
        action="store_true",
        help="Skip the deletion confirmation prompt",
    )
    sub.set_defaults(func=cmd_close)

    sub = subparsers.add_parser(
        "init",
        help="Initial UFW setup without resetting existing rules",
    )
    sub.add_argument(
        "--yes",
        action="store_true",
        help="Skip the setup confirmation prompt",
    )
    sub.set_defaults(func=cmd_init)

    sub = subparsers.add_parser(
        "enable",
        help="Enable UFW without resetting existing rules",
    )
    sub.add_argument(
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt",
    )
    sub.set_defaults(func=cmd_enable)

    sub = subparsers.add_parser("reload", help="Reload UFW rules")
    sub.set_defaults(func=cmd_reload)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        return args.func(args)
    except FirewallError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperation interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

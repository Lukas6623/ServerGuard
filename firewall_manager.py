#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ServerGuard Firewall Manager
Управление портами через UFW (Ubuntu) + постоянная служба systemd.

Без аргументов - локальное интерактивное меню.
Примеры:
    sudo python3 firewall_manager.py allow 8080/tcp
    sudo python3 firewall_manager.py deny 3306 --from 1.2.3.4
    sudo python3 firewall_manager.py install-service --protect 22
"""

import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import time

APP_NAME = "ServerGuard Firewall Manager"
VERSION = "2.0"

INSTALL_DIR = "/opt/serverguard"
INSTALL_PATH = INSTALL_DIR + "/firewall_manager.py"
SERVICE_NAME = "serverguard-firewall"
SERVICE_PATH = "/etc/systemd/system/%s.service" % SERVICE_NAME
CONFIG_DIR = "/etc/serverguard"
PROTECTED_FILE = CONFIG_DIR + "/protected_ports"
DAEMON_INTERVAL = 30

SPEC_RE = re.compile(r"^(\d{1,5})(?::(\d{1,5}))?(?:/(tcp|udp))?$")


# ---------------------------------------------------------------- утилиты

def run_command(args, timeout=60):
    """Запуск команды без shell. Возвращает (ok, output)."""
    try:
        r = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "Превышено время ожидания команды."
    except OSError as exc:
        return False, str(exc)

    out = (r.stdout or "").strip()
    err = (r.stderr or "").strip()

    if r.returncode != 0:
        return False, err or out or "Команда завершилась с ошибкой."

    return True, out


def require_root():
    if os.geteuid() != 0:
        print("ОШИБКА: нужны права root (sudo).")
        sys.exit(1)


def require_ufw():
    if not shutil.which("ufw"):
        print("UFW не установлен: sudo apt update && sudo apt install ufw")
        sys.exit(1)


def parse_spec(text):
    """'80', '80/tcp', '8000:8100/tcp' -> (lo, hi, proto|None)"""
    m = SPEC_RE.match(text.strip().lower())
    if not m:
        raise ValueError("Некорректный порт: %r (пример: 80, 80/tcp, 8000:8100/tcp)" % text)

    lo = int(m.group(1))
    hi = int(m.group(2)) if m.group(2) else lo
    proto = m.group(3)

    if not (1 <= lo <= 65535 and 1 <= hi <= 65535) or lo > hi:
        raise ValueError("Порт должен быть в диапазоне 1-65535 (и начало <= конец).")

    if lo != hi and proto is None:
        raise ValueError("Для диапазона нужно указать протокол: %d:%d/tcp" % (lo, hi))

    return lo, hi, proto


def spec_ports(spec):
    lo, hi, _ = spec
    return str(lo) if lo == hi else "%d:%d" % (lo, hi)


def spec_to_str(spec):
    ports = spec_ports(spec)
    return ports + ("/" + spec[2] if spec[2] else "")


def overlaps(a, b):
    if a[2] and b[2] and a[2] != b[2]:
        return False
    return a[0] <= b[1] and b[0] <= a[1]


def parse_source(text):
    if not text:
        return None
    try:
        return str(ipaddress.ip_network(text.strip(), strict=False))
    except ValueError:
        raise ValueError("Некорректный IP/подсеть: %r" % text)


def build_rule(action, spec, source=None, delete=False):
    cmd = ["ufw"]
    if delete:
        cmd += ["--force", "delete"]
    cmd.append(action)

    if source:
        cmd += ["from", source, "to", "any", "port", spec_ports(spec)]
        if spec[2]:
            cmd += ["proto", spec[2]]
    else:
        cmd.append(spec_to_str(spec))

    return cmd


# --------------------------------------------------- защищённые порты

def detect_ssh_port():
    ok, out = run_command(["ss", "-ltnp"])
    if ok:
        for line in out.splitlines():
            if "sshd" in line:
                m = re.search(r":(\d+)\s", line)
                if m:
                    return int(m.group(1))
    return 22


def load_protected():
    result = []
    try:
        with open(PROTECTED_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        result.append(parse_spec(line))
                    except ValueError:
                        pass
    except OSError:
        pass
    return result


def save_protected(items):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(PROTECTED_FILE, "w") as f:
        f.write("# Защищённые порты ServerGuard (всегда разрешены)\n")
        for s in items:
            f.write(spec_to_str(s) + "\n")
    os.chmod(PROTECTED_FILE, 0o640)


def is_protected(spec):
    return any(overlaps(spec, p) for p in load_protected())


def ufw_active():
    ok, out = run_command(["ufw", "status"])
    return ok and re.search(r"^Status:\s+active", out, re.I | re.M) is not None, out


def ensure_protected():
    """Гарантирует, что защищённые порты разрешены. Возвращает список добавленных."""
    active, status = ufw_active()
    if not active:
        return []

    added = []
    for spec in load_protected():
        ports = spec_ports(spec)
        pattern = r"^%s(/%s)?(\s+\(v6\))?\s+ALLOW" % (
            re.escape(ports), spec[2] or "(tcp|udp)")
        if not re.search(pattern, status, re.M):
            ok, _ = run_command(build_rule("allow", spec))
            if ok:
                added.append(spec_to_str(spec))
    return added


# ---------------------------------------------------------------- команды

def cmd_status(a):
    ok, out = run_command(["ufw", "status", "verbose"])
    if not ok:
        print("Ошибка:", out)
        return 1
    print(out)
    if re.search(r"^Status:\s+inactive", out, re.I | re.M):
        print("\nВНИМАНИЕ: UFW выключен - правила не фильтруют трафик.")
    return 0


def cmd_rules(a):
    ok, out = run_command(["ufw", "status", "numbered"])
    print(out if ok else "Ошибка: " + out)
    return 0 if ok else 1


def cmd_listening(a):
    if not shutil.which("ss"):
        print("Команда ss не найдена.")
        return 1
    ok, out = run_command(["ss", "-lntup"])
    print(out if ok else "Ошибка: " + out)
    if ok:
        print("\nПримечание: это прослушиваемые сокеты, а не обязательно "
              "доступные из интернета.")
    return 0 if ok else 1


def apply_rule(action, a, delete=False):
    try:
        spec = parse_spec(a.port)
        source = parse_source(a.source)
    except ValueError as exc:
        print("ОШИБКА:", exc)
        return 2

    restrictive = delete and action == "allow" or action in ("deny", "reject")
    if restrictive and is_protected(spec) and not a.force:
        print("ОТКАЗ: порт %s защищён (SSH/служба). Используй --force, "
              "если точно уверен." % spec_to_str(spec))
        return 3

    ok, out = run_command(build_rule(action, spec, source, delete))
    if ok:
        print("[OK] %s%s %s%s" % (
            "удалено: " if delete else "", action, spec_to_str(spec),
            " from " + source if source else ""))
        if out:
            print(out)
        return 0

    print("[ОШИБКА]", out)
    return 1


def cmd_allow(a):   return apply_rule("allow", a)
def cmd_deny(a):    return apply_rule("deny", a)
def cmd_reject(a):  return apply_rule("reject", a)
def cmd_limit(a):   return apply_rule("limit", a)
def cmd_close(a):   return apply_rule("allow", a, delete=True)
def cmd_unblock(a): return apply_rule("deny", a, delete=True)


def get_numbered():
    ok, out = run_command(["ufw", "status", "numbered"])
    rules = []
    if ok:
        for line in out.splitlines():
            m = re.match(r"^\[\s*(\d+)\]\s+(.*)$", line)
            if m:
                rules.append((int(m.group(1)), m.group(2)))
    return rules


def cmd_delete(a):
    rules = dict(get_numbered())
    text = rules.get(a.number)

    if text is None:
        print("Правило №%d не найдено (см. команду rules)." % a.number)
        return 2

    m = re.match(r"^(\d{1,5}(?::\d{1,5})?)(?:/(tcp|udp))?", text)
    if m and "ALLOW" in text and not a.force:
        try:
            spec = parse_spec(m.group(0))
            if is_protected(spec):
                print("ОТКАЗ: правило защищённого порта. Используй --force.")
                return 3
        except ValueError:
            pass

    ok, out = run_command(["ufw", "--force", "delete", str(a.number)])
    print("[OK] Правило №%d удалено." % a.number if ok else "[ОШИБКА] " + out)
    return 0 if ok else 1


def cmd_enable(a):
    protected = load_protected()
    if not protected:
        port = detect_ssh_port()
        protected = [(port, port, "tcp")]
        save_protected(protected)
        print("SSH-порт %d добавлен в защищённые." % port)

    for spec in protected:
        run_command(build_rule("allow", spec))

    ok, out = run_command(["ufw", "--force", "enable"])
    print("[OK] Firewall включён." if ok else "[ОШИБКА] " + out)
    return 0 if ok else 1


def cmd_disable(a):
    if not a.force:
        print("ОТКАЗ: отключение firewall требует --force.")
        return 3
    ok, out = run_command(["ufw", "disable"])
    print("[OK] Firewall выключен." if ok else "[ОШИБКА] " + out)
    return 0 if ok else 1


def cmd_default(a):
    ok, out = run_command(["ufw", "default", a.policy, a.direction])
    print(out if ok else "[ОШИБКА] " + out)
    return 0 if ok else 1


def cmd_logging(a):
    ok, out = run_command(["ufw", "logging", a.level])
    print(out if ok else "[ОШИБКА] " + out)
    return 0 if ok else 1


def cmd_reload(a):
    ok, out = run_command(["ufw", "reload"])
    print(out if ok else "[ОШИБКА] " + out)
    return 0 if ok else 1


def cmd_protect(a):
    items = load_protected()

    if a.action == "list":
        if not items:
            print("Защищённых портов нет.")
        for s in items:
            print(spec_to_str(s))
        return 0

    if not a.port:
        print("Укажи порт.")
        return 2

    try:
        spec = parse_spec(a.port)
    except ValueError as exc:
        print("ОШИБКА:", exc)
        return 2

    if a.action == "add":
        if spec[2] is None:
            spec = (spec[0], spec[1], "tcp")
        if spec_to_str(spec) not in [spec_to_str(s) for s in items]:
            items.append(spec)
        save_protected(items)
        run_command(build_rule("allow", spec))
        print("[OK] Защищён: " + spec_to_str(spec))
    else:
        items = [s for s in items if spec_to_str(s) != spec_to_str(spec)]
        save_protected(items)
        print("[OK] Защита снята: " + spec_to_str(spec))
    return 0


def cmd_version(a):
    print("%s %s" % (APP_NAME, VERSION))
    return 0


# ---------------------------------------------------------- служба systemd

UNIT = """[Unit]
Description=ServerGuard Firewall Manager
After=network.target ufw.service

[Service]
Type=simple
ExecStart={python} {path} daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def cmd_install_service(a):
    if not shutil.which("systemctl"):
        print("ОШИБКА: systemctl не найден (нужен systemd).")
        return 1

    os.makedirs(INSTALL_DIR, exist_ok=True)

    src = os.path.abspath(__file__)
    if src != INSTALL_PATH:
        shutil.copy2(src, INSTALL_PATH)
    os.chmod(INSTALL_PATH, 0o750)

    for p in a.protect or []:
        cmd_protect(argparse.Namespace(action="add", port=str(p)))

    if not load_protected():
        cmd_protect(argparse.Namespace(action="add", port=str(detect_ssh_port())))

    python = sys.executable or "/usr/bin/python3"
    with open(SERVICE_PATH, "w") as f:
        f.write(UNIT.format(python=python, path=INSTALL_PATH))

    for args in (["systemctl", "daemon-reload"],
                 ["systemctl", "enable", SERVICE_NAME],
                 ["systemctl", "restart", SERVICE_NAME]):
        ok, out = run_command(args)
        if not ok:
            print("[ОШИБКА]", " ".join(args), "->", out)
            return 1

    print("[OK] Служба %s установлена и запущена." % SERVICE_NAME)
    return 0


def cmd_uninstall_service(a):
    run_command(["systemctl", "disable", "--now", SERVICE_NAME])
    for path in (SERVICE_PATH,):
        if os.path.exists(path):
            os.remove(path)
    run_command(["systemctl", "daemon-reload"])
    shutil.rmtree(INSTALL_DIR, ignore_errors=True)
    print("[OK] Служба удалена. Правила UFW не изменялись.")
    return 0


def cmd_service_status(a):
    if not os.path.exists(INSTALL_PATH):
        print("Не установлено.")
        return 0
    _, active = run_command(["systemctl", "is-active", SERVICE_NAME])
    _, enabled = run_command(["systemctl", "is-enabled", SERVICE_NAME])
    print("Служба: %s\nАвтозапуск: %s\nВерсия файла: %s" % (active, enabled, VERSION))
    return 0


def cmd_daemon(a):
    print("%s: служба запущена (проверка каждые %d с)." % (APP_NAME, DAEMON_INTERVAL),
          flush=True)
    while True:
        try:
            added = ensure_protected()
            if added:
                print("Восстановлены защищённые правила: " + ", ".join(added), flush=True)
        except Exception as exc:
            print("Ошибка цикла:", exc, flush=True)
        time.sleep(DAEMON_INTERVAL)


# ---------------------------------------------------------- локальное меню

def interactive_menu():
    while True:
        print("=" * 46)
        print("       " + APP_NAME)
        print("=" * 46)
        print("1. Открыть порт\n2. Закрыть порт\n3. Состояние\n"
              "4. Правила\n5. Прослушиваемые порты\n0. Выход")
        choice = input("Выбери действие: ").strip()

        if choice in ("1", "2"):
            port = input("Порт (80, 80/tcp, 8000:8100/tcp): ").strip()
            ns = argparse.Namespace(port=port, source=None, force=False)
            (cmd_allow if choice == "1" else cmd_close)(ns)
        elif choice == "3":
            cmd_status(None)
        elif choice == "4":
            cmd_rules(None)
        elif choice == "5":
            cmd_listening(None)
        elif choice == "0":
            return
        input("\nEnter для продолжения...")


# ---------------------------------------------------------------- main

def build_parser():
    p = argparse.ArgumentParser(prog="firewall_manager.py", description=APP_NAME)
    sub = p.add_subparsers(dest="cmd")

    def rule_cmd(name, func, help_):
        s = sub.add_parser(name, help=help_)
        s.add_argument("port")
        s.add_argument("--from", dest="source", default=None)
        s.add_argument("--force", action="store_true")
        s.set_defaults(func=func)

    rule_cmd("allow", cmd_allow, "открыть порт")
    rule_cmd("deny", cmd_deny, "заблокировать порт (drop)")
    rule_cmd("reject", cmd_reject, "заблокировать порт (с ответом)")
    rule_cmd("limit", cmd_limit, "открыть с защитой от брутфорса")
    rule_cmd("close", cmd_close, "удалить разрешающее правило")
    rule_cmd("unblock", cmd_unblock, "удалить блокирующее правило")

    for name, func in (("status", cmd_status), ("rules", cmd_rules),
                       ("listening", cmd_listening), ("enable", cmd_enable),
                       ("reload", cmd_reload), ("version", cmd_version),
                       ("daemon", cmd_daemon),
                       ("uninstall-service", cmd_uninstall_service),
                       ("service-status", cmd_service_status)):
        sub.add_parser(name).set_defaults(func=func)

    s = sub.add_parser("disable")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_disable)

    s = sub.add_parser("delete")
    s.add_argument("number", type=int)
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_delete)

    s = sub.add_parser("default")
    s.add_argument("direction", choices=("incoming", "outgoing", "routed"))
    s.add_argument("policy", choices=("allow", "deny", "reject"))
    s.set_defaults(func=cmd_default)

    s = sub.add_parser("logging")
    s.add_argument("level", choices=("on", "off", "low", "medium", "high", "full"))
    s.set_defaults(func=cmd_logging)

    s = sub.add_parser("protect")
    s.add_argument("action", choices=("list", "add", "remove"))
    s.add_argument("port", nargs="?")
    s.set_defaults(func=cmd_protect)

    s = sub.add_parser("install-service")
    s.add_argument("--protect", action="append", type=int)
    s.set_defaults(func=cmd_install_service)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.cmd == "version":
        return cmd_version(args)

    require_root()
    require_ufw()

    if not args.cmd:
        interactive_menu()
        return 0

    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nРабота завершена.")

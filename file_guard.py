
#!/usr/bin/env python3
# ServerGuard FileGuard
# Version 1.2.0

import ctypes
import ctypes.util
import hashlib
import json
import os
import select
import signal
import stat
import struct
import sys
import time

from datetime import datetime, timezone


BASE_DIR = "/opt/serverguard"
DATA_DIR = os.path.join(BASE_DIR, "data")

BASELINE_FILE = os.path.join(DATA_DIR, "fileguard_baseline.json")
STATE_FILE = os.path.join(DATA_DIR, "fileguard_state.json")
EVENTS_FILE = os.path.join(DATA_DIR, "file_events.json")

WATCH_DIRECTORIES = (
    "/etc/ssh",
    "/etc/sudoers.d",
    "/etc/systemd/system",
    "/etc/cron.d",
    "/var/spool/cron",
    "/etc/pam.d",
)

PROTECTED_FILES = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/crontab",
    "/etc/ssh/sshd_config",
)

CRITICAL_FILES = set(PROTECTED_FILES)

IGNORED_FILES = {
    "/opt/serverguard/data/blocked_ips.json",
    "/opt/serverguard/data/ssh_events.json",
    "/opt/serverguard/data/ip_stats.json",
    "/opt/serverguard/data/file_events.json",
    "/opt/serverguard/data/fileguard_baseline.json",
    "/opt/serverguard/data/fileguard_state.json",
    "/opt/serverguard/telegram/seen_blocks.json",
    "/opt/serverguard/telegram/seen_events.json",
    "/opt/serverguard/telegram/seen_file_events.json",
    "/opt/serverguard/telegram/verification.json",
    "/opt/serverguard/telegram/owner.json",
    "/opt/serverguard/telegram/seen_blocks.json.tmp",
    "/opt/serverguard/telegram/seen_events.json.tmp",
    "/opt/serverguard/telegram/seen_file_events.json.tmp",
    "/opt/serverguard/telegram/verification.json.tmp",
    "/opt/serverguard/telegram/owner.json.tmp",
}

IGNORED_DIRECTORIES = {
    "/opt/serverguard",
}

IGNORED_EXTENSIONS = (
    ".tmp",
    ".temp",
    ".swp",
    ".swo",
    ".bak",
)

MAX_HASH_SIZE = 50 * 1024 * 1024
MAX_EVENTS = 1000
EVENT_DEDUP_SECONDS = 10
STATE_SAVE_INTERVAL = 30
WATCH_REFRESH_INTERVAL = 60

IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_ISDIR = 0x40000000
IN_IGNORED = 0x00008000

WATCH_MASK = (
    IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
)

INOTIFY_EVENT_STRUCT = struct.Struct("iIII")

running = True
inotify_fd = -1
libc = None

watch_descriptors = {}
descriptor_paths = {}

baseline = {}
current_state = {}
last_events = {}

last_state_save = 0
last_watch_refresh = 0


def signal_handler(signum, frame):
    global running
    running = False


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def normalize_path(path):
    return os.path.abspath(os.path.normpath(path))


def ensure_data_directory():
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    os.chmod(DATA_DIR, 0o700)


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        return default
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[WARNING] Cannot read {path}: {exc}", flush=True)
        return default


def save_json(path, data):
    temporary = path + ".tmp"

    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)

        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(temporary, flags, 0o600)

        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2, ensure_ascii=False)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())

        os.replace(temporary, path)
        os.chmod(path, 0o600)
        return True

    except (OSError, TypeError, ValueError) as exc:
        print(f"[ERROR] Cannot save {path}: {exc}", flush=True)

        try:
            os.remove(temporary)
        except OSError:
            pass

        return False


def is_ignored_extension(path):
    name = os.path.basename(path).lower()
    return name.endswith(IGNORED_EXTENSIONS)


def is_ignored_directory(path):
    path = normalize_path(path)

    for directory in IGNORED_DIRECTORIES:
        directory = normalize_path(directory)

        try:
            if os.path.commonpath((path, directory)) == directory:
                return True
        except ValueError:
            continue

    return False


def is_ignored_path(path):
    path = normalize_path(path)

    if is_ignored_extension(path):
        return True

    if is_ignored_directory(path):
        return True

    return path in {normalize_path(item) for item in IGNORED_FILES}


def is_protected_path(path):
    path = normalize_path(path)

    if is_ignored_path(path):
        return False

    if path in PROTECTED_FILES:
        return True

    for directory in WATCH_DIRECTORIES:
        directory = normalize_path(directory)

        try:
            if os.path.commonpath((path, directory)) == directory:
                return True
        except ValueError:
            continue

    return False


def calculate_sha256(path):
    try:
        file_stat = os.stat(path)

        if not stat.S_ISREG(file_stat.st_mode):
            return None

        if file_stat.st_size > MAX_HASH_SIZE:
            return None

        digest = hashlib.sha256()

        with open(path, "rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)

        return digest.hexdigest()

    except OSError:
        return None


def get_file_state(path):
    path = normalize_path(path)

    if is_ignored_path(path):
        return {"ignored": True}

    try:
        file_stat = os.stat(path)
        regular_file = stat.S_ISREG(file_stat.st_mode)

        if stat.S_ISDIR(file_stat.st_mode):
            file_type = "directory"
        elif regular_file:
            file_type = "file"
        else:
            file_type = "other"

        return {
            "exists": True,
            "type": file_type,
            "size": file_stat.st_size,
            "mode": oct(stat.S_IMODE(file_stat.st_mode)),
            "uid": file_stat.st_uid,
            "gid": file_stat.st_gid,
            "sha256": calculate_sha256(path) if regular_file else None,
        }

    except OSError:
        return {"exists": False}


def get_severity(path, event_type):
    path = normalize_path(path)

    if path in CRITICAL_FILES:
        return "CRITICAL"

    high_risk_directories = (
        "/etc/ssh/",
        "/etc/sudoers.d/",
        "/etc/systemd/system/",
        "/etc/cron.d/",
        "/var/spool/cron/",
        "/etc/pam.d/",
    )

    if path.startswith(high_risk_directories):
        return "HIGH"

    return "MEDIUM"


def event_signature(path, event_type, state):
    state = state or {}

    return (
        f"{path}|{event_type}|"
        f"{state.get('sha256', '')}|"
        f"{state.get('mode', '')}|"
        f"{state.get('uid', '')}|"
        f"{state.get('gid', '')}|"
        f"{state.get('exists', '')}"
    )


def should_report_event(path, event_type, state):
    now = time.monotonic()
    signature = event_signature(path, event_type, state)
    previous = last_events.get(signature)

    if previous is not None and now - previous < EVENT_DEDUP_SECONDS:
        return False

    last_events[signature] = now

    if len(last_events) > MAX_EVENTS * 2:
        cutoff = now - EVENT_DEDUP_SECONDS
        for key, timestamp in list(last_events.items()):
            if timestamp < cutoff:
                del last_events[key]

    return True


def append_event(path, event_type, old_state, new_state):
    events = load_json(EVENTS_FILE, [])

    if not isinstance(events, list):
        events = []

    event = {
        "timestamp": utc_now(),
        "type": event_type,
        "severity": get_severity(path, event_type),
        "path": path,
        "old_state": old_state,
        "new_state": new_state,
    }

    events.append(event)
    events = events[-MAX_EVENTS:]

    save_json(EVENTS_FILE, events)
    return event


def print_event(event):
    print("\n" + "=" * 52, flush=True)
    print(f"[FILEGUARD] {event['severity']}", flush=True)
    print(f"Time:  {event['timestamp']}", flush=True)
    print(f"Event: {event['type']}", flush=True)
    print(f"File:  {event['path']}", flush=True)

    old_state = event.get("old_state") or {}
    new_state = event.get("new_state") or {}

    if old_state:
        print(f"Old SHA256: {old_state.get('sha256')}", flush=True)
        print(f"Old mode:   {old_state.get('mode')}", flush=True)

    if new_state:
        print(f"New SHA256: {new_state.get('sha256')}", flush=True)
        print(f"New mode:   {new_state.get('mode')}", flush=True)

    print("=" * 52 + "\n", flush=True)


def process_file_event(path, event_type):
    path = normalize_path(path)

    if not is_protected_path(path):
        return

    old_state = current_state.get(path)

    if event_type == "deleted":
        new_state = {"exists": False}
    else:
        new_state = get_file_state(path)

        if new_state.get("ignored") or not new_state.get("exists"):
            if event_type == "created":
                return

            if event_type in ("modified", "permissions_changed"):
                if not new_state.get("exists"):
                    event_type = "deleted"
                    new_state = {"exists": False}
                else:
                    return

    if event_type == "modified" and old_state == new_state:
        return

    if (
        event_type == "modified"
        and old_state
        and old_state.get("sha256") == new_state.get("sha256")
        and old_state.get("mode") != new_state.get("mode")
    ):
        event_type = "permissions_changed"

    if not should_report_event(path, event_type, new_state):
        current_state[path] = new_state
        return

    event = append_event(path, event_type, old_state, new_state)
    current_state[path] = new_state
    print_event(event)


def scan_directory(directory):
    result = {}

    if not os.path.isdir(directory):
        return result

    for root, dirs, files in os.walk(
        directory,
        topdown=True,
        followlinks=False,
    ):
        root = normalize_path(root)

        dirs[:] = [
            name
            for name in dirs
            if not os.path.islink(os.path.join(root, name))
            and not is_ignored_directory(os.path.join(root, name))
        ]

        for name in files:
            path = normalize_path(os.path.join(root, name))

            if os.path.islink(path) or not is_protected_path(path):
                continue

            state = get_file_state(path)

            if state.get("exists"):
                result[path] = state

    return result


def build_initial_baseline():
    result = {}

    for path in PROTECTED_FILES:
        path = normalize_path(path)
        state = get_file_state(path)

        if state.get("exists"):
            result[path] = state

    for directory in WATCH_DIRECTORIES:
        directory = normalize_path(directory)

        try:
            result.update(scan_directory(directory))
        except OSError as exc:
            print(f"[WARNING] Cannot scan {directory}: {exc}", flush=True)

    print(f"[FileGuard] Initial baseline: {len(result)} files.", flush=True)
    return result


def clean_state(data):
    if not isinstance(data, dict):
        return {}

    cleaned = {}

    for path, state in data.items():
        path = normalize_path(path)

        if is_protected_path(path) and isinstance(state, dict):
            cleaned[path] = state

    return cleaned


def initialize_baseline():
    global baseline, current_state

    if os.path.exists(BASELINE_FILE):
        try:
            with open(BASELINE_FILE, "r", encoding="utf-8") as file:
                stored_baseline = json.load(file)

            if not isinstance(stored_baseline, dict):
                raise ValueError("Baseline must be a JSON object")

            baseline = clean_state(stored_baseline)

            if stored_baseline and not baseline:
                raise RuntimeError(
                    "Existing baseline contains no valid monitored paths. "
                    "It was not replaced automatically."
                )

            if not baseline:
                baseline = build_initial_baseline()

            if not save_json(BASELINE_FILE, baseline):
                raise RuntimeError("Could not save cleaned baseline")

        except (OSError, json.JSONDecodeError, ValueError, RuntimeError) as exc:
            raise RuntimeError(
                f"Cannot safely initialize baseline: {exc}"
            ) from exc
    else:
        baseline = build_initial_baseline()

        if not save_json(BASELINE_FILE, baseline):
            raise RuntimeError("Could not create initial baseline")

    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as file:
                stored_state = json.load(file)

            if not isinstance(stored_state, dict):
                raise ValueError("State file must be a JSON object")

            current_state = clean_state(stored_state)

        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(
                f"[WARNING] State file could not be loaded: {exc}. "
                "Using baseline state.",
                flush=True,
            )
            current_state = dict(baseline)
    else:
        current_state = dict(baseline)

    print(
        f"[FileGuard] Baseline contains {len(baseline)} files; "
        f"runtime state contains {len(current_state)} entries.",
        flush=True,
    )


def load_inotify():
    global libc

    library_name = ctypes.util.find_library("c")

    if not library_name:
        raise RuntimeError("Could not locate libc")

    libc = ctypes.CDLL(library_name, use_errno=True)

    libc.inotify_init1.argtypes = [ctypes.c_int]
    libc.inotify_init1.restype = ctypes.c_int

    libc.inotify_add_watch.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint32,
    ]
    libc.inotify_add_watch.restype = ctypes.c_int

    libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
    libc.inotify_rm_watch.restype = ctypes.c_int


def add_watch(path):
    path = normalize_path(path)

    if is_ignored_directory(path) or not os.path.isdir(path):
        return

    if path in descriptor_paths:
        return

    wd = libc.inotify_add_watch(
        inotify_fd,
        os.fsencode(path),
        WATCH_MASK,
    )

    if wd < 0:
        error = ctypes.get_errno()
        print(
            f"[WARNING] Cannot watch {path}: "
            f"{os.strerror(error)}",
            flush=True,
        )
        return

    previous_path = watch_descriptors.get(wd)

    if previous_path and previous_path != path:
        descriptor_paths.pop(previous_path, None)

    watch_descriptors[wd] = path
    descriptor_paths[path] = wd


def add_recursive_watches(directory):
    directory = normalize_path(directory)

    if is_ignored_directory(directory) or not os.path.isdir(directory):
        return

    add_watch(directory)

    for root, dirs, _ in os.walk(
        directory,
        topdown=True,
        followlinks=False,
    ):
        root = normalize_path(root)

        dirs[:] = [
            name
            for name in dirs
            if not os.path.islink(os.path.join(root, name))
            and not is_ignored_directory(os.path.join(root, name))
        ]

        for name in dirs:
            add_watch(os.path.join(root, name))


def refresh_watches():
    global last_watch_refresh

    for wd, path in list(watch_descriptors.items()):
        if not os.path.isdir(path):
            try:
                libc.inotify_rm_watch(inotify_fd, wd)
            except OSError:
                pass

            watch_descriptors.pop(wd, None)
            descriptor_paths.pop(path, None)

    for directory in WATCH_DIRECTORIES:
        add_recursive_watches(directory)

    last_watch_refresh = time.monotonic()


def initialize_inotify():
    global inotify_fd

    load_inotify()

    inotify_fd = libc.inotify_init1(os.O_NONBLOCK)

    if inotify_fd < 0:
        error = ctypes.get_errno()
        raise RuntimeError(f"inotify_init1 failed: {os.strerror(error)}")

    refresh_watches()

    print(
        f"[FileGuard] Watching {len(watch_descriptors)} directories.",
        flush=True,
    )


def check_protected_files():
    for path in PROTECTED_FILES:
        path = normalize_path(path)
        old_state = current_state.get(path)
        new_state = get_file_state(path)

        if new_state.get("ignored"):
            continue

        if old_state is None:
            if new_state.get("exists"):
                process_file_event(path, "created")
            else:
                current_state[path] = new_state
            continue

        if old_state != new_state:
            if not new_state.get("exists"):
                process_file_event(path, "deleted")
            else:
                process_file_event(path, "modified")


def read_inotify_events():
    try:
        data = os.read(inotify_fd, 1024 * 1024)
    except BlockingIOError:
        return
    except OSError as exc:
        print(f"[WARNING] inotify read failed: {exc}", flush=True)
        return

    offset = 0

    while offset + INOTIFY_EVENT_STRUCT.size <= len(data):
        wd, mask, cookie, name_length = INOTIFY_EVENT_STRUCT.unpack_from(
            data,
            offset,
        )
        offset += INOTIFY_EVENT_STRUCT.size

        raw_name = data[offset:offset + name_length]
        offset += name_length

        name = raw_name.split(b"\0", 1)[0].decode(
            "utf-8",
            errors="replace",
        )

        directory = watch_descriptors.get(wd)

        if directory is None:
            continue

        path = normalize_path(
            os.path.join(directory, name) if name else directory
        )

        if mask & IN_IGNORED:
            old_path = watch_descriptors.pop(wd, None)

            if old_path:
                descriptor_paths.pop(old_path, None)

            continue

        if is_ignored_path(path):
            continue

        if not is_protected_path(path):
            continue

        if mask & IN_ISDIR:
            if mask & (IN_CREATE | IN_MOVED_TO):
                add_recursive_watches(path)
            continue

        if mask & (IN_CREATE | IN_MOVED_TO):
            process_file_event(path, "created")
        elif mask & (IN_DELETE | IN_MOVED_FROM):
            process_file_event(path, "deleted")
        elif mask & (IN_MODIFY | IN_CLOSE_WRITE):
            process_file_event(path, "modified")
        elif mask & IN_ATTRIB:
            process_file_event(path, "permissions_changed")


def save_state(force=False):
    global last_state_save

    now = time.monotonic()

    if not force and now - last_state_save < STATE_SAVE_INTERVAL:
        return

    cleaned = clean_state(current_state)

    if save_json(STATE_FILE, cleaned):
        last_state_save = now


def start():
    global running

    ensure_data_directory()

    print("=" * 52)
    print("ServerGuard FileGuard 1.2.0")
    print("Mode: system configuration monitoring")
    print(f"Baseline: {BASELINE_FILE}")
    print(f"State:    {STATE_FILE}")
    print(f"Events:   {EVENTS_FILE}")
    print()
    print("Ignored: /opt/serverguard and its contents")
    print("Monitoring directories:")

    for directory in WATCH_DIRECTORIES:
        print(f"  - {directory}")

    print()

    initialize_baseline()

    try:
        initialize_inotify()
    except Exception as exc:
        print(f"[CRITICAL] Cannot initialize FileGuard: {exc}", flush=True)
        return 1

    print("[OK] FileGuard is active.", flush=True)
    print("[OK] Waiting for filesystem events.", flush=True)

    try:
        while running:
            readable, _, _ = select.select(
                [inotify_fd],
                [],
                [],
                5,
            )

            if readable:
                read_inotify_events()

            check_protected_files()

            now = time.monotonic()

            if now - last_watch_refresh >= WATCH_REFRESH_INTERVAL:
                refresh_watches()

            save_state()

    except KeyboardInterrupt:
        running = False
    except Exception as exc:
        print(f"[ERROR] FileGuard main loop: {exc}", flush=True)
        return 1
    finally:
        if inotify_fd >= 0:
            try:
                os.close(inotify_fd)
            except OSError:
                pass

        save_state(force=True)
        print("[FileGuard] Stopped.", flush=True)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(start())
    except Exception as exc:
        print(f"[CRITICAL] FileGuard crashed: {exc}", flush=True)
        sys.exit(1)

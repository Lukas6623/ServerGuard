
#!/usr/bin/env python3

import os
import sys
import json
import time
import stat
import hashlib
import ctypes
import ctypes.util
import struct
import select
import signal
from pathlib import Path
from datetime import datetime, timezone


# ============================================================
# SERVERGUARD FILEGUARD
# ============================================================

BASE_DIR = "/opt/serverguard"

DATA_DIR = os.path.join(
    BASE_DIR,
    "data"
)

BASELINE_FILE = os.path.join(
    DATA_DIR,
    "fileguard_baseline.json"
)

STATE_FILE = os.path.join(
    DATA_DIR,
    "fileguard_state.json"
)

EVENTS_FILE = os.path.join(
    DATA_DIR,
    "file_events.json"
)


# ============================================================
# SETTINGS
# ============================================================

# Directories that should be monitored.
#
# These are intentionally limited to security-sensitive
# locations so FileGuard remains lightweight on weak VPS.
#
WATCH_DIRECTORIES = [
    "/etc/ssh",
    "/etc/sudoers.d",
    "/etc/systemd/system",
    "/etc/cron.d",
    "/var/spool/cron",
    "/opt/serverguard",
]


# Individual important files.
#
# These are monitored even if their parent directory is not
# recursively available.
#
PROTECTED_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/crontab",
    "/etc/ssh/sshd_config",
]


# Maximum file size for SHA-256 calculation.
#
# We don't want FileGuard to accidentally hash a multi-GB file.
MAX_HASH_SIZE = 50 * 1024 * 1024


# How many events can be kept in file_events.json.
MAX_EVENTS = 1000


# Avoid sending the exact same event repeatedly.
EVENT_DEDUP_SECONDS = 10


# How often state is written to disk.
STATE_SAVE_INTERVAL = 30


# ============================================================
# CRITICAL FILES
# ============================================================

CRITICAL_FILES = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
}


# ============================================================
# INOTIFY CONSTANTS
# ============================================================

IN_ACCESS = 0x00000001
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


# Linux inotify_event structure:
#
# int      wd
# uint32_t mask
# uint32_t cookie
# uint32_t len
#
# Followed by name[len]
#
INOTIFY_EVENT_STRUCT = struct.Struct(
    "iIII"
)


# ============================================================
# GLOBAL STATE
# ============================================================

running = True

inotify_fd = -1

watch_descriptors = {}

descriptor_paths = {}

baseline = {}

current_state = {}

last_events = {}

last_state_save = 0


# ============================================================
# SIGNAL HANDLERS
# ============================================================

def signal_handler(signum, frame):
    global running

    print(
        "\n[FileGuard] Stopping..."
    )

    running = False


signal.signal(
    signal.SIGTERM,
    signal_handler
)

signal.signal(
    signal.SIGINT,
    signal_handler
)


# ============================================================
# DIRECTORY CREATION
# ============================================================

def ensure_data_directory():
    os.makedirs(
        DATA_DIR,
        mode=0o700,
        exist_ok=True
    )


# ============================================================
# TIME
# ============================================================

def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# JSON
# ============================================================

def load_json(path, default):
    try:
        if not os.path.exists(path):
            return default

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as f:
            return json.load(f)

    except Exception as e:
        print(
            f"[WARNING] Failed to read {path}: {e}"
        )

        return default


def save_json(path, data):
    temporary = path + ".tmp"

    try:
        with open(
            temporary,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                data,
                f,
                indent=2,
                ensure_ascii=False
            )

            f.write("\n")

        os.chmod(
            temporary,
            0o600
        )

        os.replace(
            temporary,
            path
        )

        return True

    except Exception as e:
        print(
            f"[ERROR] Failed to save {path}: {e}"
        )

        try:
            if os.path.exists(temporary):
                os.remove(temporary)
        except Exception:
            pass

        return False


# ============================================================
# SHA256
# ============================================================

def calculate_sha256(path):
    try:
        st = os.stat(path)

        if not stat.S_ISREG(st.st_mode):
            return None

        if st.st_size > MAX_HASH_SIZE:
            return None

        sha256 = hashlib.sha256()

        with open(
            path,
            "rb"
        ) as f:

            while True:
                chunk = f.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                sha256.update(
                    chunk
                )

        return sha256.hexdigest()

    except (
        FileNotFoundError,
        PermissionError,
        OSError
    ):
        return None


# ============================================================
# FILE INFORMATION
# ============================================================

def get_file_state(path):
    try:
        st = os.stat(path)

        mode = stat.S_IMODE(
            st.st_mode
        )

        is_regular = stat.S_ISREG(
            st.st_mode
        )

        sha256 = None

        if is_regular:
            sha256 = calculate_sha256(
                path
            )

        return {
            "exists": True,
            "type": (
                "file"
                if is_regular
                else "directory"
                if stat.S_ISDIR(st.st_mode)
                else "other"
            ),
            "size": st.st_size,
            "mode": oct(mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "sha256": sha256,
        }

    except (
        FileNotFoundError,
        PermissionError,
        OSError
    ):
        return {
            "exists": False
        }


# ============================================================
# SHOULD MONITOR
# ============================================================

def is_protected_path(path):
    path = os.path.abspath(path)

    if path in PROTECTED_FILES:
        return True

    for directory in WATCH_DIRECTORIES:
        directory = os.path.abspath(
            directory
        )

        try:
            if os.path.commonpath(
                [path, directory]
            ) == directory:

                return True

        except ValueError:
            pass

    return False


# ============================================================
# CRITICALITY
# ============================================================

def get_severity(path, event_type):
    path = os.path.abspath(path)

    if path in CRITICAL_FILES:
        return "CRITICAL"

    if event_type in (
        "deleted",
        "created"
    ):
        if (
            path.startswith(
                "/etc/systemd/system/"
            )
            or
            path.startswith(
                "/etc/cron.d/"
            )
            or
            path.startswith(
                "/etc/sudoers.d/"
            )
        ):
            return "HIGH"

    if (
        path.startswith(
            "/etc/ssh/"
        )
        or
        path.startswith(
            "/etc/sudoers.d/"
        )
        or
        path.startswith(
            "/etc/systemd/system/"
        )
        or
        path.startswith(
            "/etc/cron.d/"
        )
    ):
        return "HIGH"

    return "MEDIUM"


# ============================================================
# EVENT DEDUPLICATION
# ============================================================

def event_signature(path, event_type, state):
    sha256 = ""

    if state:
        sha256 = state.get(
            "sha256",
            ""
        ) or ""

    mode = ""

    if state:
        mode = state.get(
            "mode",
            ""
        ) or ""

    return (
        f"{path}|"
        f"{event_type}|"
        f"{sha256}|"
        f"{mode}"
    )


def should_report_event(
    path,
    event_type,
    state
):
    signature = event_signature(
        path,
        event_type,
        state
    )

    now = time.time()

    previous = last_events.get(
        signature
    )

    if previous is not None:

        if (
            now - previous
            < EVENT_DEDUP_SECONDS
        ):
            return False

    last_events[
        signature
    ] = now

    return True


# ============================================================
# EVENT STORAGE
# ============================================================

def append_event(
    path,
    event_type,
    severity,
    old_state,
    new_state
):
    events = load_json(
        EVENTS_FILE,
        []
    )

    if not isinstance(
        events,
        list
    ):
        events = []

    event = {
        "timestamp": utc_now(),
        "type": event_type,
        "severity": severity,
        "path": path,
        "old_state": old_state,
        "new_state": new_state,
    }

    events.append(
        event
    )

    if len(events) > MAX_EVENTS:
        events = events[
            -MAX_EVENTS:
        ]

    save_json(
        EVENTS_FILE,
        events
    )

    return event


# ============================================================
# CONSOLE EVENT
# ============================================================

def print_event(event):
    severity = event.get(
        "severity",
        "UNKNOWN"
    )

    event_type = event.get(
        "type",
        "unknown"
    )

    path = event.get(
        "path",
        ""
    )

    timestamp = event.get(
        "timestamp",
        ""
    )

    print(
        "\n"
        "=================================================="
    )

    print(
        f"[FILEGUARD] {severity}"
    )

    print(
        f"Time:   {timestamp}"
    )

    print(
        f"Event:  {event_type}"
    )

    print(
        f"File:   {path}"
    )

    old_state = event.get(
        "old_state"
    )

    new_state = event.get(
        "new_state"
    )

    if old_state:
        print(
            f"Old SHA256: "
            f"{old_state.get('sha256')}"
        )

        print(
            f"Old mode:   "
            f"{old_state.get('mode')}"
        )

    if new_state:
        print(
            f"New SHA256: "
            f"{new_state.get('sha256')}"
        )

        print(
            f"New mode:   "
            f"{new_state.get('mode')}"
        )

    print(
        "==================================================\n"
    )


# ============================================================
# PROCESS FILE EVENT
# ============================================================

def process_file_event(
    path,
    event_type
):
    path = os.path.abspath(
        path
    )

    if not is_protected_path(
        path
    ):
        return

    old_state = current_state.get(
        path
    )

    # --------------------------------------------------------
    # CREATED
    # --------------------------------------------------------

    if event_type == "created":

        new_state = get_file_state(
            path
        )

        if not new_state.get(
            "exists",
            False
        ):
            return

        if not should_report_event(
            path,
            "created",
            new_state
        ):
            current_state[
                path
            ] = new_state

            return

        severity = get_severity(
            path,
            "created"
        )

        event = append_event(
            path,
            "created",
            severity,
            old_state,
            new_state
        )

        current_state[
            path
        ] = new_state

        print_event(
            event
        )

        return


    # --------------------------------------------------------
    # DELETED
    # --------------------------------------------------------

    if event_type == "deleted":

        new_state = {
            "exists": False
        }

        if not should_report_event(
            path,
            "deleted",
            new_state
        ):
            current_state[
                path
            ] = new_state

            return

        severity = get_severity(
            path,
            "deleted"
        )

        event = append_event(
            path,
            "deleted",
            severity,
            old_state,
            new_state
        )

        current_state[
            path
        ] = new_state

        print_event(
            event
        )

        return


    # --------------------------------------------------------
    # MODIFIED
    # --------------------------------------------------------

    if event_type in (
        "modified",
        "permissions_changed"
    ):

        new_state = get_file_state(
            path
        )

        if not new_state.get(
            "exists",
            False
        ):
            return

        # Nothing actually changed.
        if old_state == new_state:
            return

        # ----------------------------------------------------
        # Determine whether content or permissions changed.
        # ----------------------------------------------------

        if (
            event_type == "modified"
            and
            old_state
            and
            old_state.get(
                "sha256"
            ) == new_state.get(
                "sha256"
            )
            and
            old_state.get(
                "mode"
            ) != new_state.get(
                "mode"
            )
        ):
            event_type = (
                "permissions_changed"
            )


        if not should_report_event(
            path,
            event_type,
            new_state
        ):
            current_state[
                path
            ] = new_state

            return


        severity = get_severity(
            path,
            event_type
        )

        event = append_event(
            path,
            event_type,
            severity,
            old_state,
            new_state
        )

        current_state[
            path
        ] = new_state

        print_event(
            event
        )

        return


# ============================================================
# INITIAL BASELINE
# ============================================================

def build_initial_baseline():
    print(
        "[FileGuard] Building initial baseline..."
    )

    result = {}

    # --------------------------------------------------------
    # Individual files
    # --------------------------------------------------------

    for path in PROTECTED_FILES:

        path = os.path.abspath(
            path
        )

        state = get_file_state(
            path
        )

        if state.get(
            "exists",
            False
        ):
            result[
                path
            ] = state


    # --------------------------------------------------------
    # Protected directories
    # --------------------------------------------------------

    for directory in WATCH_DIRECTORIES:

        if not os.path.exists(
            directory
        ):
            continue

        try:
            for root, dirs, files in os.walk(
                directory,
                topdown=True,
                followlinks=False
            ):

                # Never follow dangerous links.
                dirs[:] = [
                    d
                    for d in dirs
                    if not os.path.islink(
                        os.path.join(
                            root,
                            d
                        )
                    )
                ]

                for filename in files:

                    path = os.path.join(
                        root,
                        filename
                    )

                    if os.path.islink(
                        path
                    ):
                        continue

                    state = get_file_state(
                        path
                    )

                    if state.get(
                        "exists",
                        False
                    ):
                        result[
                            os.path.abspath(path)
                        ] = state

        except Exception as e:
            print(
                f"[WARNING] Failed to scan "
                f"{directory}: {e}"
            )


    print(
        f"[FileGuard] Baseline contains "
        f"{len(result)} files."
    )

    return result


# ============================================================
# INITIALIZE BASELINE
# ============================================================

def initialize_baseline():
    global baseline
    global current_state

    if os.path.exists(
        BASELINE_FILE
    ):

        print(
            "[FileGuard] Existing baseline found."
        )

        baseline = load_json(
            BASELINE_FILE,
            {}
        )

        if not isinstance(
            baseline,
            dict
        ):
            baseline = {}

    else:

        baseline = build_initial_baseline()

        save_json(
            BASELINE_FILE,
            baseline
        )


    current_state = dict(
        baseline
    )


# ============================================================
# INOTIFY LIBRARY
# ============================================================

def load_inotify():
    global libc

    libc_name = ctypes.util.find_library(
        "c"
    )

    if not libc_name:
        raise RuntimeError(
            "Could not find libc."
        )

    libc = ctypes.CDLL(
        libc_name,
        use_errno=True
    )

    libc.inotify_init1.argtypes = [
        ctypes.c_int
    ]

    libc.inotify_init1.restype = (
        ctypes.c_int
    )

    libc.inotify_add_watch.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint32
    ]

    libc.inotify_add_watch.restype = (
        ctypes.c_int
    )

    libc.inotify_rm_watch.argtypes = [
        ctypes.c_int,
        ctypes.c_int
    ]

    libc.inotify_rm_watch.restype = (
        ctypes.c_int
    )


# ============================================================
# ADD WATCH
# ============================================================

def add_watch(path):
    global inotify_fd

    if not os.path.isdir(
        path
    ):
        return

    try:
        wd = libc.inotify_add_watch(
            inotify_fd,
            path.encode(),
            WATCH_MASK
        )

        if wd < 0:
            return

        watch_descriptors[
            wd
        ] = path

        descriptor_paths[
            path
        ] = wd

    except Exception as e:
        print(
            f"[WARNING] Failed to watch "
            f"{path}: {e}"
        )


# ============================================================
# ADD RECURSIVE WATCHES
# ============================================================

def add_recursive_watches(directory):
    if not os.path.isdir(
        directory
    ):
        return

    add_watch(
        directory
    )

    try:
        for root, dirs, files in os.walk(
            directory,
            topdown=True,
            followlinks=False
        ):

            dirs[:] = [
                d
                for d in dirs
                if not os.path.islink(
                    os.path.join(
                        root,
                        d
                    )
                )
            ]

            for directory_name in dirs:

                full_path = os.path.join(
                    root,
                    directory_name
                )

                add_watch(
                    full_path
                )

    except Exception as e:
        print(
            f"[WARNING] Failed recursive "
            f"watch for {directory}: {e}"
        )


# ============================================================
# INITIALIZE INOTIFY
# ============================================================

def initialize_inotify():
    global inotify_fd

    load_inotify()

    # IN_NONBLOCK = 0x800
    inotify_fd = libc.inotify_init1(
        0x800
    )

    if inotify_fd < 0:
        errno = ctypes.get_errno()

        raise RuntimeError(
            f"inotify_init1 failed: "
            f"errno={errno}"
        )


    for directory in WATCH_DIRECTORIES:

        add_recursive_watches(
            directory
        )


    print(
        f"[FileGuard] Watching "
        f"{len(watch_descriptors)} directories."
    )


# ============================================================
# HANDLE NEW DIRECTORY
# ============================================================

def handle_new_directory(
    path
):
    if not os.path.isdir(
        path
    ):
        return

    add_recursive_watches(
        path
    )


# ============================================================
# READ INOTIFY EVENTS
# ============================================================

def read_inotify_events():
    try:
        data = os.read(
            inotify_fd,
            1024 * 1024
        )

    except BlockingIOError:
        return

    except OSError:
        return

    offset = 0

    data_length = len(
        data
    )


    while (
        offset +
        INOTIFY_EVENT_STRUCT.size
        <= data_length
    ):

        wd, mask, cookie, name_length = (
            INOTIFY_EVENT_STRUCT.unpack_from(
                data,
                offset
            )
        )

        offset += (
            INOTIFY_EVENT_STRUCT.size
        )


        raw_name = data[
            offset:
            offset + name_length
        ]

        offset += name_length


        try:
            name = raw_name.split(
                b"\0",
                1
            )[0].decode(
                "utf-8",
                errors="replace"
            )

        except Exception:
            name = ""


        directory = watch_descriptors.get(
            wd
        )

        if directory is None:
            continue


        if name:
            path = os.path.join(
                directory,
                name
            )
        else:
            path = directory


        path = os.path.abspath(
            path
        )


        # ----------------------------------------------------
        # Watch was removed.
        # ----------------------------------------------------

        if mask & IN_IGNORED:
            continue


        # ----------------------------------------------------
        # Directory created.
        # ----------------------------------------------------

        if (
            mask & IN_CREATE
            and
            mask & IN_ISDIR
        ):

            handle_new_directory(
                path
            )

            continue


        # ----------------------------------------------------
        # Directory deleted/moved.
        # ----------------------------------------------------

        if mask & IN_ISDIR:
            continue


        # ----------------------------------------------------
        # File created.
        # ----------------------------------------------------

        if mask & IN_CREATE:

            process_file_event(
                path,
                "created"
            )

            continue


        # ----------------------------------------------------
        # File deleted.
        # ----------------------------------------------------

        if mask & IN_DELETE:

            process_file_event(
                path,
                "deleted"
            )

            continue


        # ----------------------------------------------------
        # File modified.
        # ----------------------------------------------------

        if (
            mask & IN_MODIFY
            or
            mask & IN_CLOSE_WRITE
        ):

            process_file_event(
                path,
                "modified"
            )


        # ----------------------------------------------------
        # File permissions / ownership changed.
        # ----------------------------------------------------

        elif mask & IN_ATTRIB:

            process_file_event(
                path,
                "permissions_changed"
            )


# ============================================================
# CHECK INDIVIDUAL PROTECTED FILES
# ============================================================

def check_protected_files():
    for path in PROTECTED_FILES:

        path = os.path.abspath(
            path
        )

        old_state = current_state.get(
            path
        )

        new_state = get_file_state(
            path
        )

        if old_state is None:

            if new_state.get(
                "exists",
                False
            ):

                process_file_event(
                    path,
                    "created"
                )

            else:

                current_state[
                    path
                ] = new_state

            continue


        if old_state != new_state:

            if not new_state.get(
                "exists",
                False
            ):

                process_file_event(
                    path,
                    "deleted"
                )

            else:

                process_file_event(
                    path,
                    "modified"
                )


# ============================================================
# SAVE STATE
# ============================================================

def save_state():
    global last_state_save

    now = time.time()

    if (
        now - last_state_save
        < STATE_SAVE_INTERVAL
    ):
        return

    save_json(
        STATE_FILE,
        current_state
    )

    last_state_save = now


# ============================================================
# START
# ============================================================

def start():
    global running

    ensure_data_directory()

    print(
        "=================================================="
    )

    print(
        " ServerGuard FileGuard"
    )

    print(
        "=================================================="
    )

    print(
        "Mode: lightweight / inotify"
    )

    print(
        f"Baseline: {BASELINE_FILE}"
    )

    print(
        f"Events:   {EVENTS_FILE}"
    )

    print(
        ""
    )


    # --------------------------------------------------------
    # Baseline
    # --------------------------------------------------------

    initialize_baseline()


    # --------------------------------------------------------
    # Inotify
    # --------------------------------------------------------

    try:
        initialize_inotify()

    except Exception as e:

        print(
            f"[CRITICAL] FileGuard failed "
            f"to initialize: {e}"
        )

        return 1


    print(
        "[OK] FileGuard is ACTIVE."
    )

    print(
        "[OK] Waiting for file system events..."
    )


    global last_state_save

    last_state_save = time.time()


    # --------------------------------------------------------
    # Main loop
    # --------------------------------------------------------

    while running:

        try:

            readable, _, _ = select.select(
                [inotify_fd],
                [],
                [],
                5
            )

            if readable:
                read_inotify_events()


            # Check critical individual files.
            check_protected_files()


            # Save state periodically.
            save_state()


        except KeyboardInterrupt:

            break

        except Exception as e:

            print(
                f"[ERROR] FileGuard main loop: {e}"
            )

            time.sleep(2)


    # --------------------------------------------------------
    # Shutdown
    # --------------------------------------------------------

    if inotify_fd >= 0:

        try:
            os.close(
                inotify_fd
            )
        except Exception:
            pass


    save_json(
        STATE_FILE,
        current_state
    )


    print(
        "[FileGuard] Stopped."
    )

    return 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:
        sys.exit(
            start()
        )

    except Exception as e:

        print(
            f"[CRITICAL] FileGuard crashed: {e}"
        )

        sys.exit(1)

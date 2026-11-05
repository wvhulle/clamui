import json
import shlex
import time
from datetime import timedelta

SAMPLE_USER = "sample-user"
SAMPLE_PASSWORD = "sample-password"
SESSION_BUS = "unix:path=/run/user/1000/bus"
EICAR_TEXT = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
DOWNLOADS = f"/home/{SAMPLE_USER}/Downloads"
HISTORY_DATABASE = f"/home/{SAMPLE_USER}/.local/share/clamui/history.db"


def user_command(command):
    quoted = shlex.quote(command)
    return (
        f"runuser -u {SAMPLE_USER} -- env XDG_RUNTIME_DIR=/run/user/1000 "
        f"DBUS_SESSION_BUS_ADDRESS={SESSION_BUS} SWAYSOCK=/tmp/sway-ipc.sock "
        f"sh -c {quoted}"
    )


def as_user(command):
    return machine.succeed(user_command(command))


def as_user_status(command):
    return machine.execute(user_command(command))


def wait_as_user(command, timeout=60):
    return machine.wait_until_succeeds(user_command(command), timeout=timedelta(seconds=timeout))


def wait_for_desktop():
    machine.wait_for_unit("multi-user.target")
    wait_as_user("swaymsg -t get_outputs", timeout=120)
    wait_as_user("systemctl --user is-active graphical-session.target", timeout=60)


def wait_for_clamui_service():
    wait_as_user("systemctl --user is-active clamui.service", timeout=60)
    wait_as_user("busctl --user status io.github.wvhulle.ClamUI", timeout=60)
    wait_as_user("busctl --user list --no-legend | grep -q StatusNotifierItem", timeout=60)
    time.sleep(2)


def write_eicar_file(file_path):
    directory = file_path.rsplit("/", 1)[0]
    as_user(f"mkdir -p {shlex.quote(directory)}")
    as_user(f"printf %s {shlex.quote(EICAR_TEXT)} > {shlex.quote(file_path)}")


def scanner_lines_for(unit, file_path):
    journal = machine.succeed(f"journalctl -u {unit} --no-pager --output=cat")
    return [line for line in journal.splitlines() if file_path in line and line.endswith("FOUND")]


def assert_lines_stay_at(unit, file_path, settle_seconds):
    settled_count = len(scanner_lines_for(unit, file_path))
    time.sleep(settle_seconds)
    final_count = len(scanner_lines_for(unit, file_path))
    assert final_count == settled_count, (
        f"{file_path} kept producing detections: {settled_count} -> {final_count}"
    )


def stored_detection(file_path):
    query = (
        "select signature_name, found_on_access, found_by_schedule, sighting_count, resolution "
        f"from background_detections where cast(file_path as text) = '{file_path}'"
    )
    return as_user(f"sqlite3 -readonly {HISTORY_DATABASE} {shlex.quote(query)}").strip()


def wait_for_stored_detection(file_path):
    wait_as_user(
        f"sqlite3 -readonly {HISTORY_DATABASE} "
        + shlex.quote(
            f"select 1 from background_detections where cast(file_path as text) = '{file_path}'"
        )
        + " | grep -q 1"
    )


def listed_notifications():
    listed = json.loads(as_user("makoctl list -j"))
    if isinstance(listed, dict):
        return [notification for group in listed.get("data", []) for notification in group]
    return listed


def notification_text(notification):
    def text_of(field):
        field_value = notification.get(field, "")
        return field_value.get("data", "") if isinstance(field_value, dict) else field_value

    return f"{text_of('summary')} {text_of('body')}"


def notifications_mentioning(expected_text):
    return [
        notification
        for notification in listed_notifications()
        if expected_text in notification_text(notification)
    ]


def wait_for_notification(expected_text, timeout=60):
    started_waiting = time.monotonic()
    while time.monotonic() - started_waiting < timeout:
        matching = notifications_mentioning(expected_text)
        if matching:
            return matching
        time.sleep(1)
    raise AssertionError(
        f"no notification mentioning {expected_text!r}: {listed_notifications()}"
    )


def clamui_window():
    tree = json.loads(as_user("swaymsg -t get_tree"))
    pending = [tree]
    while pending:
        node = pending.pop()
        if node.get("app_id") == "io.github.wvhulle.ClamUI":
            return node
        pending += node.get("nodes", []) + node.get("floating_nodes", [])
    return None


def wait_for_clamui_window(timeout=30):
    started_waiting = time.monotonic()
    while time.monotonic() - started_waiting < timeout:
        window = clamui_window()
        if window is not None and window.get("visible"):
            return window
        time.sleep(1)
    raise AssertionError("the ClamUI window never became visible")


def click_at(horizontal, vertical):
    as_user(
        f"swaymsg 'seat seat0 cursor set {horizontal} {vertical}' && "
        "swaymsg 'seat seat0 cursor press button1' && "
        "swaymsg 'seat seat0 cursor release button1'"
    )
    time.sleep(1)


def activate_application_action(action_name):
    as_user(
        "gdbus call --session --dest io.github.wvhulle.ClamUI "
        "--object-path /io/github/wvhulle/ClamUI "
        "--method org.gtk.Actions.Activate "
        f"{action_name} '[]' '{{}}'"
    )


def tray_status():
    names = as_user("busctl --user list --no-legend")
    tray_names = [
        line.split()[0] for line in names.splitlines() if "StatusNotifierItem" in line.split()[0]
    ]
    assert tray_names, f"ClamUI registered no tray item:\n{names}"
    status = as_user(
        f"busctl --user get-property {tray_names[0]} /StatusNotifierItem "
        "org.kde.StatusNotifierItem Status"
    )
    return status.split('"')[1]


def wait_for_tray_status(expected_status, timeout=30):
    started_waiting = time.monotonic()
    while time.monotonic() - started_waiting < timeout:
        if tray_status() == expected_status:
            return
        time.sleep(1)
    raise AssertionError(f"tray status stayed {tray_status()}, expected {expected_status}")


def answer_password_prompt(password=SAMPLE_PASSWORD):
    time.sleep(3)
    machine.send_chars(f"{password}\n")

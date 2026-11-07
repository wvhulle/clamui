import json
import shlex
import subprocess
import time
from datetime import timedelta

SAMPLE_USER = "sample-user"
SAMPLE_PASSWORD = "sample-password"
SESSION_BUS = "unix:path=/run/user/1000/bus"
EICAR_TEXT = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
DOWNLOADS = f"/home/{SAMPLE_USER}/Downloads"
LAZARET_DATABASE = f"/home/{SAMPLE_USER}/.local/share/lazaret/lazaret.db"


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


def wait_for_lazaret_service():
    wait_as_user("systemctl --user is-active lazaret.service", timeout=60)
    wait_as_user("busctl --user status page.codeberg.wvhulle.Lazaret", timeout=60)
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
        "select signature_name, detection_sources, sighting_count, resolution_kind "
        "from background_detections left join detection_resolutions "
        "using (file_path, signature_name) "
        f"where cast(file_path as text) = '{file_path}'"
    )
    return as_user(f"sqlite3 -readonly {LAZARET_DATABASE} {shlex.quote(query)}").strip()


def wait_for_stored_detection(file_path):
    wait_as_user(
        f"sqlite3 -readonly {LAZARET_DATABASE} "
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


def lazaret_window():
    tree = json.loads(as_user("swaymsg -t get_tree"))
    pending = [tree]
    while pending:
        node = pending.pop()
        if node.get("app_id") == "page.codeberg.wvhulle.Lazaret":
            return node
        pending += node.get("nodes", []) + node.get("floating_nodes", [])
    return None


def wait_for_lazaret_window(timeout=30):
    started_waiting = time.monotonic()
    while time.monotonic() - started_waiting < timeout:
        window = lazaret_window()
        if window is not None and window.get("visible"):
            return window
        time.sleep(1)
    raise AssertionError("the Lazaret window never became visible")


def click_at(horizontal, vertical):
    as_user(
        f"swaymsg 'seat seat0 cursor set {horizontal} {vertical}' && "
        "swaymsg 'seat seat0 cursor press button1' && "
        "swaymsg 'seat seat0 cursor release button1'"
    )
    time.sleep(1)


TESSERACT_FIELD_COUNT = 12
TESSERACT_WORD_LEVEL = "5"


def recognised_word_rows():
    machine.screenshot("text_lookup")
    tesseract_run = subprocess.run(
        [
            "tesseract",
            str(machine.out_dir / "text_lookup.png"),
            "-",
            "--oem",
            "2",
            "-c",
            "debug_file=/dev/null",
            "--psm",
            "11",
            "tsv",
        ],
        capture_output=True,
        text=True,
    )
    if tesseract_run.returncode != 0:
        raise AssertionError(f"tesseract failed: {tesseract_run.stderr}")
    split_rows = [output_line.split("\t") for output_line in tesseract_run.stdout.splitlines()[1:]]
    return [
        word_fields
        for word_fields in split_rows
        if len(word_fields) == TESSERACT_FIELD_COUNT
        and word_fields[0] == TESSERACT_WORD_LEVEL
        and word_fields[11].strip()
    ]


def normalised_word(word_text):
    return word_text.strip().strip(".,:;…").lower()


def text_center_on_screen(expected_text):
    expected_words = [normalised_word(expected_word) for expected_word in expected_text.split()]
    word_rows = recognised_word_rows()
    for first_position in range(len(word_rows) - len(expected_words) + 1):
        candidate_words = word_rows[first_position : first_position + len(expected_words)]
        first_top = int(candidate_words[0][7])
        first_height = int(candidate_words[0][9])
        same_line = all(
            abs(int(word_fields[7]) - first_top) <= first_height // 2
            for word_fields in candidate_words
        )
        words_match = all(
            normalised_word(word_fields[11]) == expected_word
            for word_fields, expected_word in zip(candidate_words, expected_words)
        )
        if same_line and words_match:
            left_edge = int(candidate_words[0][6])
            right_edge = int(candidate_words[-1][6]) + int(candidate_words[-1][8])
            top_edge = min(int(word_fields[7]) for word_fields in candidate_words)
            bottom_edge = max(int(word_fields[7]) + int(word_fields[9]) for word_fields in candidate_words)
            return ((left_edge + right_edge) // 2, (top_edge + bottom_edge) // 2)
    return None


def text_is_shown(expected_text):
    return text_center_on_screen(expected_text) is not None


def move_focus_until(shown_on_screen, focus_key, presses=60):
    for _ in range(presses):
        if shown_on_screen():
            return
        machine.send_key(focus_key)
        time.sleep(1)
    assert shown_on_screen(), f"pressing {focus_key} never brought the expected text on screen"


def click_on_text(expected_text, timeout=30):
    started_waiting = time.monotonic()
    while time.monotonic() - started_waiting < timeout:
        text_center = text_center_on_screen(expected_text)
        if text_center is not None:
            click_at(text_center[0], text_center[1])
            return
        time.sleep(2)
    raise AssertionError(f"the text {expected_text!r} never appeared on screen")


def activate_application_action(action_name):
    as_user(
        "gdbus call --session --dest page.codeberg.wvhulle.Lazaret "
        "--object-path /page/codeberg/wvhulle/Lazaret "
        "--method org.gtk.Actions.Activate "
        f"{action_name} '[]' '{{}}'"
    )


def activate_window_action(action_name, action_target):
    as_user(
        "gdbus call --session --dest page.codeberg.wvhulle.Lazaret "
        "--object-path /page/codeberg/wvhulle/Lazaret/window/1 "
        "--method org.gtk.Actions.Activate "
        f"{action_name} \"[<'{action_target}'>]\" '{{}}'"
    )


def tray_status():
    names = as_user("busctl --user list --no-legend")
    tray_names = [
        line.split()[0] for line in names.splitlines() if "StatusNotifierItem" in line.split()[0]
    ]
    assert tray_names, f"Lazaret registered no tray item:\n{names}"
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

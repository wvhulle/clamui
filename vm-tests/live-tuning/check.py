CHANGE_SETTINGS_TITLE = "Change Settings"
UNLOCK_LABEL = "Unlock"
CONFIRM_APPLY_LABEL = "Apply"
MAX_THREADS_TITLE = "MaxThreads"
COPY_DIALOG_NOTICE = "Nothing is applied"
COPY_LINE_LABEL = "Copy Line"
LIVE_CONFIG_DESCRIPTION = "combines your system configuration"
MERGED_CONFIG = "/run/lazaret/clamd.conf"
OVERRIDES_FILE = "/var/lib/lazaret/live-overrides.toml"
CHANGE_DOCUMENT_FILE = "/tmp/admin-service-change.toml"
USER_ANSWER_FILE = "/tmp/admin-service-answer"
USER_REQUEST_FILE = "/tmp/admin-service-request"


def change_document(key, toml_value):
    return f'change = "set-values"\n\n[setting_values]\n{key} = {toml_value}\n'


def reset_document(key):
    return f'change = "back-to-system"\nsetting_names = ["{key}"]\n'


def call_with_document(document):
    machine.succeed(f"printf %s {shlex.quote(document)} > {CHANGE_DOCUMENT_FILE}; chmod 644 {CHANGE_DOCUMENT_FILE}")
    return (
        "busctl --timeout=400 call page.codeberg.wvhulle.Lazaret.ClamavAdmin "
        "/page/codeberg/wvhulle/Lazaret/ClamavAdmin "
        "page.codeberg.wvhulle.Lazaret.ClamavAdmin ApplyChanges "
        f's "$(cat {CHANGE_DOCUMENT_FILE})" 2>&1'
    )


def apply_command(key, toml_value):
    return call_with_document(change_document(key, toml_value))


def apply_as_root(key, toml_value):
    return machine.execute(apply_command(key, toml_value))


def reset_as_root(key):
    return machine.execute(call_with_document(reset_document(key)))


def config_seen_by_clamd():
    clamd_pid = machine.succeed("systemctl show --property=MainPID --value clamav-daemon.service").strip()
    return machine.succeed(f"nsenter --target {clamd_pid} --mount cat /etc/clamav/clamd.conf")


def start_apply_as_user(key, toml_value):
    machine.succeed(f"rm -f {USER_ANSWER_FILE}")
    request_body = f"#!/bin/sh\n({apply_command(key, toml_value)}; echo finished) > {USER_ANSWER_FILE}\n"
    as_user(f"printf %s {shlex.quote(request_body)} > {USER_REQUEST_FILE}; chmod +x {USER_REQUEST_FILE}")
    as_user(f"swaymsg exec {USER_REQUEST_FILE}")


def wait_for_user_answer():
    machine.wait_until_succeeds(f"grep -q finished {USER_ANSWER_FILE}", timeout=timedelta(seconds=240))
    return machine.succeed(f"cat {USER_ANSWER_FILE}")


def show_scan_engine_page():
    activate_window_action("show-page", "scan-engine")
    time.sleep(3)


def enter_max_threads(new_value):
    machine.send_key("ctrl-a")
    machine.send_chars(f"{new_value}\n")


def copy_max_threads_line(new_value):
    move_focus_until(lambda: text_is_shown(MAX_THREADS_TITLE), "tab")
    click_on_text(MAX_THREADS_TITLE)
    machine.wait_for_text(COPY_DIALOG_NOTICE, timeout=timedelta(seconds=30))
    enter_max_threads(new_value)
    time.sleep(1)
    click_on_text(COPY_LINE_LABEL)


def edit_max_threads(new_value):
    move_focus_until(lambda: text_is_shown(MAX_THREADS_TITLE), "tab")
    click_on_text(MAX_THREADS_TITLE)
    enter_max_threads(new_value)


def wait_for_clamd():
    machine.wait_until_succeeds(f"clamdscan --config-file={MERGED_CONFIG} --ping 1", timeout=timedelta(seconds=120))


def merge_again():
    machine.succeed("systemctl reset-failed clamav-daemon.service")
    machine.succeed("systemctl restart lazaret-settings-merge.service")
    machine.succeed("systemctl reset-failed clamav-daemon.service")
    machine.succeed("systemctl start clamav-daemon.service")
    wait_for_clamd()


machine.start()
wait_for_desktop()
machine.wait_for_unit("lazaret-settings-merge.service")
machine.succeed("systemctl start clamav-daemon.service")
machine.wait_for_unit("clamav-daemon.service")
wait_for_clamd()

with subtest("the socket survives a daemon restart"):
    machine.succeed("test -S /run/clamav/clamd.ctl")
    machine.succeed("systemctl restart clamav-daemon.service")
    machine.succeed("test -S /run/clamav/clamd.ctl")
    wait_for_clamd()

with subtest("live tuning is on by default and the daemon sees the merged configuration"):
    machine.succeed("grep -qx DetectPUA /etc/lazaret/tunable-settings")
    machine.succeed(f"systemctl cat clamav-daemon.service | grep -- 'BindReadOnlyPaths=-{MERGED_CONFIG}:/etc/clamav/clamd.conf'")
    machine.fail("systemctl cat clamav-daemon.service | grep -- --config-file")
    assert "DatabaseDirectory" in machine.succeed(f"cat {MERGED_CONFIG}")
    assert config_seen_by_clamd() == machine.succeed(f"cat {MERGED_CONFIG}")

with subtest("a user change asks for a password, shows the change, and applies"):
    start_apply_as_user("MaxThreads", "7")
    time.sleep(3)
    machine.screenshot("polkit_prompt")
    prompt_text = machine.get_screen_text()
    print(prompt_text)
    answer_password_prompt()
    answer = wait_for_user_answer()
    assert "applied" in answer, answer
    assert "MaxThreads 7" in machine.succeed(f"cat {MERGED_CONFIG}")
    wait_for_clamd()

with subtest("authorization is not retained, so a second change asks again"):
    start_apply_as_user("MaxThreads", "9")
    time.sleep(3)
    machine.screenshot("polkit_prompt_again")
    machine.send_key("esc")
    answer = wait_for_user_answer()
    assert "applied" not in answer, f"applied without a new password: {answer}"
    assert "MaxThreads 9" not in machine.succeed(f"cat {MERGED_CONFIG}")

with subtest("the Scanner Engine settings offer to unlock allowed settings"):
    wait_for_lazaret_service()
    activate_application_action("show-window")
    wait_for_lazaret_window()
    time.sleep(2)
    show_scan_engine_page()
    move_focus_until(lambda: text_is_shown(LIVE_CONFIG_DESCRIPTION), "tab", presses=90)
    machine.screenshot("scanner_engine_locked")
    move_focus_until(lambda: text_is_shown(CHANGE_SETTINGS_TITLE), "shift-tab")
    machine.wait_for_text(UNLOCK_LABEL, timeout=timedelta(seconds=30))

with subtest("while locked, Copy configuration line only copies the line"):
    copy_max_threads_line(3)
    time.sleep(3)
    machine.screenshot("locked_copy")
    machine.wait_for_text("Copied", timeout=timedelta(seconds=60))
    assert "MaxThreads 3" not in machine.succeed(f"cat {MERGED_CONFIG}"), "a locked edit changed clamd"
    assert "value = 3" not in machine.succeed(f"cat {OVERRIDES_FILE}"), "a locked edit changed clamd"

with subtest("unlocking, editing and confirming applies through a real password prompt"):
    show_scan_engine_page()
    move_focus_until(lambda: text_is_shown(CHANGE_SETTINGS_TITLE), "shift-tab")
    click_on_text(UNLOCK_LABEL)
    time.sleep(1)
    machine.screenshot("preferences_unlocked")
    edit_max_threads(8)
    time.sleep(2)
    machine.screenshot("confirm_change")
    click_on_text(CONFIRM_APPLY_LABEL)
    time.sleep(2)
    machine.screenshot("gui_password_prompt")
    machine.wait_for_text("MaxThreads 8", timeout=timedelta(seconds=30))
    answer_password_prompt()
    machine.wait_until_succeeds(f"grep -q 'MaxThreads 8' {MERGED_CONFIG}", timeout=timedelta(seconds=120))
    wait_for_clamd()
    time.sleep(2)
    show_scan_engine_page()
    move_focus_until(lambda: "MaxThreads = 8" in machine.get_screen_text(), "shift-tab")
    machine.screenshot("after_gui_apply")
    machine.wait_for_text("MaxThreads = 8", timeout=timedelta(seconds=60))

with subtest("a second change starts from the value just applied"):
    show_scan_engine_page()
    edit_max_threads(10)
    time.sleep(2)
    machine.screenshot("confirm_second_change")
    machine.wait_for_text("Now: 8", timeout=timedelta(seconds=60))
    machine.send_key("esc")
    time.sleep(1)

with subtest("protected and unlisted settings are refused by the admin service"):
    for key, toml_value in (("VirusEvent", '"/bin/sh"'), ("User", '"root"'), ("MaxFileSize", '"1M"'), ("MaxThreads", '"many"')):
        status, output = apply_as_root(key, toml_value)
        assert status != 0, output
    merged = machine.succeed(f"cat {MERGED_CONFIG}")
    assert "VirusEvent" not in merged and "User root" not in merged and "MaxFileSize" not in merged

with subtest("a protected key planted in the stored changes makes the merge fall back to the base"):
    machine.succeed(
        f"printf '[VirusEvent]\\nstate = \"permanent\"\\nvalue = \"/bin/sh\"\\n\\n[MaxThreads]\\nstate = \"permanent\"\\nvalue = 5\\n' > {OVERRIDES_FILE}"
    )
    merge_again()
    merged = machine.succeed(f"cat {MERGED_CONFIG}")
    assert "VirusEvent" not in merged and "MaxThreads 5" not in merged, merged
    assert "MaxThreads 4" in merged, merged

with subtest("clamd still starts when the stored changes cannot be read"):
    machine.succeed(f"printf 'not toml at all\\n\\0\\0' > {OVERRIDES_FILE}")
    merge_again()

with subtest("a restart that fails restores the previous settings"):
    machine.succeed(f"printf '[MaxThreads]\\nstate = \"permanent\"\\nvalue = 6\\n' > {OVERRIDES_FILE}")
    merge_again()
    status, output = apply_as_root("MaxThreads", "3")
    assert status == 0 and "rolled-back" in output, output
    assert "value = 6" in machine.succeed(f"cat {OVERRIDES_FILE}")
    assert "MaxThreads 3" not in machine.succeed(f"cat {MERGED_CONFIG}")
    wait_for_clamd()

with subtest("a change that reduces protection ends on its own"):
    status, output = apply_as_root("DetectPUA", "false")
    assert status == 0 and "applied" in output, output
    assert "temporary-reduction" in machine.succeed(f"cat {OVERRIDES_FILE}")
    assert "DetectPUA no" in config_seen_by_clamd()
    time.sleep(35)
    machine.succeed("systemctl start lazaret-reduction-expiry.service")
    wait_for_clamd()
    assert "DetectPUA no" not in config_seen_by_clamd()
    machine.succeed("journalctl _SYSTEMD_UNIT=lazaret-reduction-expiry.service LAZARET_ACTION=expire-reductions | grep -q DetectPUA")

with subtest("going back to the system configuration removes the change"):
    status, output = reset_as_root("MaxThreads")
    assert status == 0 and "applied" in output, output
    wait_for_clamd()
    assert "MaxThreads 4" in config_seen_by_clamd()

with subtest("a rebuild that changes the base reaches clamd without a reboot"):
    machine.succeed("/run/current-system/specialisation/newBase/bin/switch-to-configuration test")
    machine.wait_until_succeeds(f"grep -q 'MaxThreads 11' {MERGED_CONFIG}", timeout=timedelta(seconds=120))
    wait_for_clamd()
    assert "MaxThreads 11" in config_seen_by_clamd()

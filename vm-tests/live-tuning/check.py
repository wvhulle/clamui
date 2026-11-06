CONFIRM_APPLY_BUTTON = (705, 462)
UNLOCK_BUTTON = (863, 132)
MAX_THREADS_ROW = (600, 697)
SCANNER_TAB = (679, 745)
MERGED_CONFIG = "/run/lazaret/clamd.conf"
OVERRIDES_FILE = "/var/lib/lazaret/clamd-overrides.conf"
USER_ANSWER_FILE = "/tmp/helper-answer"
USER_REQUEST_FILE = "/tmp/helper-request"


def apply_command(key, value):
    return (
        "busctl --timeout=400 call page.codeberg.wvhulle.Lazaret.SettingsHelper "
        "/page/codeberg/wvhulle/Lazaret/SettingsHelper "
        "page.codeberg.wvhulle.Lazaret.SettingsHelper ApplyChanges "
        f"'a(ss)' 1 {key} {value} 2>&1"
    )


def apply_as_root(key, value):
    return machine.execute(apply_command(key, value))


def start_apply_as_user(key, value):
    machine.succeed(f"rm -f {USER_ANSWER_FILE}")
    request_body = f"#!/bin/sh\n({apply_command(key, value)}; echo finished) > {USER_ANSWER_FILE}\n"
    as_user(f"printf %s {shlex.quote(request_body)} > {USER_REQUEST_FILE}; chmod +x {USER_REQUEST_FILE}")
    as_user(f"swaymsg exec {USER_REQUEST_FILE}")


def wait_for_user_answer():
    machine.wait_until_succeeds(f"grep -q finished {USER_ANSWER_FILE}", timeout=timedelta(seconds=240))
    return machine.succeed(f"cat {USER_ANSWER_FILE}")


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

with subtest("the daemon reads the merged configuration"):
    machine.succeed(f"systemctl cat clamav-daemon.service | grep -- --config-file={MERGED_CONFIG}")
    assert "DatabaseDirectory" in machine.succeed(f"cat {MERGED_CONFIG}")

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

with subtest("the Preferences page offers to unlock allowed settings"):
    wait_for_lazaret_service()
    activate_application_action("show-window")
    wait_for_lazaret_window()
    time.sleep(2)
    activate_application_action("preferences")
    time.sleep(3)
    click_at(SCANNER_TAB[0], SCANNER_TAB[1])
    time.sleep(2)
    machine.screenshot("preferences_locked")
    machine.wait_for_text("Unlock", timeout=timedelta(seconds=30))

with subtest("while locked, editing a setting only copies a snippet"):
    click_at(MAX_THREADS_ROW[0], MAX_THREADS_ROW[1])
    machine.send_key("ctrl-a")
    machine.send_chars("3\n")
    time.sleep(3)
    machine.screenshot("locked_edit")
    machine.wait_for_text("Copied", timeout=timedelta(seconds=60))
    assert "MaxThreads 3" not in machine.succeed(f"cat {MERGED_CONFIG}"), "a locked edit changed clamd"
    assert "MaxThreads 3" not in machine.succeed(f"cat {OVERRIDES_FILE}"), "a locked edit changed clamd"

with subtest("unlocking, editing and confirming applies through a real password prompt"):
    click_at(UNLOCK_BUTTON[0], UNLOCK_BUTTON[1])
    time.sleep(1)
    machine.screenshot("preferences_unlocked")
    click_at(MAX_THREADS_ROW[0], MAX_THREADS_ROW[1])
    machine.send_key("ctrl-a")
    machine.send_chars("8\n")
    time.sleep(2)
    machine.screenshot("confirm_change")
    click_at(CONFIRM_APPLY_BUTTON[0], CONFIRM_APPLY_BUTTON[1])
    time.sleep(2)
    machine.screenshot("gui_password_prompt")
    machine.wait_for_text("MaxThreads 8", timeout=timedelta(seconds=30))
    answer_password_prompt()
    machine.wait_until_succeeds(f"grep -q 'MaxThreads 8' {MERGED_CONFIG}", timeout=timedelta(seconds=120))
    wait_for_clamd()
    time.sleep(2)
    machine.screenshot("after_gui_apply")
    machine.wait_for_text("MaxThreads = 8", timeout=timedelta(seconds=60))

with subtest("a second change starts from the value just applied"):
    click_at(MAX_THREADS_ROW[0], MAX_THREADS_ROW[1])
    machine.send_key("ctrl-a")
    machine.send_chars("10\n")
    time.sleep(2)
    machine.screenshot("confirm_second_change")
    machine.wait_for_text("Now: 8", timeout=timedelta(seconds=60))
    machine.send_key("esc")
    time.sleep(1)

with subtest("protected and unlisted settings are refused by the helper"):
    for key, value in (("VirusEvent", "/bin/sh"), ("User", "root"), ("MaxFileSize", "1M")):
        status, output = apply_as_root(key, value)
        assert status != 0, output
    merged = machine.succeed(f"cat {MERGED_CONFIG}")
    assert "VirusEvent" not in merged and "User root" not in merged and "MaxFileSize" not in merged

with subtest("a protected key planted in the overrides is dropped at merge"):
    machine.succeed(f"printf 'VirusEvent /bin/sh\\nUser root\\nMaxThreads 5\\n' > {OVERRIDES_FILE}")
    machine.succeed("systemctl restart lazaret-settings-merge.service")
    merged = machine.succeed(f"cat {MERGED_CONFIG}")
    assert "VirusEvent" not in merged and "User root" not in merged
    assert "MaxThreads 5" in merged

with subtest("clamd still starts when the overrides cannot be used"):
    machine.succeed(f"printf 'not a valid line\\n\\0\\0' > {OVERRIDES_FILE}")
    merge_again()

with subtest("an unhealthy restart restores the previous settings"):
    machine.succeed(f"printf 'MaxThreads 6\\n' > {OVERRIDES_FILE}")
    merge_again()
    machine.succeed("systemctl reset-failed clamav-daemon.service")
    status, output = apply_as_root("NotARealClamdOption", "rejected")
    assert status == 0 and "rolled-back" in output, output
    overrides = machine.succeed(f"cat {OVERRIDES_FILE}")
    assert overrides.strip() == "MaxThreads 6", overrides
    assert "NotARealClamdOption" not in machine.succeed(f"cat {MERGED_CONFIG}")
    machine.succeed(f"clamdscan --config-file={MERGED_CONFIG} --ping 1")

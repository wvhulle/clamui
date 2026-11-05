UPDATE_DATABASE_BUTTON = (468, 488)
UPDATE_NOW_BUTTON = (967, 160)
FIXTURE_KEY = "FIXTUREKEYMUSTNEVERAPPEAR"

machine.start()
wait_for_desktop()
wait_for_clamui_service()
machine.succeed("systemctl start clamav-daemon.service")
machine.wait_until_succeeds("clamdscan --ping 1", timeout=timedelta(seconds=120))

with subtest("the Protection page lists both updaters"):
    activate_application_action("show-window")
    wait_for_clamui_window()
    time.sleep(3)
    machine.screenshot("protection_with_updaters")

with subtest("Update Now opens the update dialog"):
    click_at(UPDATE_NOW_BUTTON[0], UPDATE_NOW_BUTTON[1])
    time.sleep(2)
    machine.screenshot("update_dialog")

with subtest("a failed update is reported through a real password prompt"):
    click_at(UPDATE_DATABASE_BUTTON[0], UPDATE_DATABASE_BUTTON[1])
    time.sleep(3)
    machine.screenshot("update_password_prompt")
    answer_password_prompt()
    time.sleep(4)
    machine.screenshot("after_first_password")
    if "Authenticat" in machine.get_screen_text():
        answer_password_prompt()
    wait_as_user(
        f"sqlite3 -readonly {HISTORY_DATABASE} "
        "\"select activity_status from activity_entries\" | grep -q update",
        timeout=240,
    )
    time.sleep(2)
    machine.screenshot("update_finished")
    status = as_user(
        f"sqlite3 -readonly {HISTORY_DATABASE} \"select activity_status from activity_entries\""
    ).strip()
    print(f"update status: {status}")
    assert "failed" in status, f"a failed update was not recorded as failed: {status}"

with subtest("fangfrisch ran and logged the address containing the key"):
    machine.wait_until_succeeds(
        "systemctl show -p Result --value clamav-fangfrisch.service | grep -qv '^$'", timeout=timedelta(seconds=60)
    )
    fangfrisch_journal = machine.succeed(
        "journalctl -u clamav-fangfrisch.service --no-pager --output=cat"
    )
    assert FIXTURE_KEY in fangfrisch_journal, (
        "fangfrisch never logged the key, so this test proves nothing:\n"
        + fangfrisch_journal[-1500:]
    )

with subtest("the key never reaches the update log, the history or the screen"):
    stored_output = as_user(
        f"sqlite3 -readonly {HISTORY_DATABASE} \"select activity_output from activity_entries\""
    )
    assert "fangfrisch" in stored_output, f"fangfrisch output was not shown:\n{stored_output}"
    assert FIXTURE_KEY not in stored_output, "the update log saved the URLhaus key"
    assert "address hidden" in stored_output, f"the address was not hidden:\n{stored_output}"
    screen = machine.get_screen_text()
    assert FIXTURE_KEY not in screen, "the URLhaus key is on the screen"

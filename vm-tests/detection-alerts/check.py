QUARANTINE_BUTTON = (996, 261)
FIRST_LIST_ROW = (780, 170)
DELETE_BUTTON = (1006, 316)
CONFIRM_DELETE_BUTTON = (975, 261)
DELETED_FILE = f"{DOWNLOADS}/throwaway.exe"
ON_ACCESS_UNIT = "clamav-clamonacc.service"
BLOCKED_FILE = f"{DOWNLOADS}/invoice.pdf.exe"
SECOND_FILE = f"{DOWNLOADS}/while-closed.exe"

machine.start()
wait_for_desktop()

with subtest("logging in starts Lazaret through the module, without a window"):
    wait_for_lazaret_service()
    assert lazaret_window() is None or not lazaret_window().get("visible"), "started with a window"

with subtest("on-access scanning is ready"):
    machine.succeed("systemctl start clamav-daemon.service")
    machine.wait_for_unit("clamav-daemon.service")
    machine.wait_until_succeeds("clamdscan --ping 1", timeout=timedelta(seconds=120))
    machine.succeed(f"systemctl restart {ON_ACCESS_UNIT}")
    machine.wait_until_succeeds(
        f"journalctl -u {ON_ACCESS_UNIT} --no-pager | grep -q 'ClamInotif: watching'", timeout=timedelta(seconds=120)
    )

with subtest("a detected file is blocked"):
    write_eicar_file(BLOCKED_FILE)
    machine.wait_until_succeeds(
        user_command(f"cat {BLOCKED_FILE} 2>&1 | grep -q 'not permitted'"), timeout=timedelta(seconds=60)
    )

with subtest("one urgent notification names the signature and the file"):
    matching = wait_for_notification("Win.Fixture.Agent-1")
    assert len(matching) == 1, f"expected one notification: {matching}"
    assert BLOCKED_FILE in notification_text(matching[0]), matching
    assert "Malware blocked" in notification_text(matching[0]), matching
    print(f"notification: {matching[0]}")
    urgency = matching[0].get("urgency")
    urgency = urgency.get("data") if isinstance(urgency, dict) else urgency
    assert urgency in (2, "critical"), f"not urgent: {matching[0]}"

with subtest("repeated scanner lines become one detection with the real signature"):
    wait_for_stored_detection(BLOCKED_FILE)
    detection = stored_detection(BLOCKED_FILE).split("|")
    assert detection[0].startswith("Win.Fixture.Agent-1"), detection
    assert detection[1] == "1", f"not recorded as on-access: {detection}"
    assert detection[4] == "", f"should be unresolved: {detection}"

with subtest("refreshing does not feed back into the journal"):
    assert_lines_stay_at(ON_ACCESS_UNIT, BLOCKED_FILE, settle_seconds=8)
    assert_lines_stay_at(ON_ACCESS_UNIT, BLOCKED_FILE, settle_seconds=15)

with subtest("the tray shows that something needs attention"):
    wait_for_tray_status("NeedsAttention")

with subtest("clicking the notification opens the detection"):
    as_user("makoctl invoke")
    wait_for_lazaret_window()
    time.sleep(3)
    machine.screenshot("incident_after_notification")

with subtest("quarantining from the timeline clears the blocked file"):
    click_at(QUARANTINE_BUTTON[0], QUARANTINE_BUTTON[1])
    machine.wait_until_fails(f"test -e {BLOCKED_FILE}", timeout=timedelta(seconds=30))
    machine.screenshot("incident_after_quarantine")
    wait_as_user(
        f"sqlite3 -readonly {HISTORY_DATABASE} "
        "\"select resolution from background_detections\" | grep -q quarantined"
    )
    wait_for_tray_status("Active")
    quarantined = as_user(
        f"sqlite3 -readonly /home/{SAMPLE_USER}/.local/share/lazaret/quarantine.db "
        "\"select threat_name from quarantine\""
    )
    assert "Win.Fixture.Agent-1" in quarantined, f"lost the signature: {quarantined}"

with subtest("the action opens the page from the tray"):
    activate_application_action("open-detections")
    time.sleep(2)
    machine.screenshot("detections_page")
    machine.wait_for_text("What on-access scanning")

with subtest("deleting takes two choices and withdraws the alert that is still showing"):
    as_user("makoctl dismiss --all")
    write_eicar_file(DELETED_FILE)
    machine.wait_until_succeeds(
        user_command(f"cat {DELETED_FILE} 2>&1 | grep -q 'not permitted'"), timeout=timedelta(seconds=60)
    )
    wait_for_notification(DELETED_FILE)
    time.sleep(2)
    machine.screenshot("list_with_unresolved_detection")
    click_at(FIRST_LIST_ROW[0], FIRST_LIST_ROW[1])
    time.sleep(2)
    machine.screenshot("incident_before_delete")
    click_at(DELETE_BUTTON[0], DELETE_BUTTON[1])
    time.sleep(1)
    machine.screenshot("delete_question")
    machine.succeed(f"test -e {DELETED_FILE}")
    click_at(CONFIRM_DELETE_BUTTON[0], CONFIRM_DELETE_BUTTON[1])
    machine.wait_until_fails(f"test -e {DELETED_FILE}", timeout=timedelta(seconds=30))
    time.sleep(2)
    machine.screenshot("incident_after_delete")
    assert not notifications_mentioning(DELETED_FILE), "the alert outlived the file it warned about"
    wait_for_tray_status("Active")

with subtest("detections missed while closed are summarised once at the next start"):
    as_user("makoctl dismiss --all")
    as_user("systemctl --user stop lazaret.service")
    write_eicar_file(SECOND_FILE)
    machine.wait_until_succeeds(
        user_command(f"cat {SECOND_FILE} 2>&1 | grep -q 'not permitted'"), timeout=timedelta(seconds=60)
    )
    time.sleep(2)
    as_user("systemctl --user start lazaret.service")
    wait_for_notification("while Lazaret wasn't running")
    assert not notifications_mentioning(SECOND_FILE), "alerted individually about a missed file"
    assert_lines_stay_at(ON_ACCESS_UNIT, SECOND_FILE, settle_seconds=10)

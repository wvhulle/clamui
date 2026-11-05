use std::{
    ffi::OsString,
    fs,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use crate::{
    fixture_systemd_service::serve_fixture_systemd,
    headless_sway_session::HeadlessSwaySession,
    screenshot_fixtures::{ScreenshotFixtures, prepare_screenshot_fixtures},
    task_failure::TaskFailure,
    virtual_pointer_input::{ScreenPosition, ScreenSize, VirtualPointerInput},
};

const PAGE_SETTLE_DURATION: Duration = Duration::from_secs(4);
const CLICK_SETTLE_DURATION: Duration = Duration::from_secs(2);
const SCREEN_SIZE: ScreenSize = ScreenSize {
    logical_width: 900,
    logical_height: 700,
};
const POINTER_REST_POSITION: ScreenPosition = ScreenPosition {
    logical_x: 450,
    logical_y: 22,
};
const APPLICATION_EXIT_DURATION: Duration = Duration::from_millis(500);

struct PointerClick {
    click_horizontal: u32,
    click_vertical: u32,
    screenshot_name: &'static str,
}

impl PointerClick {
    const fn at(click_horizontal: u32, click_vertical: u32, screenshot_name: &'static str) -> Self {
        Self {
            click_horizontal,
            click_vertical,
            screenshot_name,
        }
    }
}

struct PageCapture {
    screenshot_name: &'static str,
    page_argument: &'static str,
    scans_fixture_directory: bool,
    pointer_clicks: &'static [PointerClick],
}

const LOG_ENTRY_CLICKS: [PointerClick; 1] = [PointerClick::at(548, 170, "logs-entry-selected")];
const PROFILE_MANAGER_CLICKS: [PointerClick; 1] = [PointerClick::at(814, 177, "profile-manager")];
const PREFERENCE_TAB_CLICKS: [PointerClick; 2] = [
    PointerClick::at(275, 655, "preferences-exclusions"),
    PointerClick::at(363, 655, "preferences-scheduled"),
];
const QUARANTINE_ALL_CLICKS: [PointerClick; 2] = [
    PointerClick::at(637, 92, "results-quarantine-confirmation"),
    PointerClick::at(520, 395, "results-quarantined"),
];

const PAGE_CAPTURES: [PageCapture; 8] = [
    PageCapture {
        pointer_clicks: &PROFILE_MANAGER_CLICKS,
        ..PageCapture::idle_page("scan", "--page=scan")
    },
    PageCapture {
        screenshot_name: "scan-result",
        page_argument: "--page=scan",
        scans_fixture_directory: true,
        pointer_clicks: &[],
    },
    PageCapture::idle_page("database", "--page=database"),
    PageCapture::idle_page("components", "--page=components"),
    PageCapture::idle_page("quarantine", "--page=quarantine"),
    PageCapture {
        pointer_clicks: &LOG_ENTRY_CLICKS,
        ..PageCapture::idle_page("logs", "--page=logs")
    },
    PageCapture::idle_page("protection", "--page=protection"),
    PageCapture {
        pointer_clicks: &PREFERENCE_TAB_CLICKS,
        ..PageCapture::idle_page("preferences", "--page=preferences")
    },
];
const QUARANTINE_ALL_CAPTURE: PageCapture = PageCapture {
    screenshot_name: "results-before-quarantine",
    page_argument: "--page=scan",
    scans_fixture_directory: true,
    pointer_clicks: &QUARANTINE_ALL_CLICKS,
};

impl PageCapture {
    const fn idle_page(screenshot_name: &'static str, page_argument: &'static str) -> Self {
        Self {
            screenshot_name,
            page_argument,
            scans_fixture_directory: false,
            pointer_clicks: &[],
        }
    }

    fn application_arguments(&self, screenshot_fixtures: &ScreenshotFixtures) -> Vec<OsString> {
        let scan_target = self
            .scans_fixture_directory
            .then(|| screenshot_fixtures.scan_directory.clone().into_os_string());
        std::iter::once(OsString::from(self.page_argument))
            .chain(scan_target)
            .collect()
    }
}

fn start_tool(
    tool_command: &mut Command,
    tool_name: &'static str,
) -> Result<std::process::Child, TaskFailure> {
    tool_command
        .spawn()
        .map_err(|start_failure| TaskFailure::ToolNotStarted {
            tool_name,
            start_failure,
        })
}

fn run_tool_to_completion(
    tool_command: &mut Command,
    tool_name: &'static str,
) -> Result<(), TaskFailure> {
    let exit_status = start_tool(tool_command, tool_name)?.wait()?;
    if exit_status.success() {
        Ok(())
    } else {
        Err(TaskFailure::ToolFailed {
            tool_name,
            exit_status,
        })
    }
}

fn take_screenshot(
    sway_session: &HeadlessSwaySession,
    output_directory: &Path,
    screenshot_name: &str,
) -> Result<(), TaskFailure> {
    run_tool_to_completion(
        sway_session
            .session_command("grim")
            .arg(output_directory.join(format!("{screenshot_name}.png"))),
        "grim",
    )
}

fn capture_page(
    sway_session: &HeadlessSwaySession,
    screenshot_fixtures: &ScreenshotFixtures,
    output_directory: &Path,
    page_capture: &PageCapture,
    pointer_input: &mut VirtualPointerInput,
) -> Result<(), TaskFailure> {
    let mut application_process = start_tool(
        sway_session
            .session_command("clamui")
            .env("PATH", &screenshot_fixtures.search_path)
            .args(page_capture.application_arguments(screenshot_fixtures))
            .stdin(Stdio::null()),
        "clamui",
    )?;
    thread::sleep(PAGE_SETTLE_DURATION);
    let capture_outcome =
        take_screenshot(sway_session, output_directory, page_capture.screenshot_name).and_then(
            |()| {
                page_capture
                    .pointer_clicks
                    .iter()
                    .try_for_each(|pointer_click| {
                        pointer_input.click_at(ScreenPosition {
                            logical_x: pointer_click.click_horizontal,
                            logical_y: pointer_click.click_vertical,
                        })?;
                        pointer_input.move_to(POINTER_REST_POSITION)?;
                        thread::sleep(CLICK_SETTLE_DURATION);
                        take_screenshot(
                            sway_session,
                            output_directory,
                            pointer_click.screenshot_name,
                        )
                    })
            },
        );
    let _already_exited = application_process.kill();
    let _exit_status = application_process.wait();
    thread::sleep(APPLICATION_EXIT_DURATION);
    capture_outcome
}

fn verify_fixtures_were_quarantined(
    screenshot_fixtures: &ScreenshotFixtures,
) -> Result<(), TaskFailure> {
    let remaining_threats = fs::read_dir(&screenshot_fixtures.scan_directory)?
        .filter_map(Result::ok)
        .filter(|scan_entry| scan_entry.file_name().to_string_lossy().contains("eicar"))
        .count();
    if remaining_threats == 0 {
        Ok(())
    } else {
        Err(TaskFailure::InteractionHadNoEffect {
            expected_effect: "Quarantine All removes every detected fixture from the scan folder",
        })
    }
}

pub fn render_page_screenshots(output_directory: &Path) -> Result<(), TaskFailure> {
    fs::create_dir_all(output_directory)?;
    let absolute_output = fs::canonicalize(output_directory)?;
    let sway_session = HeadlessSwaySession::start_session()?;
    let _fixture_systemd = serve_fixture_systemd(&sway_session.bus_address())?;
    let screenshot_fixtures = prepare_screenshot_fixtures(sway_session.session_root())?;
    let mut pointer_input =
        VirtualPointerInput::connect(&sway_session.wayland_socket_path(), SCREEN_SIZE)?;
    PAGE_CAPTURES.iter().try_for_each(|page_capture| {
        capture_page(
            &sway_session,
            &screenshot_fixtures,
            &absolute_output,
            page_capture,
            &mut pointer_input,
        )
    })?;
    capture_page(
        &sway_session,
        &screenshot_fixtures,
        &absolute_output,
        &QUARANTINE_ALL_CAPTURE,
        &mut pointer_input,
    )?;
    verify_fixtures_were_quarantined(&screenshot_fixtures)
}

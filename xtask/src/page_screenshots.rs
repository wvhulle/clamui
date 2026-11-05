use std::{
    ffi::OsString,
    fs,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use crate::{
    headless_sway_session::HeadlessSwaySession,
    screenshot_fixtures::{ScreenshotFixtures, prepare_screenshot_fixtures},
    task_failure::TaskFailure,
};

const PAGE_SETTLE_DURATION: Duration = Duration::from_secs(4);
const APPLICATION_EXIT_DURATION: Duration = Duration::from_millis(500);

struct PageCapture {
    screenshot_name: &'static str,
    page_argument: &'static str,
    scans_fixture_directory: bool,
}

const PAGE_CAPTURES: [PageCapture; 8] = [
    PageCapture::idle_page("scan", "--page=scan"),
    PageCapture {
        screenshot_name: "scan-result",
        page_argument: "--page=scan",
        scans_fixture_directory: true,
    },
    PageCapture::idle_page("database", "--page=database"),
    PageCapture::idle_page("components", "--page=components"),
    PageCapture::idle_page("quarantine", "--page=quarantine"),
    PageCapture::idle_page("logs", "--page=logs"),
    PageCapture::idle_page("statistics", "--page=statistics"),
    PageCapture::idle_page("preferences", "--page=preferences"),
];

impl PageCapture {
    const fn idle_page(screenshot_name: &'static str, page_argument: &'static str) -> Self {
        Self {
            screenshot_name,
            page_argument,
            scans_fixture_directory: false,
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

fn capture_page(
    sway_session: &HeadlessSwaySession,
    screenshot_fixtures: &ScreenshotFixtures,
    output_directory: &Path,
    page_capture: &PageCapture,
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
    let screenshot_path = output_directory.join(format!("{}.png", page_capture.screenshot_name));
    let grim_outcome = start_tool(
        sway_session.session_command("grim").arg(&screenshot_path),
        "grim",
    )
    .and_then(|mut grim_process| Ok(grim_process.wait()?));
    let _already_exited = application_process.kill();
    let _exit_status = application_process.wait();
    thread::sleep(APPLICATION_EXIT_DURATION);
    let grim_status = grim_outcome?;
    if grim_status.success() {
        Ok(())
    } else {
        Err(TaskFailure::ToolFailed {
            tool_name: "grim",
            exit_status: grim_status,
        })
    }
}

pub fn render_page_screenshots(output_directory: &Path) -> Result<(), TaskFailure> {
    fs::create_dir_all(output_directory)?;
    let absolute_output = fs::canonicalize(output_directory)?;
    let sway_session = HeadlessSwaySession::start_session()?;
    let screenshot_fixtures = prepare_screenshot_fixtures(sway_session.session_root())?;
    PAGE_CAPTURES.iter().try_for_each(|page_capture| {
        capture_page(
            &sway_session,
            &screenshot_fixtures,
            &absolute_output,
            page_capture,
        )
    })
}

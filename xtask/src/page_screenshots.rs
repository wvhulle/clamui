use std::{
    ffi::OsString,
    fs,
    path::Path,
    process::{Child, Stdio},
    thread,
    time::Duration,
};

use gtk_scene_capture::{
    accessible_widget_lookup::{AccessibleTree, WidgetTarget},
    headless_sway_session::HeadlessSwaySession,
    scene_driver::{SceneDriver, UserInteraction},
    virtual_pointer_input::ScreenSize,
};

use crate::{
    fixture_systemd_service::serve_fixture_systemd,
    screenshot_fixtures::{ScreenshotFixtures, prepare_screenshot_fixtures},
    task_failure::TaskFailure,
};

const PAGE_SETTLE_DURATION: Duration = Duration::from_secs(4);
const APPLICATION_EXIT_DURATION: Duration = Duration::from_millis(500);
pub const SCREEN_SIZE: ScreenSize = ScreenSize {
    logical_width: 900,
    logical_height: 700,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanFixtureUse {
    IdlePage,
    ScansFixtureFolder,
}

pub struct PageScenario {
    pub page_argument: &'static str,
    pub scan_fixture_use: ScanFixtureUse,
    pub user_interactions: Vec<UserInteraction>,
}

fn capture(screenshot_name: &'static str) -> UserInteraction {
    UserInteraction::CaptureScreen { screenshot_name }
}

fn idle_page_capture(page_argument: &'static str, screenshot_name: &'static str) -> PageScenario {
    PageScenario {
        page_argument,
        scan_fixture_use: ScanFixtureUse::IdlePage,
        user_interactions: vec![capture(screenshot_name)],
    }
}

fn click(widget_target: WidgetTarget) -> UserInteraction {
    UserInteraction::ClickWidget(widget_target)
}

fn wait_for(widget_target: WidgetTarget) -> UserInteraction {
    UserInteraction::WaitForWidget(widget_target)
}

fn page_scenarios() -> Vec<PageScenario> {
    vec![
        PageScenario {
            page_argument: "--page=scan",
            scan_fixture_use: ScanFixtureUse::IdlePage,
            user_interactions: vec![
                capture("scan"),
                click(WidgetTarget::button("Manage Profiles")),
                capture("profile-manager"),
            ],
        },
        PageScenario {
            page_argument: "--page=scan",
            scan_fixture_use: ScanFixtureUse::IdlePage,
            user_interactions: vec![
                click(WidgetTarget::list_item("Exclusions")),
                capture("scan-exclusions"),
            ],
        },
        PageScenario {
            page_argument: "--page=scan",
            scan_fixture_use: ScanFixtureUse::ScansFixtureFolder,
            user_interactions: vec![
                wait_for(WidgetTarget::button("New Scan")),
                capture("scan-result"),
            ],
        },
        idle_page_capture("--page=database", "database"),
        idle_page_capture("--page=quarantine", "quarantine"),
        PageScenario {
            page_argument: "--page=logs",
            scan_fixture_use: ScanFixtureUse::IdlePage,
            user_interactions: vec![
                capture("logs"),
                click(WidgetTarget::list_item("Found 2 threats")),
                capture("logs-entry-selected"),
            ],
        },
        idle_page_capture("--page=protection", "protection"),
        PageScenario {
            page_argument: "--page=detections",
            scan_fixture_use: ScanFixtureUse::IdlePage,
            user_interactions: vec![
                capture("detections"),
                click(WidgetTarget::list_item("invoice.pdf.exe")),
                capture("detection-incident"),
            ],
        },
        PageScenario {
            page_argument: "--page=preferences",
            scan_fixture_use: ScanFixtureUse::IdlePage,
            user_interactions: vec![
                capture("preferences"),
                click(WidgetTarget::page_tab("Online Lookups")),
                capture("preferences-online-lookups"),
            ],
        },
        PageScenario {
            page_argument: "--page=scan",
            scan_fixture_use: ScanFixtureUse::ScansFixtureFolder,
            user_interactions: vec![
                wait_for(WidgetTarget::button("New Scan")),
                capture("results-before-quarantine"),
                click(WidgetTarget::button("Quarantine 2 Threats")),
                capture("results-quarantine-confirmation"),
                click(
                    WidgetTarget::button("Quarantine")
                        .inside(WidgetTarget::alert("Move to Quarantine?")),
                ),
                capture("results-quarantined"),
            ],
        },
    ]
}

fn application_arguments(
    page_argument: &str,
    scan_fixture_use: ScanFixtureUse,
    screenshot_fixtures: &ScreenshotFixtures,
) -> Vec<OsString> {
    let scan_target = (scan_fixture_use == ScanFixtureUse::ScansFixtureFolder)
        .then(|| screenshot_fixtures.scan_directory.clone().into_os_string());
    std::iter::once(OsString::from(page_argument))
        .chain(scan_target)
        .collect()
}

fn launch_application(
    headless_session: &HeadlessSwaySession,
    screenshot_fixtures: &ScreenshotFixtures,
    page_argument: &str,
    scan_fixture_use: ScanFixtureUse,
) -> Result<Child, TaskFailure> {
    let application_process = headless_session
        .session_command("lazaret")
        .env("PATH", &screenshot_fixtures.search_path)
        .args(application_arguments(
            page_argument,
            scan_fixture_use,
            screenshot_fixtures,
        ))
        .stdin(Stdio::null())
        .spawn()
        .map_err(|start_failure| TaskFailure::ToolNotStarted {
            tool_name: "lazaret",
            start_failure,
        })?;
    thread::sleep(PAGE_SETTLE_DURATION);
    Ok(application_process)
}

fn stop_application(mut application_process: Child) {
    let _already_exited = application_process.kill();
    let _exit_status = application_process.wait();
    thread::sleep(APPLICATION_EXIT_DURATION);
}

fn run_page_scenario(
    headless_session: &HeadlessSwaySession,
    screenshot_fixtures: &ScreenshotFixtures,
    output_directory: &Path,
    page_scenario: &PageScenario,
) -> Result<(), TaskFailure> {
    let application_process = launch_application(
        headless_session,
        screenshot_fixtures,
        page_scenario.page_argument,
        page_scenario.scan_fixture_use,
    )?;
    let scenario_outcome = SceneDriver::attach(headless_session, output_directory)
        .and_then(|mut scene_driver| scene_driver.perform_all(&page_scenario.user_interactions));
    stop_application(application_process);
    Ok(scenario_outcome?)
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

struct PreparedSession {
    headless_session: HeadlessSwaySession,
    _fixture_systemd: zbus::blocking::Connection,
    screenshot_fixtures: ScreenshotFixtures,
}

fn prepare_session() -> Result<PreparedSession, TaskFailure> {
    let headless_session = HeadlessSwaySession::start_session(SCREEN_SIZE)?;
    let fixture_systemd = serve_fixture_systemd(&headless_session.bus_address())?;
    let screenshot_fixtures = prepare_screenshot_fixtures(headless_session.session_root())?;
    Ok(PreparedSession {
        headless_session,
        _fixture_systemd: fixture_systemd,
        screenshot_fixtures,
    })
}

pub fn render_page_screenshots(output_directory: &Path) -> Result<(), TaskFailure> {
    fs::create_dir_all(output_directory)?;
    let absolute_output = fs::canonicalize(output_directory)?;
    let prepared_session = prepare_session()?;
    page_scenarios().iter().try_for_each(|page_scenario| {
        run_page_scenario(
            &prepared_session.headless_session,
            &prepared_session.screenshot_fixtures,
            &absolute_output,
            page_scenario,
        )
    })?;
    verify_fixtures_were_quarantined(&prepared_session.screenshot_fixtures)
}

pub fn list_visible_widgets(page_argument: &str) -> Result<Vec<String>, TaskFailure> {
    let prepared_session = prepare_session()?;
    let application_process = launch_application(
        &prepared_session.headless_session,
        &prepared_session.screenshot_fixtures,
        page_argument,
        ScanFixtureUse::IdlePage,
    )?;
    let async_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let widget_descriptions = async_runtime.block_on(async {
        AccessibleTree::connect_through(&prepared_session.headless_session.bus_address())
            .await?
            .describe_visible_widgets()
            .await
    });
    stop_application(application_process);
    widget_descriptions
        .map_err(|lookup_failure| TaskFailure::SceneCaptureFailed(lookup_failure.into()))
}

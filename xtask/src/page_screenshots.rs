use std::{
    env,
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
    scene_driver::{SceneDriver, UserInteraction, WidgetAccess},
    virtual_pointer_input::ScreenSize,
    webp_animation_encoding::encode_webp_animation,
};

use crate::{
    fixture_systemd_service::serve_fixture_systemd,
    screenshot_fixtures::{ScreenshotFixtures, prepare_screenshot_fixtures},
    task_failure::TaskFailure,
};

const PAGE_SETTLE_DURATION: Duration = Duration::from_secs(4);
const STEP_FRAME_DURATION: Duration = Duration::from_millis(1800);
const POINTING_FRAME_DURATION: Duration = Duration::from_millis(900);
const FINAL_FRAME_DURATION: Duration = Duration::from_secs(4);
const APPLICATION_EXIT_DURATION: Duration = Duration::from_millis(500);
const LAZARET_PROGRAM_VARIABLE: &str = "LAZARET_SCREENSHOT_PROGRAM";
const SCREENSHOT_FONTCONFIG_VARIABLE: &str = "LAZARET_SCREENSHOT_FONTCONFIG";
const SCREEN_CAPTURE_TOOLS: [&str; 4] = ["dbus-daemon", "sway", "grim", "img2webp"];
const ACCESSIBILITY_TOOLS: [&str; 1] = ["at-spi2-registryd"];
const QUARANTINING_SCENARIO: &str = "scan-results";
pub const SCREEN_SIZE: ScreenSize = ScreenSize {
    logical_width: 900,
    logical_height: 700,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanFixtureUse {
    IdlePage,
    ScansFixtureFolder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchedPage {
    StartPage,
    NamedPage(&'static str),
}

impl LaunchedPage {
    fn page_arguments(self) -> Vec<OsString> {
        match self {
            Self::StartPage => Vec::new(),
            Self::NamedPage(page_name) => vec![OsString::from(format!("--page={page_name}"))],
        }
    }
}

pub struct PageScenario {
    pub launched_page: LaunchedPage,
    pub scan_fixture_use: ScanFixtureUse,
    pub animation_name: &'static str,
    pub user_interactions: Vec<UserInteraction>,
}

fn frame() -> Vec<UserInteraction> {
    vec![UserInteraction::CaptureFrame {
        shown_for: STEP_FRAME_DURATION,
    }]
}

fn shown(screenshot_name: &'static str) -> Vec<UserInteraction> {
    vec![
        UserInteraction::CaptureScreen { screenshot_name },
        UserInteraction::CaptureFrame {
            shown_for: STEP_FRAME_DURATION,
        },
    ]
}

fn point_and_click(widget_target: WidgetTarget) -> Vec<UserInteraction> {
    vec![
        UserInteraction::HoverWidget(widget_target.clone()),
        UserInteraction::CaptureFrame {
            shown_for: POINTING_FRAME_DURATION,
        },
        UserInteraction::ClickWidget(widget_target),
    ]
}

fn wait_for(widget_target: WidgetTarget) -> Vec<UserInteraction> {
    vec![UserInteraction::WaitForWidget(widget_target)]
}

fn page_scenarios() -> Vec<PageScenario> {
    vec![
        PageScenario {
            launched_page: LaunchedPage::StartPage,
            scan_fixture_use: ScanFixtureUse::IdlePage,
            animation_name: "start-page",
            user_interactions: [shown("start-page"), frame()].concat(),
        },
        PageScenario {
            launched_page: LaunchedPage::NamedPage("signature-sources"),
            scan_fixture_use: ScanFixtureUse::IdlePage,
            animation_name: "signature-sources",
            user_interactions: [
                shown("signature-sources"),
                point_and_click(WidgetTarget::list_item("Sanesecurity")),
                frame(),
            ]
            .concat(),
        },
        PageScenario {
            launched_page: LaunchedPage::NamedPage("database-updates"),
            scan_fixture_use: ScanFixtureUse::IdlePage,
            animation_name: "database-updates",
            user_interactions: [
                shown("database-updates"),
                point_and_click(WidgetTarget::list_item("Signatures current")),
                shown("signature-update"),
            ]
            .concat(),
        },
        PageScenario {
            launched_page: LaunchedPage::NamedPage("scan-engine"),
            scan_fixture_use: ScanFixtureUse::IdlePage,
            animation_name: "scan-engine",
            user_interactions: [shown("scan-engine"), frame()].concat(),
        },
        PageScenario {
            launched_page: LaunchedPage::NamedPage("on-access"),
            scan_fixture_use: ScanFixtureUse::IdlePage,
            animation_name: "on-access",
            user_interactions: [shown("on-access"), frame()].concat(),
        },
        PageScenario {
            launched_page: LaunchedPage::NamedPage("scheduled-scans"),
            scan_fixture_use: ScanFixtureUse::IdlePage,
            animation_name: "scheduled-scans",
            user_interactions: [shown("scheduled-scans"), frame()].concat(),
        },
        PageScenario {
            launched_page: LaunchedPage::NamedPage("manual-scan"),
            scan_fixture_use: ScanFixtureUse::IdlePage,
            animation_name: "manual-scan",
            user_interactions: [
                shown("manual-scan"),
                point_and_click(WidgetTarget::button("Manage Profiles")),
                shown("profile-manager"),
            ]
            .concat(),
        },
        PageScenario {
            launched_page: LaunchedPage::NamedPage("manual-scan"),
            scan_fixture_use: ScanFixtureUse::IdlePage,
            animation_name: "scan-exclusions",
            user_interactions: [
                frame(),
                point_and_click(WidgetTarget::list_item("node_modules")),
                shown("scan-exclusions"),
            ]
            .concat(),
        },
        PageScenario {
            launched_page: LaunchedPage::NamedPage("removable-drives"),
            scan_fixture_use: ScanFixtureUse::IdlePage,
            animation_name: "removable-drives",
            user_interactions: [shown("removable-drives"), frame()].concat(),
        },
        PageScenario {
            launched_page: LaunchedPage::NamedPage("detections"),
            scan_fixture_use: ScanFixtureUse::IdlePage,
            animation_name: "detections",
            user_interactions: [
                shown("detections"),
                point_and_click(WidgetTarget::list_item("invoice.pdf.exe")),
                shown("detection-incident"),
            ]
            .concat(),
        },
        PageScenario {
            launched_page: LaunchedPage::NamedPage("quarantine"),
            scan_fixture_use: ScanFixtureUse::IdlePage,
            animation_name: "quarantine",
            user_interactions: [
                shown("quarantine"),
                point_and_click(WidgetTarget::list_item("Win.Trojan.Agent")),
                frame(),
            ]
            .concat(),
        },
        PageScenario {
            launched_page: LaunchedPage::NamedPage("trusted-detections"),
            scan_fixture_use: ScanFixtureUse::IdlePage,
            animation_name: "trusted-detections",
            user_interactions: [shown("trusted-detections"), frame()].concat(),
        },
        PageScenario {
            launched_page: LaunchedPage::NamedPage("sent-samples"),
            scan_fixture_use: ScanFixtureUse::IdlePage,
            animation_name: "sent-samples",
            user_interactions: [shown("sent-samples"), frame()].concat(),
        },
        PageScenario {
            launched_page: LaunchedPage::NamedPage("manual-scan"),
            scan_fixture_use: ScanFixtureUse::ScansFixtureFolder,
            animation_name: "scan-results",
            user_interactions: [
                wait_for(WidgetTarget::button("New Scan")),
                vec![UserInteraction::CaptureScreen {
                    screenshot_name: "scan-result",
                }],
                shown("results-before-quarantine"),
                point_and_click(WidgetTarget::button("Quarantine 2 Threats")),
                shown("results-quarantine-confirmation"),
                point_and_click(
                    WidgetTarget::button("Quarantine")
                        .inside(WidgetTarget::alert("Move to Quarantine?")),
                ),
                shown("results-quarantined"),
            ]
            .concat(),
        },
        PageScenario {
            launched_page: LaunchedPage::NamedPage("preferences"),
            scan_fixture_use: ScanFixtureUse::IdlePage,
            animation_name: "preferences",
            user_interactions: [shown("preferences"), frame()].concat(),
        },
        PageScenario {
            launched_page: LaunchedPage::NamedPage("online-services"),
            scan_fixture_use: ScanFixtureUse::IdlePage,
            animation_name: "online-services",
            user_interactions: [shown("online-services"), frame()].concat(),
        },
    ]
}

fn application_arguments(
    page_arguments: Vec<OsString>,
    scan_fixture_use: ScanFixtureUse,
    screenshot_fixtures: &ScreenshotFixtures,
) -> Vec<OsString> {
    let scan_target = (scan_fixture_use == ScanFixtureUse::ScansFixtureFolder)
        .then(|| screenshot_fixtures.scan_directory.clone().into_os_string());
    page_arguments.into_iter().chain(scan_target).collect()
}

fn lazaret_program() -> OsString {
    env::var_os(LAZARET_PROGRAM_VARIABLE).unwrap_or_else(|| OsString::from("lazaret"))
}

fn program_on_path(program_name: &str) -> bool {
    env::var_os("PATH").is_some_and(|search_path| {
        env::split_paths(&search_path)
            .any(|search_directory| search_directory.join(program_name).is_file())
    })
}

fn check_required_tools(widget_access: WidgetAccess) -> Result<(), TaskFailure> {
    let accessibility_tools: &[&str] = match widget_access {
        WidgetAccess::ScreenOnly => &[],
        WidgetAccess::WidgetInteraction => &ACCESSIBILITY_TOOLS,
    };
    let missing_tools: Vec<&str> = SCREEN_CAPTURE_TOOLS
        .iter()
        .chain(accessibility_tools)
        .copied()
        .filter(|tool_name| !program_on_path(tool_name))
        .collect();
    if missing_tools.is_empty() {
        Ok(())
    } else {
        Err(TaskFailure::ScreenshotToolsMissing {
            missing_tools: missing_tools.join(", "),
        })
    }
}

fn launch_application(
    headless_session: &HeadlessSwaySession,
    screenshot_fixtures: &ScreenshotFixtures,
    page_arguments: Vec<OsString>,
    scan_fixture_use: ScanFixtureUse,
    widget_access: WidgetAccess,
) -> Result<Child, TaskFailure> {
    if widget_access == WidgetAccess::WidgetInteraction {
        headless_session.start_accessibility()?;
    }
    let mut application_command = headless_session.session_command(lazaret_program());
    if let Some(screenshot_fontconfig) = env::var_os(SCREENSHOT_FONTCONFIG_VARIABLE) {
        application_command.env("FONTCONFIG_FILE", screenshot_fontconfig);
    }
    let application_process = application_command
        .env("PATH", &screenshot_fixtures.search_path)
        .env("GTK_A11Y", widget_access.gtk_accessibility_backend())
        .args(application_arguments(
            page_arguments,
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
    let widget_access = WidgetAccess::required_by(&page_scenario.user_interactions);
    let application_process = launch_application(
        headless_session,
        screenshot_fixtures,
        page_scenario.launched_page.page_arguments(),
        page_scenario.scan_fixture_use,
        widget_access,
    )?;
    let scenario_outcome = SceneDriver::attach(headless_session, output_directory, widget_access)
        .and_then(|mut scene_driver| {
            scene_driver.perform_all(&page_scenario.user_interactions)?;
            Ok(scene_driver.take_animation_frames())
        });
    stop_application(application_process);
    let mut animation_frames = scenario_outcome?;
    if let Some(final_frame) = animation_frames.last_mut() {
        final_frame.shown_for = FINAL_FRAME_DURATION;
    }
    let animation_path = output_directory.join(format!("{}.webp", page_scenario.animation_name));
    encode_webp_animation(&animation_frames, &animation_path)?;
    println!("rendered {}", animation_path.display());
    Ok(())
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

fn prepare_session(widget_access: WidgetAccess) -> Result<PreparedSession, TaskFailure> {
    check_required_tools(widget_access)?;
    let headless_session = HeadlessSwaySession::start_session(SCREEN_SIZE)?;
    let fixture_systemd = serve_fixture_systemd(&headless_session.bus_address())?;
    let screenshot_fixtures = prepare_screenshot_fixtures(headless_session.session_root())?;
    Ok(PreparedSession {
        headless_session,
        _fixture_systemd: fixture_systemd,
        screenshot_fixtures,
    })
}

fn select_scenarios(selected_names: &[String]) -> Result<Vec<PageScenario>, TaskFailure> {
    let all_scenarios = page_scenarios();
    if let Some(unknown_name) = selected_names.iter().find(|selected_name| {
        !all_scenarios
            .iter()
            .any(|page_scenario| page_scenario.animation_name == selected_name.as_str())
    }) {
        return Err(TaskFailure::ScenarioUnknown {
            requested_name: unknown_name.clone(),
            known_names: all_scenarios
                .iter()
                .map(|page_scenario| page_scenario.animation_name)
                .collect::<Vec<_>>()
                .join(", "),
        });
    }
    Ok(all_scenarios
        .into_iter()
        .filter(|page_scenario| {
            selected_names.is_empty()
                || selected_names
                    .iter()
                    .any(|selected_name| selected_name == page_scenario.animation_name)
        })
        .collect())
}

fn widget_access_for_all(page_scenarios: &[PageScenario]) -> WidgetAccess {
    if page_scenarios.iter().any(|page_scenario| {
        WidgetAccess::required_by(&page_scenario.user_interactions)
            == WidgetAccess::WidgetInteraction
    }) {
        WidgetAccess::WidgetInteraction
    } else {
        WidgetAccess::ScreenOnly
    }
}

pub fn render_page_screenshots(
    output_directory: &Path,
    selected_names: &[String],
) -> Result<(), TaskFailure> {
    let selected_scenarios = select_scenarios(selected_names)?;
    fs::create_dir_all(output_directory)?;
    let absolute_output = fs::canonicalize(output_directory)?;
    let prepared_session = prepare_session(widget_access_for_all(&selected_scenarios))?;
    selected_scenarios.iter().try_for_each(|page_scenario| {
        run_page_scenario(
            &prepared_session.headless_session,
            &prepared_session.screenshot_fixtures,
            &absolute_output,
            page_scenario,
        )
    })?;
    if selected_scenarios
        .iter()
        .any(|page_scenario| page_scenario.animation_name == QUARANTINING_SCENARIO)
    {
        verify_fixtures_were_quarantined(&prepared_session.screenshot_fixtures)
    } else {
        Ok(())
    }
}

pub fn list_visible_widgets(page_argument: &str) -> Result<Vec<String>, TaskFailure> {
    let prepared_session = prepare_session(WidgetAccess::WidgetInteraction)?;
    let application_process = launch_application(
        &prepared_session.headless_session,
        &prepared_session.screenshot_fixtures,
        vec![OsString::from(page_argument)],
        ScanFixtureUse::IdlePage,
        WidgetAccess::WidgetInteraction,
    )?;
    let async_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let widget_descriptions = async_runtime.block_on(async {
        AccessibleTree::connect_to(
            &prepared_session
                .headless_session
                .accessibility_bus_address(),
        )
        .await?
        .describe_visible_widgets()
        .await
    });
    stop_application(application_process);
    widget_descriptions
        .map_err(|lookup_failure| TaskFailure::SceneCaptureFailed(lookup_failure.into()))
}

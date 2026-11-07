use std::path::PathBuf;

use crate::application_window::application_pages::{ALL_APPLICATION_PAGES, ApplicationPage};

const STARTUP_PAGE_PREFIX: &str = "--page=";
const BACKGROUND_ARGUMENT: &str = "--background";
const PREFERENCES_PAGE_NAME: &str = "preferences";
const ONLINE_SERVICES_PAGE_NAME: &str = "online-services";
const PAGE_NAME_ALIASES: [(&str, StartupPage); 6] = [
    ("protection", StartupPage::FirstAreaNeedingAttention),
    ("logs", StartupPage::FirstAreaNeedingAttention),
    (
        "signatures",
        StartupPage::ApplicationPage(ApplicationPage::SignatureSources),
    ),
    (
        "database",
        StartupPage::ApplicationPage(ApplicationPage::DatabaseUpdates),
    ),
    (
        "scan",
        StartupPage::ApplicationPage(ApplicationPage::ManualScan),
    ),
    (
        "analysis",
        StartupPage::ApplicationPage(ApplicationPage::TrustedDetections),
    ),
];
const DEFAULT_STARTUP_PAGE: StartupPage = StartupPage::FirstAreaNeedingAttention;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupPage {
    ApplicationPage(ApplicationPage),
    FirstAreaNeedingAttention,
    PreferencesDialog,
    OnlineServicesPreferences,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StartupPageRequest {
    RecognizedPage(StartupPage),
    UnrecognizedPage { requested_page_name: String },
}

#[derive(Debug, Eq, PartialEq)]
pub struct StartupRequest {
    pub startup_page: StartupPageRequest,
    pub scan_targets: Vec<PathBuf>,
    pub start_in_background: bool,
}

impl StartupPageRequest {
    fn from_page_name(requested_page_name: &str) -> Self {
        if requested_page_name == PREFERENCES_PAGE_NAME {
            return Self::RecognizedPage(StartupPage::PreferencesDialog);
        }
        if requested_page_name == ONLINE_SERVICES_PAGE_NAME {
            return Self::RecognizedPage(StartupPage::OnlineServicesPreferences);
        }
        ApplicationPage::from_page_name(requested_page_name)
            .map(StartupPage::ApplicationPage)
            .or_else(|| {
                PAGE_NAME_ALIASES
                    .into_iter()
                    .find(|(alias_name, _aliased_page)| *alias_name == requested_page_name)
                    .map(|(_alias_name, aliased_page)| aliased_page)
            })
            .map_or_else(
                || Self::UnrecognizedPage {
                    requested_page_name: requested_page_name.to_owned(),
                },
                Self::RecognizedPage,
            )
    }

    pub const fn shown_startup_page(&self) -> StartupPage {
        match self {
            Self::RecognizedPage(startup_page) => *startup_page,
            Self::UnrecognizedPage { .. } => DEFAULT_STARTUP_PAGE,
        }
    }
}

pub fn known_startup_page_names() -> Vec<&'static str> {
    ALL_APPLICATION_PAGES
        .iter()
        .map(|application_page| application_page.page_name())
        .chain([PREFERENCES_PAGE_NAME])
        .collect()
}

pub fn parse_startup_arguments(
    command_line_arguments: impl IntoIterator<Item = String>,
) -> StartupRequest {
    command_line_arguments.into_iter().skip(1).fold(
        StartupRequest {
            startup_page: StartupPageRequest::RecognizedPage(DEFAULT_STARTUP_PAGE),
            scan_targets: Vec::new(),
            start_in_background: false,
        },
        |mut startup_request, command_line_argument| {
            if command_line_argument == BACKGROUND_ARGUMENT {
                startup_request.start_in_background = true;
                return startup_request;
            }
            match command_line_argument.strip_prefix(STARTUP_PAGE_PREFIX) {
                Some(requested_page_name) => {
                    startup_request.startup_page =
                        StartupPageRequest::from_page_name(requested_page_name);
                }
                None => {
                    let scan_target = PathBuf::from(&command_line_argument);
                    startup_request
                        .scan_targets
                        .push(std::path::absolute(&scan_target).unwrap_or(scan_target));
                }
            }
            startup_request
        },
    )
}

#[cfg(test)]
mod startup_arguments_tests {
    use super::*;

    fn parsed_arguments(command_line_arguments: &[&str]) -> StartupRequest {
        parse_startup_arguments(
            command_line_arguments
                .iter()
                .map(|command_line_argument| (*command_line_argument).to_owned()),
        )
    }

    #[test]
    fn no_arguments_open_the_first_area_needing_attention_without_targets() {
        assert_eq!(
            parsed_arguments(&["lazaret"]),
            StartupRequest {
                startup_page: StartupPageRequest::RecognizedPage(DEFAULT_STARTUP_PAGE),
                scan_targets: Vec::new(),
                start_in_background: false,
            }
        );
    }

    #[test]
    fn page_selection_and_scan_targets_are_separated() {
        assert_eq!(
            parsed_arguments(&["lazaret", "--page=quarantine", "/scan/one", "/scan/two"]),
            StartupRequest {
                startup_page: StartupPageRequest::RecognizedPage(StartupPage::ApplicationPage(
                    ApplicationPage::Quarantine
                )),
                scan_targets: vec![PathBuf::from("/scan/one"), PathBuf::from("/scan/two")],
                start_in_background: false,
            }
        );
    }

    #[test]
    fn the_background_flag_is_not_mistaken_for_a_scan_target() {
        let startup_request = parsed_arguments(&["lazaret", "--background"]);
        assert!(startup_request.start_in_background);
        assert!(startup_request.scan_targets.is_empty());
    }

    #[test]
    fn the_preferences_page_opens_the_preferences_dialog() {
        assert_eq!(
            parsed_arguments(&["lazaret", "--page=preferences"]).startup_page,
            StartupPageRequest::RecognizedPage(StartupPage::PreferencesDialog)
        );
        assert_eq!(
            parsed_arguments(&["lazaret", "--page=online-services"]).startup_page,
            StartupPageRequest::RecognizedPage(StartupPage::OnlineServicesPreferences)
        );
    }

    #[test]
    fn the_database_page_opens_the_database_updates_page() {
        ["--page=database", "--page=database-updates"]
            .into_iter()
            .for_each(|page_argument| {
                assert_eq!(
                    parsed_arguments(&["lazaret", page_argument]).startup_page,
                    StartupPageRequest::RecognizedPage(StartupPage::ApplicationPage(
                        ApplicationPage::DatabaseUpdates
                    ))
                );
            });
    }

    #[test]
    fn each_area_page_opens_by_its_name() {
        [
            ("--page=scan-engine", ApplicationPage::ScanEngine),
            ("--page=on-access", ApplicationPage::OnAccessScanning),
            ("--page=scheduled-scans", ApplicationPage::ScheduledScans),
            ("--page=manual-scan", ApplicationPage::ManualScan),
            (
                "--page=signature-sources",
                ApplicationPage::SignatureSources,
            ),
            (
                "--page=trusted-detections",
                ApplicationPage::TrustedDetections,
            ),
            ("--page=sent-samples", ApplicationPage::SentSamples),
        ]
        .into_iter()
        .for_each(|(page_argument, expected_page)| {
            assert_eq!(
                parsed_arguments(&["lazaret", page_argument]).startup_page,
                StartupPageRequest::RecognizedPage(StartupPage::ApplicationPage(expected_page))
            );
        });
    }

    #[test]
    fn an_unknown_page_is_reported_and_opens_the_first_area_needing_attention() {
        let startup_page = parsed_arguments(&["lazaret", "--page=quarantaine"]).startup_page;
        assert_eq!(
            startup_page,
            StartupPageRequest::UnrecognizedPage {
                requested_page_name: "quarantaine".to_owned()
            }
        );
        assert_eq!(startup_page.shown_startup_page(), DEFAULT_STARTUP_PAGE);
    }

    #[test]
    fn old_page_names_still_open_their_new_pages() {
        [
            ("protection", StartupPage::FirstAreaNeedingAttention),
            ("logs", StartupPage::FirstAreaNeedingAttention),
            (
                "signatures",
                StartupPage::ApplicationPage(ApplicationPage::SignatureSources),
            ),
            (
                "database",
                StartupPage::ApplicationPage(ApplicationPage::DatabaseUpdates),
            ),
            (
                "scan",
                StartupPage::ApplicationPage(ApplicationPage::ManualScan),
            ),
            (
                "analysis",
                StartupPage::ApplicationPage(ApplicationPage::TrustedDetections),
            ),
        ]
        .into_iter()
        .for_each(|(old_name, expected_page)| {
            assert_eq!(
                parsed_arguments(&["lazaret", &format!("--page={old_name}")]).startup_page,
                StartupPageRequest::RecognizedPage(expected_page),
                "{old_name}"
            );
        });
    }

    #[test]
    fn hardening_is_no_longer_a_page() {
        assert_eq!(
            parsed_arguments(&["lazaret", "--page=hardening"])
                .startup_page
                .shown_startup_page(),
            StartupPage::FirstAreaNeedingAttention
        );
    }

    #[test]
    fn every_known_page_name_is_recognized() {
        known_startup_page_names()
            .into_iter()
            .for_each(|known_page_name| {
                assert!(matches!(
                    StartupPageRequest::from_page_name(known_page_name),
                    StartupPageRequest::RecognizedPage(_)
                ));
            });
    }
}

use std::path::PathBuf;

const STARTUP_PAGE_PREFIX: &str = "--page=";
const BACKGROUND_ARGUMENT: &str = "--background";
pub const DEFAULT_STARTUP_PAGE: &str = "protection";

#[derive(Debug, Eq, PartialEq)]
pub struct StartupRequest {
    pub startup_page: String,
    pub scan_targets: Vec<PathBuf>,
    pub start_in_background: bool,
}

pub fn parse_startup_arguments(
    command_line_arguments: impl IntoIterator<Item = String>,
) -> StartupRequest {
    command_line_arguments.into_iter().skip(1).fold(
        StartupRequest {
            startup_page: DEFAULT_STARTUP_PAGE.to_owned(),
            scan_targets: Vec::new(),
            start_in_background: false,
        },
        |mut startup_request, command_line_argument| {
            if command_line_argument == BACKGROUND_ARGUMENT {
                startup_request.start_in_background = true;
                return startup_request;
            }
            match command_line_argument.strip_prefix(STARTUP_PAGE_PREFIX) {
                Some(startup_page) => startup_page.clone_into(&mut startup_request.startup_page),
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
    fn no_arguments_open_the_protection_page_without_targets() {
        assert_eq!(
            parsed_arguments(&["lazaret"]),
            StartupRequest {
                startup_page: DEFAULT_STARTUP_PAGE.to_owned(),
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
                startup_page: "quarantine".to_owned(),
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
}

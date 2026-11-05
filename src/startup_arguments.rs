use std::path::PathBuf;

const STARTUP_PAGE_PREFIX: &str = "--page=";
pub const DEFAULT_STARTUP_PAGE: &str = "protection";

#[derive(Debug, Eq, PartialEq)]
pub struct StartupRequest {
    pub startup_page: String,
    pub scan_targets: Vec<PathBuf>,
}

pub fn parse_startup_arguments(
    command_line_arguments: impl IntoIterator<Item = String>,
) -> StartupRequest {
    command_line_arguments.into_iter().skip(1).fold(
        StartupRequest {
            startup_page: DEFAULT_STARTUP_PAGE.to_owned(),
            scan_targets: Vec::new(),
        },
        |mut startup_request, command_line_argument| {
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
            parsed_arguments(&["clamui"]),
            StartupRequest {
                startup_page: DEFAULT_STARTUP_PAGE.to_owned(),
                scan_targets: Vec::new(),
            }
        );
    }

    #[test]
    fn page_selection_and_scan_targets_are_separated() {
        assert_eq!(
            parsed_arguments(&["clamui", "--page=quarantine", "/scan/one", "/scan/two"]),
            StartupRequest {
                startup_page: "quarantine".to_owned(),
                scan_targets: vec![PathBuf::from("/scan/one"), PathBuf::from("/scan/two")],
            }
        );
    }
}

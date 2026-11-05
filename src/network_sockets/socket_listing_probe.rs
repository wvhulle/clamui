use thiserror::Error;

use crate::{
    network_sockets::socket_listing_parser::{ParsedSockets, parse_socket_listing},
    system_audit::host_command_probes::{CommandProbe, run_command_probe},
};

const SOCKET_LISTING_ARGUMENTS: [&str; 7] = [
    "--no-header",
    "--numeric",
    "--all",
    "--tcp",
    "--udp",
    "--processes",
    "--oneline",
];

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SocketListingFailure {
    #[error("the socket listing timed out")]
    ToolTimedOut,
    #[error("the socket listing was too large")]
    OutputTooLarge,
    #[error("the socket listing tool is unavailable")]
    ToolUnavailable,
}

pub fn interpret_listing_probe(
    listing_probe: &CommandProbe,
) -> Result<ParsedSockets, SocketListingFailure> {
    match listing_probe {
        CommandProbe::ExitedSuccessfully { stdout_bytes } => {
            Ok(parse_socket_listing(&String::from_utf8_lossy(stdout_bytes)))
        }
        CommandProbe::ProbeTimedOut => Err(SocketListingFailure::ToolTimedOut),
        CommandProbe::OutputExceededLimit => Err(SocketListingFailure::OutputTooLarge),
        CommandProbe::ExitedWithFailure
        | CommandProbe::ProgramMissing
        | CommandProbe::StartFailed => Err(SocketListingFailure::ToolUnavailable),
    }
}

pub async fn probe_socket_listing() -> Result<ParsedSockets, SocketListingFailure> {
    interpret_listing_probe(&run_command_probe("ss", &SOCKET_LISTING_ARGUMENTS).await)
}

#[cfg(test)]
mod socket_listing_probe_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "reads the real host"]
    async fn host_listing_parses_every_line() {
        let parsed_sockets = probe_socket_listing().await.expect("host listing");
        assert!(!parsed_sockets.listed_sockets.is_empty());
        assert_eq!(parsed_sockets.unparsed_line_count, 0);
    }

    #[test]
    fn failed_probes_are_reported_to_the_page() {
        assert_eq!(
            interpret_listing_probe(&CommandProbe::ProbeTimedOut),
            Err(SocketListingFailure::ToolTimedOut)
        );
        assert_eq!(
            interpret_listing_probe(&CommandProbe::OutputExceededLimit),
            Err(SocketListingFailure::OutputTooLarge)
        );
        [
            CommandProbe::ExitedWithFailure,
            CommandProbe::ProgramMissing,
            CommandProbe::StartFailed,
        ]
        .iter()
        .for_each(|failed_probe| {
            assert_eq!(
                interpret_listing_probe(failed_probe),
                Err(SocketListingFailure::ToolUnavailable)
            );
        });
    }

    #[test]
    fn an_empty_successful_listing_is_not_a_failure() {
        assert_eq!(
            interpret_listing_probe(&CommandProbe::ExitedSuccessfully {
                stdout_bytes: Vec::new()
            }),
            Ok(ParsedSockets::default())
        );
    }

    #[test]
    fn undecodable_process_names_do_not_lose_the_whole_listing() {
        let parsed_sockets = interpret_listing_probe(&CommandProbe::ExitedSuccessfully {
            stdout_bytes:
                b"tcp LISTEN 0 1 127.0.0.1:80 0.0.0.0:* users:((\"na\xffme\",pid=7,fd=3))\n"
                    .to_vec(),
        })
        .expect("listing");
        assert_eq!(parsed_sockets.listed_sockets.len(), 1);
        assert_eq!(
            parsed_sockets.listed_sockets[0].owning_processes[0].process_id,
            7
        );
    }
}

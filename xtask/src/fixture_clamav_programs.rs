use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

pub const FIXTURE_PROGRAM_NAMES: [&str; 4] = ["clamscan", "clamdscan", "freshclam", "clamd"];
const FIXTURE_VERSION_BANNER: &str = "ClamAV 1.5.4/28173/Tue Nov  3 07:27:52 2026";
const DETECTED_NAME_MARKER: &[u8] = b"eicar";
const DETECTION_REPORT_SUFFIX: &[u8] = b": Eicar-Test-Signature FOUND\n";
const CLEAN_REPORT_SUFFIX: &[u8] = b": OK\n";
const DETECTION_EXIT_CODE: u8 = 1;

#[derive(Debug, Default, Eq, PartialEq)]
struct FixtureScanReport {
    report_bytes: Vec<u8>,
    threat_found: bool,
}

pub fn invoked_as_fixture_program() -> bool {
    env::args_os()
        .next()
        .as_deref()
        .and_then(|program_path| Path::new(program_path).file_name())
        .and_then(OsStr::to_str)
        .is_some_and(|program_name| FIXTURE_PROGRAM_NAMES.contains(&program_name))
}

fn path_is_detected(scanned_path: &[u8]) -> bool {
    scanned_path
        .windows(DETECTED_NAME_MARKER.len())
        .any(|path_window| path_window == DETECTED_NAME_MARKER)
}

fn scan_listed_paths(file_list_bytes: &[u8]) -> FixtureScanReport {
    file_list_bytes
        .split(|list_byte| *list_byte == b'\n')
        .filter(|scanned_path| !scanned_path.is_empty())
        .fold(
            FixtureScanReport::default(),
            |mut scan_report, scanned_path| {
                let path_detected = path_is_detected(scanned_path);
                scan_report.report_bytes.extend_from_slice(scanned_path);
                scan_report
                    .report_bytes
                    .extend_from_slice(if path_detected {
                        DETECTION_REPORT_SUFFIX
                    } else {
                        CLEAN_REPORT_SUFFIX
                    });
                scan_report.threat_found |= path_detected;
                scan_report
            },
        )
}

fn file_list_argument(program_arguments: &[OsString]) -> Option<&OsString> {
    program_arguments
        .windows(2)
        .find(|argument_pair| argument_pair[0] == "--file-list")
        .map(|argument_pair| &argument_pair[1])
}

fn has_argument(program_arguments: &[OsString], expected_argument: &str) -> bool {
    program_arguments
        .iter()
        .any(|program_argument| program_argument == expected_argument)
}

fn fixture_scan_report(program_arguments: &[OsString]) -> io::Result<FixtureScanReport> {
    if has_argument(program_arguments, "--version") {
        return Ok(FixtureScanReport {
            report_bytes: format!("{FIXTURE_VERSION_BANNER}\n").into_bytes(),
            threat_found: false,
        });
    }
    if has_argument(program_arguments, "--ping") {
        return Ok(FixtureScanReport {
            report_bytes: b"PONG\n".to_vec(),
            threat_found: false,
        });
    }
    match file_list_argument(program_arguments) {
        Some(file_list_path) => Ok(scan_listed_paths(&fs::read(file_list_path)?)),
        None => Ok(FixtureScanReport::default()),
    }
}

pub fn run_fixture_program() -> ExitCode {
    let program_arguments = env::args_os().skip(1).collect::<Vec<_>>();
    match fixture_scan_report(&program_arguments).and_then(|scan_report| {
        io::stdout().write_all(&scan_report.report_bytes)?;
        Ok(scan_report.threat_found)
    }) {
        Ok(true) => ExitCode::from(DETECTION_EXIT_CODE),
        Ok(false) => ExitCode::SUCCESS,
        Err(fixture_failure) => {
            eprintln!("fixture scanner: {fixture_failure}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod fixture_clamav_programs_tests {
    use super::*;

    #[test]
    fn listed_paths_are_reported_byte_exactly() {
        let scan_report = scan_listed_paths(b"/scan/eicar-\xff.txt\n/scan/report.pdf\n");
        assert_eq!(
            scan_report.report_bytes,
            b"/scan/eicar-\xff.txt: Eicar-Test-Signature FOUND\n/scan/report.pdf: OK\n"
        );
        assert!(scan_report.threat_found);
    }

    #[test]
    fn clean_lists_report_no_threat() {
        assert!(!scan_listed_paths(b"/scan/report.pdf\n").threat_found);
    }

    #[test]
    fn version_and_ping_answer_without_a_file_list() {
        assert_eq!(
            fixture_scan_report(&[OsString::from("--ping"), OsString::from("1")])
                .expect("ping report")
                .report_bytes,
            b"PONG\n"
        );
        assert!(
            String::from_utf8(
                fixture_scan_report(&[OsString::from("--version")])
                    .expect("version report")
                    .report_bytes
            )
            .expect("version text")
            .starts_with("ClamAV ")
        );
    }

    #[test]
    fn file_list_argument_is_found_after_other_options() {
        let program_arguments = [
            OsString::from("--fdpass"),
            OsString::from("-v"),
            OsString::from("--file-list"),
            OsString::from("/private/list"),
        ];
        assert_eq!(
            file_list_argument(&program_arguments),
            Some(&OsString::from("/private/list"))
        );
    }
}

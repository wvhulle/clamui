use std::{
    path::Path,
    process::{Output, Stdio},
    time::Duration,
};

use tokio::{process::Command, time::timeout};

const PROGRAM_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Eq, PartialEq)]
pub enum ProgramProbe {
    VersionReported { version_text: String },
    NotFoundOnPath,
    ProbeFailed { failure_text: String },
}

fn program_probe_from_output(version_output: &Output) -> ProgramProbe {
    if version_output.status.success() {
        ProgramProbe::VersionReported {
            version_text: String::from_utf8_lossy(&version_output.stdout)
                .lines()
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned(),
        }
    } else {
        ProgramProbe::ProbeFailed {
            failure_text: String::from_utf8_lossy(&version_output.stderr)
                .trim()
                .to_owned(),
        }
    }
}

pub async fn probe_program_version(program_path: &Path) -> ProgramProbe {
    let mut version_command = Command::new(program_path);
    version_command
        .arg("--version")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    match timeout(PROGRAM_PROBE_TIMEOUT, version_command.output()).await {
        Ok(Ok(version_output)) => program_probe_from_output(&version_output),
        Ok(Err(spawn_failure)) if spawn_failure.kind() == std::io::ErrorKind::NotFound => {
            ProgramProbe::NotFoundOnPath
        }
        Ok(Err(spawn_failure)) => ProgramProbe::ProbeFailed {
            failure_text: spawn_failure.to_string(),
        },
        Err(_probe_timed_out) => ProgramProbe::ProbeFailed {
            failure_text: "timed out".to_owned(),
        },
    }
}

pub async fn clamd_answers_ping(clamdscan_program: &Path) -> bool {
    let mut ping_command = Command::new(clamdscan_program);
    ping_command
        .args(["--ping", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    matches!(
        timeout(PROGRAM_PROBE_TIMEOUT, ping_command.status()).await,
        Ok(Ok(ping_status)) if ping_status.success()
    )
}

#[cfg(test)]
mod component_availability_tests {
    use std::os::unix::process::ExitStatusExt;

    use super::*;

    fn finished_output(exit_code: i32, stdout_text: &str, stderr_text: &str) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(exit_code << 8),
            stdout: stdout_text.as_bytes().to_vec(),
            stderr: stderr_text.as_bytes().to_vec(),
        }
    }

    #[test]
    fn version_probe_reports_the_first_output_line() {
        assert_eq!(
            program_probe_from_output(&finished_output(0, "ClamAV 1.5.4/28173\nextra\n", "")),
            ProgramProbe::VersionReported {
                version_text: "ClamAV 1.5.4/28173".to_owned(),
            }
        );
    }

    #[test]
    fn failing_programs_report_their_diagnostics() {
        assert_eq!(
            program_probe_from_output(&finished_output(3, "", "broken install\n")),
            ProgramProbe::ProbeFailed {
                failure_text: "broken install".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn missing_programs_are_distinguished_from_failing_ones() {
        assert_eq!(
            probe_program_version(Path::new("/nonexistent/clamscan")).await,
            ProgramProbe::NotFoundOnPath
        );
    }
}

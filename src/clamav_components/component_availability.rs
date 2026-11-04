use std::{path::Path, process::Stdio, time::Duration};

use tokio::{process::Command, time::timeout};

const PROGRAM_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClamavComponent {
    ClamscanScanner,
    FreshclamUpdater,
    ClamdscanClient,
    ClamdDaemon,
}

pub const ALL_CLAMAV_COMPONENTS: [ClamavComponent; 4] = [
    ClamavComponent::ClamscanScanner,
    ClamavComponent::FreshclamUpdater,
    ClamavComponent::ClamdscanClient,
    ClamavComponent::ClamdDaemon,
];

impl ClamavComponent {
    pub fn program_name(self) -> &'static str {
        match self {
            Self::ClamscanScanner => "clamscan",
            Self::FreshclamUpdater => "freshclam",
            Self::ClamdscanClient => "clamdscan",
            Self::ClamdDaemon => "clamd",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComponentAvailability {
    CheckingAvailability,
    Installed { version_text: String },
    Running { version_text: String },
    Stopped { version_text: String },
    NotInstalled,
    ProbeFailed { failure_text: String },
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProgramProbe {
    VersionReported { version_text: String },
    NotFoundOnPath,
    ProbeFailed { failure_text: String },
}

pub async fn probe_program_version(program_path: &Path) -> ProgramProbe {
    let mut version_command = Command::new(program_path);
    version_command
        .arg("--version")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    match timeout(PROGRAM_PROBE_TIMEOUT, version_command.output()).await {
        Ok(Ok(version_output)) if version_output.status.success() => {
            ProgramProbe::VersionReported {
                version_text: String::from_utf8_lossy(&version_output.stdout)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_owned(),
            }
        }
        Ok(Ok(version_output)) => ProgramProbe::ProbeFailed {
            failure_text: String::from_utf8_lossy(&version_output.stderr)
                .trim()
                .to_owned(),
        },
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

pub async fn probe_component_availability(component: ClamavComponent) -> ComponentAvailability {
    match probe_program_version(Path::new(component.program_name())).await {
        ProgramProbe::NotFoundOnPath => ComponentAvailability::NotInstalled,
        ProgramProbe::ProbeFailed { failure_text } => {
            ComponentAvailability::ProbeFailed { failure_text }
        }
        ProgramProbe::VersionReported { version_text }
            if component == ClamavComponent::ClamdDaemon =>
        {
            if clamd_answers_ping(Path::new("clamdscan")).await {
                ComponentAvailability::Running { version_text }
            } else {
                ComponentAvailability::Stopped { version_text }
            }
        }
        ProgramProbe::VersionReported { version_text } => {
            ComponentAvailability::Installed { version_text }
        }
    }
}

#[cfg(test)]
mod component_availability_tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;

    fn executable_fixture(fixture_directory: &Path, fixture_script: &str) -> std::path::PathBuf {
        let fixture_path = fixture_directory.join("fixture-program");
        fs::write(&fixture_path, fixture_script).expect("fixture script");
        fs::set_permissions(&fixture_path, fs::Permissions::from_mode(0o700))
            .expect("fixture mode");
        fixture_path
    }

    #[tokio::test]
    async fn version_probe_reports_the_first_output_line() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let fixture_path = executable_fixture(
            temporary_root.path(),
            "#!/bin/sh\nprintf 'ClamAV 1.5.4/28173\\nextra\\n'\n",
        );
        assert_eq!(
            probe_program_version(&fixture_path).await,
            ProgramProbe::VersionReported {
                version_text: "ClamAV 1.5.4/28173".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn version_probe_distinguishes_missing_from_failing_programs() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let fixture_path = executable_fixture(
            temporary_root.path(),
            "#!/bin/sh\nprintf 'broken install\\n' >&2\nexit 3\n",
        );
        assert_eq!(
            probe_program_version(&fixture_path).await,
            ProgramProbe::ProbeFailed {
                failure_text: "broken install".to_owned(),
            }
        );
        assert_eq!(
            probe_program_version(Path::new("/nonexistent/clamscan")).await,
            ProgramProbe::NotFoundOnPath
        );
    }
}

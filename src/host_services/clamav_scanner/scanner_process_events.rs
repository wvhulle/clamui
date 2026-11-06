use std::{
    io, mem,
    process::{ExitStatus, Stdio},
    time::Duration,
};

use futures::{Stream, StreamExt, future::ready, stream};
use rustix::process::{Pid, Signal, kill_process_group};
use tempfile::{NamedTempFile, TempDir};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::{Child, Command},
    runtime::Handle,
    time::timeout,
};
use tokio_stream::wrappers::SplitStream;

use crate::host_services::{
    clamav_config::detection_options::DetectionSettingsFailure,
    clamav_programs::trusted_program_lookup::ProgramRefusal,
    clamav_scanner::scanner_command_builder::ProgramLookupFailure,
};

const TERMINATION_GRACE_PERIOD: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum ScannerProcessEvent {
    ReportLine(Vec<u8>),
    DiagnosticLine(Vec<u8>),
    Exited(io::Result<ExitStatus>),
}

#[derive(Debug, thiserror::Error)]
pub enum ScanStartFailure {
    #[error("the scanner program is not installed")]
    ScannerProgramMissing,
    #[error("the scanner program at {} can be replaced by your account through {}", .candidate_path.display(), .replaceable_path.display())]
    ScannerProgramReplaceable {
        candidate_path: std::path::PathBuf,
        replaceable_path: std::path::PathBuf,
    },
    #[error("the scanner could not be started: {0}")]
    ScannerSpawnFailed(io::Error),
    #[error("the scanner output could not be captured")]
    ScannerOutputUncaptured,
    #[error("the private scanner work directory could not be created: {0}")]
    ScannerWorkDirectoryUnavailable(io::Error),
    #[error("the clamd detection settings could not be read: {0}")]
    DetectionSettingsUnreadable(#[from] DetectionSettingsFailure),
    #[error("the scanner programs could not be looked up: {0}")]
    ProgramLookupFailed(#[from] ProgramLookupFailure),
    #[error("the scan input could not be opened safely: {input_failure}")]
    ScanInputUnavailable {
        input_path: std::path::PathBuf,
        input_failure: io::Error,
    },
}

impl From<ProgramRefusal> for ScanStartFailure {
    fn from(program_refusal: ProgramRefusal) -> Self {
        match program_refusal {
            ProgramRefusal::ProgramMissing => Self::ScannerProgramMissing,
            ProgramRefusal::ProgramReplaceable {
                candidate_path,
                replaceable_path,
            } => Self::ScannerProgramReplaceable {
                candidate_path,
                replaceable_path,
            },
        }
    }
}

pub enum RetainedScannerFiles {
    NoRetainedFiles,
    TemporaryFileList(NamedTempFile),
    TemporaryWorkDirectory(TempDir),
}

impl RetainedScannerFiles {
    fn remove_retained_files(self) {
        match self {
            Self::NoRetainedFiles => {}
            Self::TemporaryFileList(file_list) => {
                let _already_removed = file_list.close();
            }
            Self::TemporaryWorkDirectory(work_directory) => {
                let _already_removed = work_directory.close();
            }
        }
    }
}

enum GuardedScannerChild {
    Running {
        scanner_child: Box<Child>,
        retained_files: RetainedScannerFiles,
    },
    Reaped,
}

struct ScannerTerminationGuard {
    guarded_child: GuardedScannerChild,
}

impl ScannerTerminationGuard {
    async fn wait_for_scanner_exit(&mut self) -> io::Result<ExitStatus> {
        match mem::replace(&mut self.guarded_child, GuardedScannerChild::Reaped) {
            GuardedScannerChild::Running {
                mut scanner_child,
                retained_files,
            } => {
                let exit_status = scanner_child.wait().await;
                retained_files.remove_retained_files();
                exit_status
            }
            GuardedScannerChild::Reaped => Err(io::Error::from(io::ErrorKind::NotFound)),
        }
    }
}

impl Drop for ScannerTerminationGuard {
    fn drop(&mut self) {
        if let GuardedScannerChild::Running {
            scanner_child,
            retained_files,
        } = mem::replace(&mut self.guarded_child, GuardedScannerChild::Reaped)
        {
            terminate_scanner_child(*scanner_child, retained_files);
        }
    }
}

fn scanner_process_group(scanner_child: &Child) -> Option<Pid> {
    scanner_child
        .id()
        .and_then(|process_id| i32::try_from(process_id).ok())
        .and_then(Pid::from_raw)
}

fn signal_scanner_group(process_group: Option<Pid>, termination_signal: Signal) {
    if let Some(process_group) = process_group {
        let _already_exited = kill_process_group(process_group, termination_signal);
    }
}

fn terminate_scanner_child(mut scanner_child: Child, retained_files: RetainedScannerFiles) {
    let process_group = scanner_process_group(&scanner_child);
    signal_scanner_group(process_group, Signal::TERM);
    match Handle::try_current() {
        Ok(runtime_handle) => {
            runtime_handle.spawn(async move {
                if timeout(TERMINATION_GRACE_PERIOD, scanner_child.wait())
                    .await
                    .is_err()
                {
                    signal_scanner_group(process_group, Signal::KILL);
                    let _exit_status = scanner_child.wait().await;
                }
                retained_files.remove_retained_files();
            });
        }
        Err(_no_runtime) => {
            signal_scanner_group(process_group, Signal::KILL);
            retained_files.remove_retained_files();
        }
    }
}

fn scanner_output_lines(
    output_pipe: impl AsyncRead + Unpin + Send + 'static,
) -> impl Stream<Item = Vec<u8>> + Send + 'static {
    SplitStream::new(BufReader::new(output_pipe).split(b'\n'))
        .take_while(|output_segment| ready(output_segment.is_ok()))
        .filter_map(|output_segment| ready(output_segment.ok()))
}

pub fn scanner_process_events(
    mut scanner_command: Command,
    retained_files: RetainedScannerFiles,
) -> Result<impl Stream<Item = ScannerProcessEvent> + Send + 'static, ScanStartFailure> {
    let mut scanner_child = scanner_command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|spawn_failure| match spawn_failure.kind() {
            io::ErrorKind::NotFound => ScanStartFailure::ScannerProgramMissing,
            _other_kind => ScanStartFailure::ScannerSpawnFailed(spawn_failure),
        })?;
    let (Some(report_pipe), Some(diagnostic_pipe)) =
        (scanner_child.stdout.take(), scanner_child.stderr.take())
    else {
        return Err(ScanStartFailure::ScannerOutputUncaptured);
    };
    let mut termination_guard = ScannerTerminationGuard {
        guarded_child: GuardedScannerChild::Running {
            scanner_child: Box::new(scanner_child),
            retained_files,
        },
    };
    let output_events = stream::select(
        scanner_output_lines(report_pipe).map(ScannerProcessEvent::ReportLine),
        scanner_output_lines(diagnostic_pipe).map(ScannerProcessEvent::DiagnosticLine),
    );
    let exit_event = stream::once(async move {
        ScannerProcessEvent::Exited(termination_guard.wait_for_scanner_exit().await)
    });
    Ok(output_events.chain(exit_event))
}

#[cfg(test)]
mod scanner_process_events_tests {
    use std::{
        env,
        ffi::OsStr,
        fs,
        io::Write,
        os::unix::process::CommandExt,
        path::Path,
        time::{Duration, Instant},
    };

    use rustix::process::test_kill_process;

    use super::*;

    const CHILD_TEST_NAME: &str =
        "host_services::clamav_scanner::scanner_process_events::scanner_process_events_tests::fixture_process_child";
    const BEHAVIOUR_VARIABLE: &str = "SCANNER_FIXTURE_BEHAVIOUR";
    const PROCESS_ID_VARIABLE: &str = "SCANNER_FIXTURE_PROCESS_ID_FILE";
    const FIXTURE_LINE_PREFIX: &[u8] = b"/scan/";
    const DIAGNOSTIC_LINE_COUNT: u32 = 20_000;

    fn fixture_process_command(fixture_behaviour: &str, process_id_file: &Path) -> Command {
        let mut child_command =
            std::process::Command::new(env::current_exe().expect("test binary"));
        child_command
            .args(["--exact", "--ignored", "--nocapture", CHILD_TEST_NAME])
            .env(BEHAVIOUR_VARIABLE, fixture_behaviour)
            .env(PROCESS_ID_VARIABLE, process_id_file)
            .process_group(0);
        Command::from(child_command)
    }

    fn record_process_id() {
        fs::write(
            env::var_os(PROCESS_ID_VARIABLE).expect("process id file"),
            std::process::id().to_string(),
        )
        .expect("recorded process id");
    }

    fn sleep_until_killed() -> ! {
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    #[test]
    #[ignore = "runs only as a child process of the tests in this module"]
    fn fixture_process_child() {
        let Some(fixture_behaviour) = env::var_os(BEHAVIOUR_VARIABLE) else {
            return;
        };
        record_process_id();
        match fixture_behaviour.to_str().expect("behaviour name") {
            "non-utf8-output" => {
                std::io::stdout()
                    .write_all(b"/scan/bad-\xff-name: OK\n/scan/eicar: Eicar FOUND\n")
                    .expect("fixture output");
                std::process::exit(1);
            }
            "diagnostic-flood" => {
                (1..=DIAGNOSTIC_LINE_COUNT).for_each(|line_number| {
                    eprintln!("/scan/diagnostic-{line_number}");
                });
                println!("/scan/finished");
                std::process::exit(0);
            }
            "cooperative" => sleep_until_killed(),
            "ignores-sigterm" => {
                unsafe {
                    libc::signal(libc::SIGTERM, libc::SIG_IGN);
                }
                sleep_until_killed()
            }
            unknown_behaviour => panic!("unknown fixture behaviour: {unknown_behaviour}"),
        }
    }

    async fn wait_until_process_gone(process_id: Pid, deadline: Duration) -> Duration {
        let started_at = Instant::now();
        while test_kill_process(process_id).is_ok() && started_at.elapsed() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            test_kill_process(process_id).is_err(),
            "scanner still alive"
        );
        started_at.elapsed()
    }

    async fn read_process_id(process_id_file: &Path) -> Pid {
        let started_at = Instant::now();
        loop {
            if let Some(process_id) = fs::read_to_string(process_id_file)
                .ok()
                .and_then(|recorded_text| recorded_text.trim().parse::<i32>().ok())
                .and_then(Pid::from_raw)
            {
                return process_id;
            }
            assert!(
                started_at.elapsed() < Duration::from_secs(10),
                "scanner never started"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn fixture_lines(
        process_events: &[ScannerProcessEvent],
        select_line: impl Fn(&ScannerProcessEvent) -> Option<&[u8]>,
    ) -> Vec<Vec<u8>> {
        process_events
            .iter()
            .filter_map(select_line)
            .filter(|output_line| output_line.starts_with(FIXTURE_LINE_PREFIX))
            .map(<[u8]>::to_vec)
            .collect()
    }

    fn report_line_of(process_event: &ScannerProcessEvent) -> Option<&[u8]> {
        match process_event {
            ScannerProcessEvent::ReportLine(report_line) => Some(report_line),
            _other_event => None,
        }
    }

    fn diagnostic_line_of(process_event: &ScannerProcessEvent) -> Option<&[u8]> {
        match process_event {
            ScannerProcessEvent::DiagnosticLine(diagnostic_line) => Some(diagnostic_line),
            _other_event => None,
        }
    }

    #[tokio::test]
    async fn non_utf8_output_does_not_end_the_stream_or_hide_later_lines() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let process_events = scanner_process_events(
            fixture_process_command("non-utf8-output", &temporary_root.path().join("pid")),
            RetainedScannerFiles::NoRetainedFiles,
        )
        .expect("spawned scanner");
        let collected_events = process_events.collect::<Vec<_>>().await;
        assert_eq!(
            fixture_lines(&collected_events, report_line_of),
            vec![
                b"/scan/bad-\xff-name: OK".to_vec(),
                b"/scan/eicar: Eicar FOUND".to_vec(),
            ]
        );
        assert!(matches!(
            collected_events.last(),
            Some(ScannerProcessEvent::Exited(Ok(exit_status))) if exit_status.code() == Some(1)
        ));
    }

    #[tokio::test]
    async fn diagnostic_flood_is_drained_without_blocking_the_report() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let process_events = scanner_process_events(
            fixture_process_command("diagnostic-flood", &temporary_root.path().join("pid")),
            RetainedScannerFiles::NoRetainedFiles,
        )
        .expect("spawned scanner");
        let collected_events =
            tokio::time::timeout(Duration::from_secs(30), process_events.collect::<Vec<_>>())
                .await
                .expect("no pipe deadlock");
        assert_eq!(
            fixture_lines(&collected_events, diagnostic_line_of).len(),
            DIAGNOSTIC_LINE_COUNT as usize
        );
        assert_eq!(
            fixture_lines(&collected_events, report_line_of),
            vec![b"/scan/finished".to_vec()]
        );
    }

    #[tokio::test]
    async fn missing_program_is_reported_as_missing() {
        assert!(matches!(
            scanner_process_events(
                Command::new(OsStr::new("/nonexistent/clamdscan")),
                RetainedScannerFiles::NoRetainedFiles
            ),
            Err(ScanStartFailure::ScannerProgramMissing)
        ));
    }

    #[tokio::test]
    async fn dropping_the_stream_stops_a_cooperative_scanner_quickly() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let process_id_file = temporary_root.path().join("pid");
        let process_events = scanner_process_events(
            fixture_process_command("cooperative", &process_id_file),
            RetainedScannerFiles::NoRetainedFiles,
        )
        .expect("spawned scanner");
        let scanner_process_id = read_process_id(&process_id_file).await;
        drop(process_events);
        let stop_duration =
            wait_until_process_gone(scanner_process_id, Duration::from_secs(4)).await;
        assert!(stop_duration < TERMINATION_GRACE_PERIOD);
    }

    #[tokio::test]
    async fn dropping_the_stream_kills_a_scanner_that_ignores_sigterm() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let process_id_file = temporary_root.path().join("pid");
        let work_directory = tempfile::tempdir_in(temporary_root.path()).expect("work directory");
        let work_directory_path = work_directory.path().to_path_buf();
        let process_events = scanner_process_events(
            fixture_process_command("ignores-sigterm", &process_id_file),
            RetainedScannerFiles::TemporaryWorkDirectory(work_directory),
        )
        .expect("spawned scanner");
        let scanner_process_id = read_process_id(&process_id_file).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        drop(process_events);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            test_kill_process(scanner_process_id).is_ok(),
            "grace period skipped"
        );
        assert!(work_directory_path.exists(), "removed while scanner alive");
        wait_until_process_gone(
            scanner_process_id,
            TERMINATION_GRACE_PERIOD + Duration::from_secs(5),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!work_directory_path.exists(), "work directory left behind");
    }
}

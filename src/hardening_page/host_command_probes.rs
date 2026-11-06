use std::{
    env,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use tokio::{io::AsyncReadExt, process::Child, task::spawn_blocking, time::timeout};

use crate::host_services::desktop::flatpak_sandbox::{
    host_program_async_command, host_program_search_directories, readable_host_path,
};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_OUTPUT_LIMIT: u64 = 2 * 1024 * 1024;
const SYSTEM_PROGRAM_DIRECTORIES: [&str; 3] = ["/usr/local/sbin", "/usr/sbin", "/sbin"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandProbe {
    ExitedSuccessfully { stdout_bytes: Vec<u8> },
    ExitedWithFailure,
    ProgramMissing,
    StartFailed,
    ProbeTimedOut,
    OutputExceededLimit,
}

impl CommandProbe {
    pub fn verified_text(&self) -> Option<&str> {
        match self {
            Self::ExitedSuccessfully { stdout_bytes } => std::str::from_utf8(stdout_bytes).ok(),
            Self::ExitedWithFailure
            | Self::ProgramMissing
            | Self::StartFailed
            | Self::ProbeTimedOut
            | Self::OutputExceededLimit => None,
        }
    }
}

struct ProbeLimits {
    run_timeout: Duration,
    output_limit: u64,
}

fn is_executable_file(program_path: &Path) -> bool {
    program_path.metadata().is_ok_and(|program_metadata| {
        program_metadata.is_file() && program_metadata.permissions().mode() & 0o111 != 0
    })
}

fn find_program_in_directories(
    program_name: &str,
    search_directories: impl IntoIterator<Item = PathBuf>,
) -> Option<PathBuf> {
    search_directories
        .into_iter()
        .map(|search_directory| search_directory.join(program_name))
        .find(|program_path| is_executable_file(program_path))
}

pub fn locate_host_program(program_name: &str) -> Option<PathBuf> {
    if let Some(host_directories) = host_program_search_directories() {
        return host_directories
            .into_iter()
            .map(|host_directory| host_directory.join(program_name))
            .find(|host_program| is_executable_file(&readable_host_path(host_program)));
    }
    let path_directories = env::var_os("PATH")
        .map(|search_path| env::split_paths(&search_path).collect::<Vec<_>>())
        .unwrap_or_default();
    find_program_in_directories(
        program_name,
        path_directories
            .into_iter()
            .chain(SYSTEM_PROGRAM_DIRECTORIES.map(PathBuf::from)),
    )
}

async fn collect_limited_output(
    probe_process: &mut Child,
    output_limit: u64,
) -> std::io::Result<CommandProbe> {
    let mut stdout_bytes = Vec::new();
    if let Some(process_stdout) = probe_process.stdout.take() {
        process_stdout
            .take(output_limit + 1)
            .read_to_end(&mut stdout_bytes)
            .await?;
    }
    if stdout_bytes.len() as u64 > output_limit {
        return Ok(CommandProbe::OutputExceededLimit);
    }
    Ok(if probe_process.wait().await?.success() {
        CommandProbe::ExitedSuccessfully { stdout_bytes }
    } else {
        CommandProbe::ExitedWithFailure
    })
}

async fn run_program_probe(
    program_path: &Path,
    program_arguments: &[&str],
    probe_limits: ProbeLimits,
) -> CommandProbe {
    let mut probe_command = host_program_async_command(program_path, &[("LC_ALL", "C")]);
    probe_command
        .args(program_arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let Ok(mut probe_process) = probe_command.spawn() else {
        return CommandProbe::StartFailed;
    };
    match timeout(
        probe_limits.run_timeout,
        collect_limited_output(&mut probe_process, probe_limits.output_limit),
    )
    .await
    {
        Ok(Ok(command_probe)) => command_probe,
        Ok(Err(_read_failure)) => CommandProbe::ExitedWithFailure,
        Err(_probe_timed_out) => CommandProbe::ProbeTimedOut,
    }
}

pub async fn run_command_probe(program_name: &str, program_arguments: &[&str]) -> CommandProbe {
    let Some(program_path) = locate_host_program(program_name) else {
        return CommandProbe::ProgramMissing;
    };
    run_program_probe(
        &program_path,
        program_arguments,
        ProbeLimits {
            run_timeout: PROBE_TIMEOUT,
            output_limit: PROBE_OUTPUT_LIMIT,
        },
    )
    .await
}

pub async fn read_host_text(host_path: &'static str) -> Option<String> {
    spawn_blocking(move || std::fs::read_to_string(host_path).ok())
        .await
        .ok()
        .flatten()
}

#[cfg(test)]
mod host_command_probes_tests {
    use super::*;

    const CHILD_TEST_NAME: &str =
        "hardening_page::host_command_probes::host_command_probes_tests::probe_child_process";

    #[test]
    #[ignore = "runs only as the child of the probe tests"]
    fn probe_child_process() {
        use std::io::Write;
        match std::env::args().next_back().as_deref() {
            Some("role=ok") => println!("CHILD_OUTPUT"),
            Some("role=locale") => println!("LOCALE={}", env::var("LC_ALL").unwrap_or_default()),
            Some("role=huge") => {
                std::io::stdout()
                    .write_all(&[b'y'; 4096])
                    .expect("child output");
            }
            Some("role=hang") => std::thread::sleep(Duration::from_secs(30)),
            Some("role=fail") => std::process::exit(3),
            _not_a_child => {}
        }
    }

    fn child_program() -> PathBuf {
        env::current_exe().expect("test binary path")
    }

    fn child_arguments(child_role: &'static str) -> [&'static str; 5] {
        [
            "--exact",
            CHILD_TEST_NAME,
            "--ignored",
            "--nocapture",
            child_role,
        ]
    }

    fn probe_output_text(command_probe: &CommandProbe) -> String {
        match command_probe {
            CommandProbe::ExitedSuccessfully { stdout_bytes } => {
                String::from_utf8_lossy(stdout_bytes).into_owned()
            }
            other_probe => panic!("expected a successful probe, got {other_probe:?}"),
        }
    }

    #[test]
    fn verified_text_requires_success_and_valid_text() {
        assert_eq!(
            CommandProbe::ExitedSuccessfully {
                stdout_bytes: b"active\n".to_vec()
            }
            .verified_text(),
            Some("active\n")
        );
        assert_eq!(
            CommandProbe::ExitedSuccessfully {
                stdout_bytes: b"Status: active\n\xff".to_vec()
            }
            .verified_text(),
            None
        );
        [
            CommandProbe::ExitedWithFailure,
            CommandProbe::ProgramMissing,
            CommandProbe::StartFailed,
            CommandProbe::ProbeTimedOut,
            CommandProbe::OutputExceededLimit,
        ]
        .iter()
        .for_each(|incomplete_probe| assert_eq!(incomplete_probe.verified_text(), None));
    }

    #[test]
    fn programs_are_found_only_when_executable() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let executable_path = temporary_root.path().join("present-tool");
        std::fs::write(&executable_path, b"").expect("empty program");
        std::fs::set_permissions(&executable_path, std::fs::Permissions::from_mode(0o755))
            .expect("executable mode");
        std::fs::write(temporary_root.path().join("plain-file"), b"fixture").expect("plain file");
        let search_directories = || [temporary_root.path().to_path_buf()];
        assert_eq!(
            find_program_in_directories("present-tool", search_directories()),
            Some(executable_path)
        );
        assert_eq!(
            find_program_in_directories("plain-file", search_directories()),
            None
        );
        assert_eq!(
            find_program_in_directories("absent-tool", search_directories()),
            None
        );
    }

    #[tokio::test]
    async fn probes_report_output_failure_and_oversized_output() {
        let generous_limits = || ProbeLimits {
            run_timeout: Duration::from_secs(30),
            output_limit: 1024 * 1024,
        };
        let successful_probe = run_program_probe(
            &child_program(),
            &child_arguments("role=ok"),
            generous_limits(),
        )
        .await;
        assert!(probe_output_text(&successful_probe).contains("CHILD_OUTPUT"));
        let locale_probe = run_program_probe(
            &child_program(),
            &child_arguments("role=locale"),
            generous_limits(),
        )
        .await;
        assert!(probe_output_text(&locale_probe).contains("LOCALE=C"));
        assert_eq!(
            run_program_probe(
                &child_program(),
                &child_arguments("role=fail"),
                generous_limits()
            )
            .await,
            CommandProbe::ExitedWithFailure
        );
        assert_eq!(
            run_program_probe(
                &child_program(),
                &child_arguments("role=huge"),
                ProbeLimits {
                    run_timeout: Duration::from_secs(30),
                    output_limit: 1024,
                },
            )
            .await,
            CommandProbe::OutputExceededLimit
        );
    }

    #[tokio::test]
    async fn a_hanging_program_times_out() {
        assert_eq!(
            run_program_probe(
                &child_program(),
                &child_arguments("role=hang"),
                ProbeLimits {
                    run_timeout: Duration::from_millis(200),
                    output_limit: 1024 * 1024,
                },
            )
            .await,
            CommandProbe::ProbeTimedOut
        );
    }
}

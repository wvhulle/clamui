use std::{
    ffi::{OsStr, OsString},
    fs::File,
    os::unix::process::CommandExt,
    path::Path,
    process::Stdio,
    time::Duration,
};

use tokio::process::Command;

use crate::host_services::{
    clamav_programs::trusted_program_lookup::{
        ClamavProgram, ProgramLocation, ProgramRefusal, locate_trusted_program,
    },
    clamav_scanner::scan_exclusion_rules::ScanExclusions,
    desktop::flatpak_sandbox::{
        host_program_async_command, host_program_command, scanner_visible_path,
    },
};

const CLAMD_PING_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScannerBackend {
    ClamdDaemon,
    StandaloneClamscan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScannerBackendPreference {
    PreferClamdWhenAvailable,
    AlwaysClamd,
    AlwaysClamscan,
}

#[derive(Clone, Debug)]
pub struct ScannerProgramPaths {
    pub clamdscan_program: ProgramLocation,
    pub clamscan_program: ProgramLocation,
}

impl ScannerProgramPaths {
    pub fn locate_trusted_programs() -> Self {
        Self {
            clamdscan_program: locate_trusted_program(ClamavProgram::ClamdClient),
            clamscan_program: locate_trusted_program(ClamavProgram::StandaloneScanner),
        }
    }

    pub const fn nothing_found() -> Self {
        Self {
            clamdscan_program: ProgramLocation::ProgramNotFound,
            clamscan_program: ProgramLocation::ProgramNotFound,
        }
    }
}

pub enum ScannerInvocation<'invocation> {
    StandaloneTarget {
        target_path: &'invocation Path,
        scanner_work_directory: &'invocation Path,
        scan_exclusions: &'invocation ScanExclusions,
        detection_arguments: &'invocation [OsString],
    },
    ClamdFileList {
        file_list_path: &'invocation Path,
    },
    ClamdStandardInput {
        scan_input_file: File,
    },
}

pub async fn choose_scanner_backend(
    backend_preference: ScannerBackendPreference,
    scanner_programs: &ScannerProgramPaths,
) -> ScannerBackend {
    match backend_preference {
        ScannerBackendPreference::PreferClamdWhenAvailable => {
            probe_clamd_availability(scanner_programs).await
        }
        ScannerBackendPreference::AlwaysClamd => ScannerBackend::ClamdDaemon,
        ScannerBackendPreference::AlwaysClamscan => ScannerBackend::StandaloneClamscan,
    }
}

pub async fn probe_clamd_availability(scanner_programs: &ScannerProgramPaths) -> ScannerBackend {
    let Ok(clamdscan_path) = scanner_programs.clamdscan_program.runnable_path() else {
        return ScannerBackend::StandaloneClamscan;
    };
    let mut ping_command = host_program_async_command(clamdscan_path, &[]);
    ping_command
        .args(["--ping", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    match tokio::time::timeout(CLAMD_PING_TIMEOUT, ping_command.status()).await {
        Ok(Ok(ping_status)) if ping_status.success() => ScannerBackend::ClamdDaemon,
        _ => ScannerBackend::StandaloneClamscan,
    }
}

pub fn build_scanner_command(
    scanner_programs: &ScannerProgramPaths,
    scanner_invocation: ScannerInvocation<'_>,
) -> Result<Command, ProgramRefusal> {
    let mut scanner_command = match scanner_invocation {
        ScannerInvocation::StandaloneTarget {
            target_path,
            scanner_work_directory,
            scan_exclusions,
            detection_arguments,
        } => standalone_clamscan_command(
            scanner_programs,
            target_path,
            scanner_work_directory,
            scan_exclusions,
            detection_arguments,
        )?,
        ScannerInvocation::ClamdFileList { file_list_path } => {
            let mut file_list_command = clamd_base_command(scanner_programs)?;
            file_list_command.arg("--file-list").arg(file_list_path);
            file_list_command.stdin(Stdio::null());
            file_list_command
        }
        ScannerInvocation::ClamdStandardInput { scan_input_file } => {
            let mut standard_input_command = clamd_base_command(scanner_programs)?;
            standard_input_command.arg("-").stdin(scan_input_file);
            standard_input_command
        }
    };
    scanner_command.process_group(0);
    Ok(Command::from(scanner_command))
}

fn clamd_base_command(
    scanner_programs: &ScannerProgramPaths,
) -> Result<std::process::Command, ProgramRefusal> {
    let mut clamd_command =
        host_program_command(scanner_programs.clamdscan_program.runnable_path()?, &[]);
    clamd_command.args(["--fdpass", "-v"]);
    Ok(clamd_command)
}

fn standalone_clamscan_command(
    scanner_programs: &ScannerProgramPaths,
    target_path: &Path,
    scanner_work_directory: &Path,
    scan_exclusions: &ScanExclusions,
    detection_arguments: &[OsString],
) -> Result<std::process::Command, ProgramRefusal> {
    let mut clamscan_command =
        host_program_command(scanner_programs.clamscan_program.runnable_path()?, &[]);
    if target_path.is_dir() {
        clamscan_command.arg("-r");
    }
    let mut work_directory_argument = OsString::from("--tempdir=");
    work_directory_argument.push(scanner_work_directory);
    clamscan_command
        .arg("-v")
        .arg(work_directory_argument)
        .args(scan_exclusions.clamscan_arguments())
        .args(detection_arguments)
        .stdin(Stdio::null());
    clamscan_command
        .arg("--")
        .arg(OsStr::new(&scanner_visible_path(target_path)));
    Ok(clamscan_command)
}

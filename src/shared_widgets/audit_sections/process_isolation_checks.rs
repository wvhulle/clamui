use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
};

use gettextrs::gettext;
use rustix::fs::Access;

use crate::{
    hardening_page::host_command_probes::read_host_text,
    host_services::{
        clamav_config::clamav_host_config::{HostConfigView, read_clamd_config},
        clamav_programs::distribution_install_guides::DistributionFamily,
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        desktop::flatpak_sandbox::running_in_flatpak,
    },
    shared_widgets::audit_sections::audit_check_results::{AuditCheck, AuditStatus},
};

const PTRACE_SCOPE_PATH: &str = "/proc/sys/kernel/yama/ptrace_scope";
const DEFAULT_CLAMD_SOCKET: &str = "/run/clamav/clamd.ctl";
const STICKY_MODE_BIT: u32 = 0o1000;
const NIXOS_PTRACE_SNIPPET: &str = "boot.kernel.sysctl.\"kernel.yama.ptrace_scope\" = 1;";
const SYSCTL_PTRACE_COMMAND: &str = "echo 'kernel.yama.ptrace_scope = 1' | sudo tee \
                                     /etc/sysctl.d/10-ptrace.conf && sudo sysctl --system";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PtraceScope {
    UnrestrictedAttach,
    RestrictedAttach,
    ScopeUnknown,
}

pub fn parse_ptrace_scope(scope_text: &str) -> PtraceScope {
    match scope_text.trim().parse::<u8>() {
        Ok(0) => PtraceScope::UnrestrictedAttach,
        Ok(_restricted_level) => PtraceScope::RestrictedAttach,
        Err(_unreadable_level) => PtraceScope::ScopeUnknown,
    }
}

pub fn ptrace_scope_check(
    ptrace_scope: PtraceScope,
    distribution_family: DistributionFamily,
) -> AuditCheck {
    let check_name = gettext("Process tampering");
    match ptrace_scope {
        PtraceScope::RestrictedAttach => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext("Programs can't attach to other programs you run, such as Lazaret"),
        ),
        PtraceScope::UnrestrictedAttach => AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            gettext(
                "Any program you run can attach to Lazaret and change what it shows, including \
                 scan results",
            ),
        )
        .with_recommendation(gettext(
            "Set kernel.yama.ptrace_scope to 1, so only a program's parent can attach to it.",
        ))
        .with_suggested_commands([
            if distribution_family == DistributionFamily::NixosFamily {
                NIXOS_PTRACE_SNIPPET
            } else {
                SYSCTL_PTRACE_COMMAND
            },
        ]),
        PtraceScope::ScopeUnknown => AuditCheck::new(
            check_name,
            AuditStatus::StatusUnknown,
            gettext("The kernel doesn't report whether programs may attach to each other"),
        ),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClamdSocketOwnership {
    SocketProtected {
        socket_path: PathBuf,
    },
    SocketReplaceable {
        socket_path: PathBuf,
        replaceable_path: PathBuf,
    },
    SocketMissing {
        socket_path: PathBuf,
    },
    SocketNotCheckable,
}

fn configured_socket_path() -> PathBuf {
    match read_clamd_config() {
        HostConfigView::ConfigFound {
            config_settings, ..
        } => config_settings
            .into_iter()
            .find(|config_setting| config_setting.setting_key == "LocalSocket")
            .map(|config_setting| PathBuf::from(config_setting.setting_value))
            .filter(|socket_path| socket_path.is_absolute())
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CLAMD_SOCKET)),
        HostConfigView::ConfigNotFound => PathBuf::from(DEFAULT_CLAMD_SOCKET),
    }
}

fn user_controls_path(checked_path: &Path, user_id: u32) -> bool {
    fs::symlink_metadata(checked_path).is_ok_and(|path_metadata| {
        let sticky_directory =
            path_metadata.is_dir() && path_metadata.mode() & STICKY_MODE_BIT != 0;
        path_metadata.uid() == user_id
            || (!sticky_directory && rustix::fs::access(checked_path, Access::WRITE_OK).is_ok())
    })
}

pub fn inspect_socket_ownership(socket_path: &Path, user_id: u32) -> ClamdSocketOwnership {
    let socket_is_present = fs::symlink_metadata(socket_path)
        .is_ok_and(|socket_metadata| socket_metadata.file_type().is_socket());
    if !socket_is_present {
        return ClamdSocketOwnership::SocketMissing {
            socket_path: socket_path.to_path_buf(),
        };
    }
    socket_path
        .ancestors()
        .find(|checked_path| {
            if *checked_path == socket_path {
                fs::symlink_metadata(checked_path)
                    .is_ok_and(|socket_metadata| socket_metadata.uid() == user_id)
            } else {
                user_controls_path(checked_path, user_id)
            }
        })
        .map_or_else(
            || ClamdSocketOwnership::SocketProtected {
                socket_path: socket_path.to_path_buf(),
            },
            |replaceable_path| ClamdSocketOwnership::SocketReplaceable {
                socket_path: socket_path.to_path_buf(),
                replaceable_path: replaceable_path.to_path_buf(),
            },
        )
}

fn inspect_clamd_socket() -> ClamdSocketOwnership {
    if running_in_flatpak() {
        return ClamdSocketOwnership::SocketNotCheckable;
    }
    inspect_socket_ownership(
        &configured_socket_path(),
        rustix::process::getuid().as_raw(),
    )
}

fn shown_path(displayed_path: &Path) -> String {
    sanitize_scanner_line(&displayed_path.to_string_lossy())
}

pub fn clamd_socket_check(socket_ownership: &ClamdSocketOwnership) -> AuditCheck {
    let check_name = gettext("clamd socket");
    match socket_ownership {
        ClamdSocketOwnership::SocketProtected { socket_path } => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext("Only the system can replace {path}")
                .replace("{path}", &shown_path(socket_path)),
        ),
        ClamdSocketOwnership::SocketReplaceable {
            socket_path,
            replaceable_path,
        } => AuditCheck::new(
            check_name,
            AuditStatus::CheckFailed,
            gettext(
                "Your account can replace {replaceable}, so a program running as you could put a \
                 fake clamd at {path} that reports every file as clean",
            )
            .replace("{replaceable}", &shown_path(replaceable_path))
            .replace("{path}", &shown_path(socket_path)),
        )
        .with_recommendation(gettext(
            "Let clamd create its socket in a directory that only root or the clamav user can \
             write, such as /run/clamav.",
        )),
        ClamdSocketOwnership::SocketMissing { socket_path } => AuditCheck::new(
            check_name,
            AuditStatus::StatusUnknown,
            gettext("No clamd socket at {path}, so clamd isn't running or listens elsewhere")
                .replace("{path}", &shown_path(socket_path)),
        ),
        ClamdSocketOwnership::SocketNotCheckable => AuditCheck::new(
            check_name,
            AuditStatus::CheckSkipped,
            gettext("The Flatpak sandbox can't see who owns the clamd socket"),
        ),
    }
}

pub async fn process_isolation_checks(distribution_family: DistributionFamily) -> Vec<AuditCheck> {
    let ptrace_scope = read_host_text(PTRACE_SCOPE_PATH)
        .await
        .map_or(PtraceScope::ScopeUnknown, |scope_text| {
            parse_ptrace_scope(&scope_text)
        });
    let socket_ownership = tokio::task::spawn_blocking(inspect_clamd_socket)
        .await
        .unwrap_or(ClamdSocketOwnership::SocketNotCheckable);
    vec![
        ptrace_scope_check(ptrace_scope, distribution_family),
        clamd_socket_check(&socket_ownership),
    ]
}

#[cfg(test)]
mod process_isolation_checks_tests {
    use std::os::unix::net::UnixListener;

    use super::*;

    #[test]
    fn only_scope_zero_lets_any_program_attach() {
        assert_eq!(parse_ptrace_scope("0\n"), PtraceScope::UnrestrictedAttach);
        assert_eq!(parse_ptrace_scope("1\n"), PtraceScope::RestrictedAttach);
        assert_eq!(parse_ptrace_scope("3"), PtraceScope::RestrictedAttach);
        assert_eq!(parse_ptrace_scope("x"), PtraceScope::ScopeUnknown);
        assert_eq!(
            ptrace_scope_check(
                PtraceScope::UnrestrictedAttach,
                DistributionFamily::NixosFamily
            )
            .check_status,
            AuditStatus::NeedsReview
        );
    }

    #[test]
    fn a_socket_in_a_directory_you_own_is_replaceable() {
        let socket_directory = tempfile::tempdir().unwrap();
        let socket_path = socket_directory.path().join("clamd.ctl");
        let _listening_socket = UnixListener::bind(&socket_path).unwrap();
        assert!(matches!(
            inspect_socket_ownership(&socket_path, rustix::process::getuid().as_raw()),
            ClamdSocketOwnership::SocketReplaceable { .. }
        ));
        assert!(matches!(
            inspect_socket_ownership(&socket_directory.path().join("absent.ctl"), 0),
            ClamdSocketOwnership::SocketMissing { .. }
        ));
    }
}

use std::io;

use tokio::task::spawn_blocking;

const PTRACE_SCOPE_PATH: &str = "/proc/sys/kernel/yama/ptrace_scope";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessAttachReadFailure {
    ScopeFileUnreadable { failure_kind: io::ErrorKind },
    ScopeValueUnrecognized,
    ReadingTaskInterrupted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessAttachScope {
    AttachRestricted,
    AnyProgramMayAttach,
    YamaNotLoaded,
    ScopeUnreadable(ProcessAttachReadFailure),
}

pub fn parse_ptrace_scope(scope_text: &str) -> ProcessAttachScope {
    match scope_text.trim().parse::<u8>() {
        Ok(0) => ProcessAttachScope::AnyProgramMayAttach,
        Ok(_restricted_level) => ProcessAttachScope::AttachRestricted,
        Err(_unrecognized_level) => {
            ProcessAttachScope::ScopeUnreadable(ProcessAttachReadFailure::ScopeValueUnrecognized)
        }
    }
}

pub fn process_attach_scope_from_reading(
    scope_reading: Result<String, io::ErrorKind>,
) -> ProcessAttachScope {
    match scope_reading {
        Ok(scope_text) => parse_ptrace_scope(&scope_text),
        Err(io::ErrorKind::NotFound) => ProcessAttachScope::YamaNotLoaded,
        Err(failure_kind) => {
            ProcessAttachScope::ScopeUnreadable(ProcessAttachReadFailure::ScopeFileUnreadable {
                failure_kind,
            })
        }
    }
}

pub async fn inspect_process_attach_scope() -> ProcessAttachScope {
    spawn_blocking(|| {
        std::fs::read_to_string(PTRACE_SCOPE_PATH).map_err(|read_failure| read_failure.kind())
    })
    .await
    .map_or(
        ProcessAttachScope::ScopeUnreadable(ProcessAttachReadFailure::ReadingTaskInterrupted),
        process_attach_scope_from_reading,
    )
}

#[cfg(test)]
mod process_attach_scope_tests {
    use super::*;

    #[test]
    fn only_scope_zero_lets_any_program_attach() {
        assert_eq!(
            parse_ptrace_scope("0\n"),
            ProcessAttachScope::AnyProgramMayAttach
        );
        assert_eq!(
            parse_ptrace_scope("1\n"),
            ProcessAttachScope::AttachRestricted
        );
        assert_eq!(
            parse_ptrace_scope("3"),
            ProcessAttachScope::AttachRestricted
        );
        assert_eq!(
            parse_ptrace_scope("x"),
            ProcessAttachScope::ScopeUnreadable(ProcessAttachReadFailure::ScopeValueUnrecognized)
        );
    }

    #[test]
    fn a_missing_scope_file_means_yama_is_not_loaded() {
        assert_eq!(
            process_attach_scope_from_reading(Err(io::ErrorKind::NotFound)),
            ProcessAttachScope::YamaNotLoaded
        );
        assert_eq!(
            process_attach_scope_from_reading(Err(io::ErrorKind::PermissionDenied)),
            ProcessAttachScope::ScopeUnreadable(ProcessAttachReadFailure::ScopeFileUnreadable {
                failure_kind: io::ErrorKind::PermissionDenied,
            })
        );
    }
}

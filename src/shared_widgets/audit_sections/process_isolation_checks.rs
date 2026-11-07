use gettextrs::gettext;

use crate::{
    hardening_page::host_command_probes::read_host_text,
    host_services::clamav_programs::distribution_install_guides::DistributionFamily,
    shared_widgets::audit_sections::audit_check_results::{AuditCheck, AuditStatus},
};

const PTRACE_SCOPE_PATH: &str = "/proc/sys/kernel/yama/ptrace_scope";
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

pub async fn process_isolation_checks(distribution_family: DistributionFamily) -> Vec<AuditCheck> {
    let ptrace_scope = read_host_text(PTRACE_SCOPE_PATH)
        .await
        .map_or(PtraceScope::ScopeUnknown, |scope_text| {
            parse_ptrace_scope(&scope_text)
        });
    vec![ptrace_scope_check(ptrace_scope, distribution_family)]
}

#[cfg(test)]
mod process_isolation_checks_tests {
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
}

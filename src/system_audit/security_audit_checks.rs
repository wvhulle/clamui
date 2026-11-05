use gettextrs::gettext;

use crate::{
    clamav_components::distribution_install_guides::DistributionFamily,
    system_audit::{
        audit_report_model::{AuditCategory, AuditCheck, AuditSection, AuditStatus},
        clamav_health_checks::audit_clamav_health,
        firewall_audit_checks::audit_firewall,
        host_command_probes::{
            CommandProbe, UnitState, locate_host_program, probe_unit_state, read_host_text,
            run_command_probe,
        },
        suggested_audit_commands::{SuggestedRemedy, suggested_command},
    },
};

const APPARMOR_DOCUMENTATION_URL: &str = "https://wiki.archlinux.org/title/AppArmor";
const SELINUX_DOCUMENTATION_URL: &str = "https://wiki.archlinux.org/title/SELinux";
const FAIL2BAN_DOCUMENTATION_URL: &str = "https://github.com/fail2ban/fail2ban/wiki";
const CROWDSEC_DOCUMENTATION_URL: &str = "https://docs.crowdsec.net/";

const APPARMOR_ENABLED_PATH: &str = "/sys/module/apparmor/parameters/enabled";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppArmorState {
    ModuleEnabled,
    ModuleDisabled,
    NoModule,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelinuxState {
    EnforcingMode,
    PermissiveMode,
    DisabledMode,
    ModeUndetermined,
    GetenforceMissing,
}

pub fn parse_apparmor_state(enabled_text: &str) -> AppArmorState {
    if enabled_text.trim() == "Y" {
        AppArmorState::ModuleEnabled
    } else {
        AppArmorState::ModuleDisabled
    }
}

pub fn inspect_selinux_probe(selinux_probe: &CommandProbe) -> SelinuxState {
    if *selinux_probe == CommandProbe::ProgramMissing {
        return SelinuxState::GetenforceMissing;
    }
    match selinux_probe
        .verified_text()
        .map(|mode_text| mode_text.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("enforcing") => SelinuxState::EnforcingMode,
        Some("permissive") => SelinuxState::PermissiveMode,
        Some("disabled") => SelinuxState::DisabledMode,
        Some(_) | None => SelinuxState::ModeUndetermined,
    }
}

fn apparmor_check(
    apparmor_state: AppArmorState,
    selinux_state: SelinuxState,
) -> Option<AuditCheck> {
    let check_name = gettext("AppArmor");
    let apparmor_row = match apparmor_state {
        AppArmorState::NoModule => return None,
        AppArmorState::ModuleEnabled => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext("AppArmor is enabled"),
        ),
        AppArmorState::ModuleDisabled if selinux_state == SelinuxState::EnforcingMode => {
            AuditCheck::new(
                check_name,
                AuditStatus::CheckSkipped,
                gettext("AppArmor module is loaded but not enabled"),
            )
        }
        AppArmorState::ModuleDisabled => AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            gettext("AppArmor module is loaded but not enabled"),
        )
        .with_recommendation(gettext("Enable AppArmor for application sandboxing")),
    };
    Some(apparmor_row.with_documentation(APPARMOR_DOCUMENTATION_URL))
}

fn selinux_check(apparmor_state: AppArmorState, selinux_state: SelinuxState) -> Option<AuditCheck> {
    let check_name = gettext("SELinux");
    let selinux_row = match selinux_state {
        SelinuxState::GetenforceMissing => return None,
        SelinuxState::EnforcingMode => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext("SELinux is enforcing"),
        ),
        SelinuxState::PermissiveMode => AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            gettext("SELinux is in permissive mode"),
        )
        .with_recommendation(gettext(
            "Consider switching to enforcing mode for stronger protection",
        )),
        SelinuxState::DisabledMode if apparmor_state == AppArmorState::ModuleEnabled => {
            AuditCheck::new(
                check_name,
                AuditStatus::CheckSkipped,
                gettext("SELinux is disabled"),
            )
        }
        SelinuxState::DisabledMode => AuditCheck::new(
            check_name,
            AuditStatus::CheckFailed,
            gettext("SELinux is disabled"),
        )
        .with_recommendation(gettext("Enable SELinux for mandatory access control")),
        SelinuxState::ModeUndetermined => AuditCheck::new(
            check_name,
            AuditStatus::StatusUnknown,
            gettext("SELinux mode could not be determined"),
        ),
    };
    Some(selinux_row.with_documentation(SELINUX_DOCUMENTATION_URL))
}

pub fn access_control_checks(
    apparmor_state: AppArmorState,
    selinux_state: SelinuxState,
) -> Vec<AuditCheck> {
    let framework_rows = apparmor_check(apparmor_state, selinux_state)
        .into_iter()
        .chain(selinux_check(apparmor_state, selinux_state))
        .collect::<Vec<_>>();
    if framework_rows.is_empty() {
        vec![
            AuditCheck::new(
                gettext("MAC Framework"),
                AuditStatus::StatusUnknown,
                gettext("No mandatory access control framework detected"),
            )
            .with_recommendation(gettext("Consider enabling AppArmor or SELinux")),
        ]
    } else {
        framework_rows
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntrusionDetectionTool {
    Fail2banTool,
    CrowdsecTool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolPresence {
    ServiceActive,
    InstalledStopped,
    ToolAbsent,
}

impl IntrusionDetectionTool {
    fn display_name(self) -> &'static str {
        match self {
            Self::Fail2banTool => "fail2ban",
            Self::CrowdsecTool => "CrowdSec",
        }
    }

    fn service_unit(self) -> &'static str {
        match self {
            Self::Fail2banTool => "fail2ban.service",
            Self::CrowdsecTool => "crowdsec.service",
        }
    }

    fn client_program(self) -> &'static str {
        match self {
            Self::Fail2banTool => "fail2ban-client",
            Self::CrowdsecTool => "cscli",
        }
    }

    fn documentation_url(self) -> &'static str {
        match self {
            Self::Fail2banTool => FAIL2BAN_DOCUMENTATION_URL,
            Self::CrowdsecTool => CROWDSEC_DOCUMENTATION_URL,
        }
    }

    fn active_detail(self) -> String {
        match self {
            Self::Fail2banTool => gettext("fail2ban is active and protecting services"),
            Self::CrowdsecTool => gettext("CrowdSec is active with community threat intelligence"),
        }
    }

    fn start_recommendation(self) -> String {
        match self {
            Self::Fail2banTool => gettext("Start fail2ban to protect against brute force attacks"),
            Self::CrowdsecTool => gettext("Start CrowdSec for collaborative intrusion prevention"),
        }
    }

    fn start_remedy(self) -> SuggestedRemedy {
        match self {
            Self::Fail2banTool => SuggestedRemedy::Fail2banServiceStart,
            Self::CrowdsecTool => SuggestedRemedy::CrowdsecServiceStart,
        }
    }
}

fn intrusion_tool_check(
    detection_tool: IntrusionDetectionTool,
    tool_presence: ToolPresence,
    distribution_family: DistributionFamily,
) -> Option<AuditCheck> {
    let check_name = detection_tool.display_name().to_owned();
    let tool_row = match tool_presence {
        ToolPresence::ToolAbsent => return None,
        ToolPresence::ServiceActive => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            detection_tool.active_detail(),
        ),
        ToolPresence::InstalledStopped => AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            gettext("{name} is installed but not running")
                .replace("{name}", detection_tool.display_name()),
        )
        .with_recommendation(detection_tool.start_recommendation())
        .with_suggested_commands(suggested_command(
            detection_tool.start_remedy(),
            distribution_family,
        )),
    };
    Some(tool_row.with_documentation(detection_tool.documentation_url()))
}

pub fn intrusion_detection_checks(
    fail2ban_presence: ToolPresence,
    crowdsec_presence: ToolPresence,
    distribution_family: DistributionFamily,
) -> Vec<AuditCheck> {
    let tool_rows = intrusion_tool_check(
        IntrusionDetectionTool::Fail2banTool,
        fail2ban_presence,
        distribution_family,
    )
    .into_iter()
    .chain(intrusion_tool_check(
        IntrusionDetectionTool::CrowdsecTool,
        crowdsec_presence,
        distribution_family,
    ))
    .collect::<Vec<_>>();
    if tool_rows.is_empty() {
        vec![
            AuditCheck::new(
                gettext("Intrusion Prevention"),
                AuditStatus::StatusUnknown,
                gettext("No intrusion detection system found"),
            )
            .with_recommendation(gettext(
                "Install fail2ban or CrowdSec to protect against attacks",
            ))
            .with_suggested_commands(suggested_command(
                SuggestedRemedy::IntrusionPreventionInstall,
                distribution_family,
            ))
            .with_documentation(FAIL2BAN_DOCUMENTATION_URL),
        ]
    } else {
        tool_rows
    }
}

async fn inspect_tool_presence(detection_tool: IntrusionDetectionTool) -> ToolPresence {
    if probe_unit_state(detection_tool.service_unit()).await == UnitState::UnitActive {
        ToolPresence::ServiceActive
    } else if locate_host_program(detection_tool.client_program()).is_some() {
        ToolPresence::InstalledStopped
    } else {
        ToolPresence::ToolAbsent
    }
}

pub async fn gather_audit_section(
    audit_category: AuditCategory,
    distribution_family: DistributionFamily,
) -> AuditSection {
    let section_checks = match audit_category {
        AuditCategory::ClamavHealth => return audit_clamav_health(distribution_family).await,
        AuditCategory::FirewallProtection => return audit_firewall(distribution_family).await,
        AuditCategory::AccessControl => {
            let apparmor_state = read_host_text(APPARMOR_ENABLED_PATH)
                .await
                .map_or(AppArmorState::NoModule, |enabled_text| {
                    parse_apparmor_state(&enabled_text)
                });
            let selinux_probe = run_command_probe("getenforce", &[]).await;
            access_control_checks(apparmor_state, inspect_selinux_probe(&selinux_probe))
        }
        AuditCategory::IntrusionDetection => intrusion_detection_checks(
            inspect_tool_presence(IntrusionDetectionTool::Fail2banTool).await,
            inspect_tool_presence(IntrusionDetectionTool::CrowdsecTool).await,
            distribution_family,
        ),
    };
    AuditSection {
        audit_category,
        section_checks,
    }
}

#[cfg(test)]
mod security_audit_checks_tests {
    use super::*;
    use crate::system_audit::audit_report_model::CheckGuidance;

    fn completed_probe(stdout_text: &str) -> CommandProbe {
        CommandProbe::ExitedSuccessfully {
            stdout_bytes: stdout_text.as_bytes().to_vec(),
        }
    }

    fn row_statuses(audit_checks: &[AuditCheck]) -> Vec<AuditStatus> {
        audit_checks
            .iter()
            .map(|audit_check| audit_check.check_status)
            .collect()
    }

    fn suggested_commands(audit_check: &AuditCheck) -> Vec<&'static str> {
        audit_check
            .check_guidance
            .iter()
            .filter_map(|check_guidance| match check_guidance {
                CheckGuidance::SuggestedCommand(suggested_command) => Some(*suggested_command),
                CheckGuidance::RecommendationText(_) | CheckGuidance::DocumentationLink(_) => None,
            })
            .collect()
    }

    #[tokio::test]
    #[ignore = "reads the real host"]
    async fn host_audit_reports_every_section() {
        let audited_sections = futures::future::join_all(
            crate::system_audit::audit_report_model::ALL_AUDIT_CATEGORIES.map(|audit_category| {
                gather_audit_section(
                    audit_category,
                    crate::clamav_components::distribution_install_guides::detect_distribution_family(),
                )
            }),
        )
        .await;
        audited_sections.iter().for_each(|audited_section| {
            assert!(!audited_section.section_checks.is_empty());
            audited_section
                .section_checks
                .iter()
                .for_each(|audit_check| {
                    println!(
                        "{:?} | {} | {:?} | {} | {:?}",
                        audited_section.audit_category,
                        audit_check.check_name,
                        audit_check.check_status,
                        audit_check.status_detail,
                        suggested_commands(audit_check),
                    );
                });
        });
    }

    #[test]
    fn apparmor_and_selinux_states_are_parsed() {
        assert_eq!(parse_apparmor_state("Y\n"), AppArmorState::ModuleEnabled);
        assert_eq!(parse_apparmor_state("N\n"), AppArmorState::ModuleDisabled);
        assert_eq!(
            inspect_selinux_probe(&completed_probe("Enforcing\n")),
            SelinuxState::EnforcingMode
        );
        assert_eq!(
            inspect_selinux_probe(&completed_probe("Permissive\n")),
            SelinuxState::PermissiveMode
        );
        assert_eq!(
            inspect_selinux_probe(&completed_probe("Disabled\n")),
            SelinuxState::DisabledMode
        );
        assert_eq!(
            inspect_selinux_probe(&completed_probe("surprising\n")),
            SelinuxState::ModeUndetermined
        );
        assert_eq!(
            inspect_selinux_probe(&CommandProbe::ProgramMissing),
            SelinuxState::GetenforceMissing
        );
        assert_eq!(
            inspect_selinux_probe(&CommandProbe::ExitedWithFailure),
            SelinuxState::ModeUndetermined
        );
    }

    #[test]
    fn one_active_framework_excuses_the_other_being_off() {
        assert_eq!(
            row_statuses(&access_control_checks(
                AppArmorState::ModuleEnabled,
                SelinuxState::DisabledMode
            )),
            vec![AuditStatus::CheckPassed, AuditStatus::CheckSkipped]
        );
        assert_eq!(
            row_statuses(&access_control_checks(
                AppArmorState::ModuleDisabled,
                SelinuxState::EnforcingMode
            )),
            vec![AuditStatus::CheckSkipped, AuditStatus::CheckPassed]
        );
        assert_eq!(
            row_statuses(&access_control_checks(
                AppArmorState::NoModule,
                SelinuxState::DisabledMode
            )),
            vec![AuditStatus::CheckFailed]
        );
        assert_eq!(
            row_statuses(&access_control_checks(
                AppArmorState::ModuleDisabled,
                SelinuxState::GetenforceMissing
            )),
            vec![AuditStatus::NeedsReview]
        );
    }

    #[test]
    fn absent_frameworks_are_unknown_rather_than_failed() {
        assert_eq!(
            row_statuses(&access_control_checks(
                AppArmorState::NoModule,
                SelinuxState::GetenforceMissing
            )),
            vec![AuditStatus::StatusUnknown]
        );
    }

    #[test]
    fn intrusion_rows_appear_for_present_tools_only() {
        assert_eq!(
            row_statuses(&intrusion_detection_checks(
                ToolPresence::ServiceActive,
                ToolPresence::InstalledStopped,
                DistributionFamily::DebianFamily
            )),
            vec![AuditStatus::CheckPassed, AuditStatus::NeedsReview]
        );
        let absent_rows = intrusion_detection_checks(
            ToolPresence::ToolAbsent,
            ToolPresence::ToolAbsent,
            DistributionFamily::NixosFamily,
        );
        assert_eq!(row_statuses(&absent_rows), vec![AuditStatus::StatusUnknown]);
        assert_eq!(
            suggested_commands(&absent_rows[0]),
            vec!["services.fail2ban.enable = true;"]
        );
    }
}

use std::{collections::BTreeMap, path::Path};

use gettextrs::gettext;

use crate::{
    clamav_components::distribution_install_guides::DistributionFamily,
    malware_scan::scanner_output_parser::sanitize_scanner_line,
    system_audit::{
        audit_report_model::{AuditCategory, AuditCheck, AuditSection, AuditStatus},
        clamav_health_checks::audit_clamav_health,
        firewall_audit_checks::audit_firewall,
        host_command_probes::{
            CommandProbe, UnitState, first_active_unit, locate_host_program, probe_unit_state,
            read_host_text, run_command_probe, systemd_is_available,
        },
        suggested_audit_commands::{
            CHKROOTKIT_SCAN_COMMAND, DNF_AUTOMATIC_ENABLE_COMMAND, LYNIS_AUDIT_COMMAND,
            RPM_OSTREE_AUTOMATIC_ENABLE_COMMAND, SSHD_EFFECTIVE_CONFIG_COMMAND, SuggestedRemedy,
            UNATTENDED_RECONFIGURE_COMMAND, suggested_command,
        },
    },
};

const APPARMOR_DOCUMENTATION_URL: &str = "https://wiki.archlinux.org/title/AppArmor";
const SELINUX_DOCUMENTATION_URL: &str = "https://wiki.archlinux.org/title/SELinux";
const UNATTENDED_DOCUMENTATION_URL: &str = "https://wiki.debian.org/UnattendedUpgrades";
const DNF_DOCUMENTATION_URL: &str = "https://dnf.readthedocs.io/en/latest/automatic.html";
const FAIL2BAN_DOCUMENTATION_URL: &str = "https://github.com/fail2ban/fail2ban/wiki";
const CROWDSEC_DOCUMENTATION_URL: &str = "https://docs.crowdsec.net/";
const SSH_DOCUMENTATION_URL: &str = "https://wiki.archlinux.org/title/OpenSSH#Protection";
const SSHD_CONFIG_DOCUMENTATION_URL: &str =
    "https://man7.org/linux/man-pages/man5/sshd_config.5.html";
const LYNIS_DOCUMENTATION_URL: &str = "https://cisofy.com/lynis/";
const CHKROOTKIT_DOCUMENTATION_URL: &str = "https://www.chkrootkit.org/";
const PORTMASTER_DOCUMENTATION_URL: &str = "https://safing.io/portmaster/";
const PORTMASTER_INSTALL_URL: &str = "https://docs.safing.io/portmaster/install/linux";

const APPARMOR_ENABLED_PATH: &str = "/sys/module/apparmor/parameters/enabled";
const REBOOT_REQUIRED_PATH: &str = "/var/run/reboot-required";
const SSHD_CONFIG_PATH: &str = "/etc/ssh/sshd_config";
const SSH_SERVER_UNITS: [&str; 4] = ["sshd.service", "ssh.service", "sshd.socket", "ssh.socket"];
const DNF_AUTOMATIC_UNIT: &str = "dnf-automatic.timer";
const RPM_OSTREE_AUTOMATIC_UNIT: &str = "rpm-ostreed-automatic.timer";
const NIXOS_UPGRADE_UNIT: &str = "nixos-upgrade.timer";
const PORTMASTER_UNIT: &str = "portmaster.service";

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
pub enum AptPeriodicState {
    UpgradesEnabled,
    UpgradesDisabled,
    NotConfigured,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateMechanismEvidence {
    AptUpgradesEnabled,
    AptUpgradesDisabled,
    DnfTimerActive,
    DnfTimerInactive,
    RpmOstreeTimerActive,
    RpmOstreeTimerInactive,
    NixosUpgradeActive,
    NixosUpgradeAbsent,
    MechanismUndetermined,
}

pub fn parse_apt_periodic_state(apt_configuration: &str) -> AptPeriodicState {
    if apt_configuration.contains("\"1\"")
        || apt_configuration.to_ascii_lowercase().contains("\"true\"")
    {
        AptPeriodicState::UpgradesEnabled
    } else if apt_configuration.contains("\"0\"") {
        AptPeriodicState::UpgradesDisabled
    } else {
        AptPeriodicState::NotConfigured
    }
}

pub fn update_mechanism_check(
    mechanism_evidence: UpdateMechanismEvidence,
    distribution_family: DistributionFamily,
) -> AuditCheck {
    match mechanism_evidence {
        UpdateMechanismEvidence::AptUpgradesEnabled => AuditCheck::new(
            gettext("Unattended Upgrades"),
            AuditStatus::CheckPassed,
            gettext("Automatic security updates are enabled"),
        )
        .with_documentation(UNATTENDED_DOCUMENTATION_URL),
        UpdateMechanismEvidence::AptUpgradesDisabled => AuditCheck::new(
            gettext("Unattended Upgrades"),
            AuditStatus::NeedsReview,
            gettext("Unattended upgrades is installed but disabled"),
        )
        .with_recommendation(gettext("Enable automatic security updates"))
        .with_suggested_commands([UNATTENDED_RECONFIGURE_COMMAND])
        .with_documentation(UNATTENDED_DOCUMENTATION_URL),
        UpdateMechanismEvidence::DnfTimerActive => AuditCheck::new(
            gettext("DNF Automatic"),
            AuditStatus::CheckPassed,
            gettext("DNF automatic updates are enabled"),
        )
        .with_documentation(DNF_DOCUMENTATION_URL),
        UpdateMechanismEvidence::DnfTimerInactive => AuditCheck::new(
            gettext("DNF Automatic"),
            AuditStatus::NeedsReview,
            gettext("DNF automatic is installed but timer is not active"),
        )
        .with_recommendation(gettext("Enable automatic updates"))
        .with_suggested_commands([DNF_AUTOMATIC_ENABLE_COMMAND])
        .with_documentation(DNF_DOCUMENTATION_URL),
        UpdateMechanismEvidence::RpmOstreeTimerActive => AuditCheck::new(
            gettext("rpm-ostree Automatic"),
            AuditStatus::CheckPassed,
            gettext("rpm-ostree automatic updates are enabled"),
        ),
        UpdateMechanismEvidence::RpmOstreeTimerInactive => AuditCheck::new(
            gettext("rpm-ostree Automatic"),
            AuditStatus::NeedsReview,
            gettext("rpm-ostree automatic update timer is not active"),
        )
        .with_recommendation(gettext("Enable automatic updates"))
        .with_suggested_commands([RPM_OSTREE_AUTOMATIC_ENABLE_COMMAND]),
        UpdateMechanismEvidence::NixosUpgradeActive => AuditCheck::new(
            gettext("NixOS Automatic Upgrades"),
            AuditStatus::CheckPassed,
            gettext("The NixOS upgrade timer is active"),
        ),
        UpdateMechanismEvidence::NixosUpgradeAbsent => AuditCheck::new(
            gettext("NixOS Automatic Upgrades"),
            AuditStatus::NeedsReview,
            gettext("The NixOS upgrade timer is not active"),
        )
        .with_recommendation(gettext("Enable automatic updates"))
        .with_suggested_commands(suggested_command(
            SuggestedRemedy::AutomaticUpdatesEnable,
            distribution_family,
        )),
        UpdateMechanismEvidence::MechanismUndetermined => AuditCheck::new(
            gettext("Automatic Updates"),
            AuditStatus::StatusUnknown,
            gettext("Could not determine automatic update status"),
        )
        .with_recommendation(gettext("Configure automatic security updates"))
        .with_suggested_commands(suggested_command(
            SuggestedRemedy::AutomaticUpdatesEnable,
            distribution_family,
        )),
    }
}

async fn inspect_update_mechanism(
    distribution_family: DistributionFamily,
) -> UpdateMechanismEvidence {
    match distribution_family {
        DistributionFamily::NixosFamily => match probe_unit_state(NIXOS_UPGRADE_UNIT).await {
            UnitState::UnitActive => UpdateMechanismEvidence::NixosUpgradeActive,
            UnitState::UnitInactive | UnitState::UnitNotFound => {
                UpdateMechanismEvidence::NixosUpgradeAbsent
            }
            UnitState::SystemdUnavailable => UpdateMechanismEvidence::MechanismUndetermined,
        },
        DistributionFamily::FedoraAtomic => match probe_unit_state(RPM_OSTREE_AUTOMATIC_UNIT).await
        {
            UnitState::UnitActive => UpdateMechanismEvidence::RpmOstreeTimerActive,
            UnitState::UnitInactive => UpdateMechanismEvidence::RpmOstreeTimerInactive,
            UnitState::UnitNotFound | UnitState::SystemdUnavailable => {
                UpdateMechanismEvidence::MechanismUndetermined
            }
        },
        DistributionFamily::DebianFamily
        | DistributionFamily::FedoraWorkstation
        | DistributionFamily::ArchFamily
        | DistributionFamily::UnrecognizedFamily => inspect_package_manager_updates().await,
    }
}

async fn inspect_package_manager_updates() -> UpdateMechanismEvidence {
    let apt_probe =
        run_command_probe("apt-config", &["dump", "APT::Periodic::Unattended-Upgrade"]).await;
    match apt_probe
        .verified_text()
        .map_or(AptPeriodicState::NotConfigured, parse_apt_periodic_state)
    {
        AptPeriodicState::UpgradesEnabled => return UpdateMechanismEvidence::AptUpgradesEnabled,
        AptPeriodicState::UpgradesDisabled => return UpdateMechanismEvidence::AptUpgradesDisabled,
        AptPeriodicState::NotConfigured => {}
    }
    if locate_host_program("dnf").is_none() {
        return UpdateMechanismEvidence::MechanismUndetermined;
    }
    match probe_unit_state(DNF_AUTOMATIC_UNIT).await {
        UnitState::UnitActive => UpdateMechanismEvidence::DnfTimerActive,
        UnitState::UnitInactive => UpdateMechanismEvidence::DnfTimerInactive,
        UnitState::UnitNotFound | UnitState::SystemdUnavailable => {
            UpdateMechanismEvidence::MechanismUndetermined
        }
    }
}

fn pending_reboot_check() -> AuditCheck {
    AuditCheck::new(
        gettext("Pending Reboot"),
        AuditStatus::NeedsReview,
        gettext("System reboot required to apply updates"),
    )
    .with_recommendation(gettext(
        "Reboot the system to apply pending security updates",
    ))
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

pub type SshdSettings = BTreeMap<String, String>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SshConfigEvidence {
    EffectiveSettings(SshdSettings),
    ConfigFileSettings(SshdSettings),
    ConfigUnreadable,
}

fn recorded_setting(mut sshd_settings: SshdSettings, setting_line: &str) -> SshdSettings {
    let mut line_fields = setting_line.split_whitespace();
    if let Some(setting_key) = line_fields.next() {
        let setting_value = line_fields.collect::<Vec<_>>().join(" ");
        if !setting_value.is_empty() {
            sshd_settings
                .entry(setting_key.to_ascii_lowercase())
                .or_insert(setting_value);
        }
    }
    sshd_settings
}

pub fn parse_sshd_effective_output(effective_output: &str) -> SshdSettings {
    effective_output
        .lines()
        .fold(SshdSettings::new(), recorded_setting)
}

pub fn parse_sshd_config_file(config_text: &str) -> SshdSettings {
    config_text
        .lines()
        .map(str::trim)
        .filter(|config_line| !config_line.is_empty() && !config_line.starts_with('#'))
        .take_while(|config_line| {
            config_line
                .split_whitespace()
                .next()
                .is_none_or(|setting_key| !setting_key.eq_ignore_ascii_case("match"))
        })
        .fold(SshdSettings::new(), recorded_setting)
}

fn setting_value(sshd_settings: &SshdSettings, setting_key: &str, default_value: &str) -> String {
    sshd_settings
        .get(setting_key)
        .map_or(default_value, String::as_str)
        .to_ascii_lowercase()
}

fn root_login_check(
    sshd_settings: &SshdSettings,
    distribution_family: DistributionFamily,
) -> AuditCheck {
    let root_login = setting_value(sshd_settings, "permitrootlogin", "prohibit-password");
    let shown_value = sanitize_scanner_line(&root_login);
    let check_name = gettext("Root Login");
    let root_row = if matches!(
        root_login.as_str(),
        "no" | "prohibit-password" | "without-password" | "forced-commands-only"
    ) {
        AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext("Root login: {value}").replace("{value}", &shown_value),
        )
    } else {
        AuditCheck::new(
            check_name,
            AuditStatus::CheckFailed,
            gettext("Root login is allowed ({value})").replace("{value}", &shown_value),
        )
        .with_recommendation(gettext("Disable root SSH login for security"))
        .with_suggested_commands(suggested_command(
            SuggestedRemedy::SshRootLoginDisable,
            distribution_family,
        ))
    };
    root_row.with_documentation(SSHD_CONFIG_DOCUMENTATION_URL)
}

fn password_login_check(
    sshd_settings: &SshdSettings,
    distribution_family: DistributionFamily,
) -> AuditCheck {
    let check_name = gettext("Password Auth");
    let password_row = if setting_value(sshd_settings, "passwordauthentication", "yes") == "no" {
        AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext("Password authentication is disabled (key-only)"),
        )
    } else {
        AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            gettext("Password authentication is enabled"),
        )
        .with_recommendation(gettext(
            "Consider disabling password auth in favor of SSH keys",
        ))
        .with_suggested_commands(suggested_command(
            SuggestedRemedy::SshPasswordLoginDisable,
            distribution_family,
        ))
    };
    password_row.with_documentation(SSHD_CONFIG_DOCUMENTATION_URL)
}

fn x11_forwarding_check(
    sshd_settings: &SshdSettings,
    distribution_family: DistributionFamily,
) -> AuditCheck {
    let check_name = gettext("X11 Forwarding");
    let forwarding_row = if setting_value(sshd_settings, "x11forwarding", "no") == "no" {
        AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext("X11 forwarding is disabled"),
        )
    } else {
        AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            gettext("X11 forwarding is enabled"),
        )
        .with_recommendation(gettext("Disable X11 forwarding to reduce attack surface"))
        .with_suggested_commands(suggested_command(
            SuggestedRemedy::SshX11ForwardingDisable,
            distribution_family,
        ))
    };
    forwarding_row.with_documentation(SSHD_CONFIG_DOCUMENTATION_URL)
}

fn ssh_setting_checks(
    sshd_settings: &SshdSettings,
    distribution_family: DistributionFamily,
) -> Vec<AuditCheck> {
    vec![
        root_login_check(sshd_settings, distribution_family),
        password_login_check(sshd_settings, distribution_family),
        x11_forwarding_check(sshd_settings, distribution_family),
    ]
}

pub fn ssh_configuration_checks(
    config_evidence: &SshConfigEvidence,
    distribution_family: DistributionFamily,
) -> Vec<AuditCheck> {
    match config_evidence {
        SshConfigEvidence::EffectiveSettings(sshd_settings) => {
            ssh_setting_checks(sshd_settings, distribution_family)
        }
        SshConfigEvidence::ConfigFileSettings(sshd_settings) => {
            let include_warning = sshd_settings.contains_key("include").then(|| {
                AuditCheck::new(
                    gettext("SSH Configuration"),
                    AuditStatus::StatusUnknown,
                    gettext(
                        "The SSH configuration includes other files that were not evaluated; the \
                         settings below may be overridden.",
                    ),
                )
                .with_suggested_commands([SSHD_EFFECTIVE_CONFIG_COMMAND])
                .with_documentation(SSH_DOCUMENTATION_URL)
            });
            include_warning
                .into_iter()
                .chain(ssh_setting_checks(sshd_settings, distribution_family))
                .collect()
        }
        SshConfigEvidence::ConfigUnreadable => vec![
            AuditCheck::new(
                gettext("SSH Configuration"),
                AuditStatus::StatusUnknown,
                gettext("Could not read SSH configuration"),
            )
            .with_suggested_commands([SSHD_EFFECTIVE_CONFIG_COMMAND])
            .with_documentation(SSH_DOCUMENTATION_URL),
        ],
    }
}

async fn inspect_ssh_configuration() -> SshConfigEvidence {
    let effective_probe = run_command_probe("sshd", &["-T"]).await;
    if let Some(effective_output) = effective_probe
        .verified_text()
        .filter(|effective_output| !effective_output.is_empty())
    {
        return SshConfigEvidence::EffectiveSettings(parse_sshd_effective_output(effective_output));
    }
    read_host_text(SSHD_CONFIG_PATH)
        .await
        .map_or(SshConfigEvidence::ConfigUnreadable, |config_text| {
            SshConfigEvidence::ConfigFileSettings(parse_sshd_config_file(&config_text))
        })
}

async fn audit_ssh_security(distribution_family: DistributionFamily) -> Vec<AuditCheck> {
    if !systemd_is_available() {
        return vec![
            AuditCheck::new(
                gettext("SSH Server"),
                AuditStatus::StatusUnknown,
                gettext("SSH server status could not be determined"),
            )
            .with_documentation(SSH_DOCUMENTATION_URL),
        ];
    }
    if first_active_unit(&SSH_SERVER_UNITS).await.is_none() {
        return vec![
            AuditCheck::new(
                gettext("SSH Server"),
                AuditStatus::CheckPassed,
                gettext("SSH server is not running (no remote attack surface)"),
            )
            .with_documentation(SSH_DOCUMENTATION_URL),
        ];
    }
    let running_row = AuditCheck::new(
        gettext("SSH Server"),
        AuditStatus::CheckPassed,
        gettext("SSH server is running"),
    )
    .with_documentation(SSH_DOCUMENTATION_URL);
    std::iter::once(running_row)
        .chain(ssh_configuration_checks(
            &inspect_ssh_configuration().await,
            distribution_family,
        ))
        .collect()
}

pub fn portmaster_service_check(
    service_state: UnitState,
    distribution_family: DistributionFamily,
) -> AuditCheck {
    let check_name = gettext("Portmaster");
    match service_state {
        UnitState::UnitActive => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext("The Portmaster service is active"),
        )
        .with_documentation(PORTMASTER_DOCUMENTATION_URL),
        UnitState::UnitInactive => AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            gettext("Portmaster is installed but not running"),
        )
        .with_recommendation(gettext(
            "Start the Portmaster service to enable network protection",
        ))
        .with_suggested_commands(suggested_command(
            SuggestedRemedy::PortmasterServiceStart,
            distribution_family,
        ))
        .with_documentation(PORTMASTER_DOCUMENTATION_URL),
        UnitState::UnitNotFound | UnitState::SystemdUnavailable => AuditCheck::new(
            check_name,
            AuditStatus::CheckSkipped,
            gettext("Not detected — optional network monitor and application firewall"),
        )
        .with_documentation(PORTMASTER_INSTALL_URL),
    }
}

pub fn lynis_deep_scan_check(
    lynis_installed: bool,
    distribution_family: DistributionFamily,
) -> AuditCheck {
    let check_name = "Lynis".to_owned();
    let lynis_row = if lynis_installed {
        AuditCheck::new(
            check_name,
            AuditStatus::CheckSkipped,
            gettext("Lynis needs administrator access, so ClamUI does not run it."),
        )
        .with_recommendation(gettext(
            "Run 'sudo lynis audit system' for detailed recommendations",
        ))
    } else {
        AuditCheck::new(
            check_name,
            AuditStatus::CheckSkipped,
            gettext("{name} is not installed").replace("{name}", "Lynis"),
        )
        .with_recommendation(
            gettext("Install {name} for comprehensive security auditing")
                .replace("{name}", "Lynis"),
        )
        .with_suggested_commands(suggested_command(
            SuggestedRemedy::LynisProgramInstall,
            distribution_family,
        ))
    };
    lynis_row
        .with_suggested_commands([LYNIS_AUDIT_COMMAND])
        .with_documentation(LYNIS_DOCUMENTATION_URL)
}

pub fn chkrootkit_deep_scan_check(
    chkrootkit_installed: bool,
    distribution_family: DistributionFamily,
) -> AuditCheck {
    let check_name = "chkrootkit".to_owned();
    let chkrootkit_row = if chkrootkit_installed {
        AuditCheck::new(
            check_name,
            AuditStatus::CheckSkipped,
            gettext("chkrootkit needs administrator access, so ClamUI does not run it."),
        )
        .with_suggested_commands([CHKROOTKIT_SCAN_COMMAND])
    } else {
        AuditCheck::new(
            check_name,
            AuditStatus::CheckSkipped,
            gettext("{name} is not installed").replace("{name}", "chkrootkit"),
        )
        .with_recommendation(gettext("Install chkrootkit for rootkit detection"))
        .with_suggested_commands(suggested_command(
            SuggestedRemedy::ChkrootkitProgramInstall,
            distribution_family,
        ))
    };
    chkrootkit_row.with_documentation(CHKROOTKIT_DOCUMENTATION_URL)
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
        AuditCategory::AutomaticUpdates => {
            let mechanism_row = update_mechanism_check(
                inspect_update_mechanism(distribution_family).await,
                distribution_family,
            );
            std::iter::once(mechanism_row)
                .chain(
                    Path::new(REBOOT_REQUIRED_PATH)
                        .exists()
                        .then(pending_reboot_check),
                )
                .collect()
        }
        AuditCategory::IntrusionDetection => intrusion_detection_checks(
            inspect_tool_presence(IntrusionDetectionTool::Fail2banTool).await,
            inspect_tool_presence(IntrusionDetectionTool::CrowdsecTool).await,
            distribution_family,
        ),
        AuditCategory::SshSecurity => audit_ssh_security(distribution_family).await,
        AuditCategory::PortmasterService => vec![portmaster_service_check(
            probe_unit_state(PORTMASTER_UNIT).await,
            distribution_family,
        )],
        AuditCategory::DeepScans => vec![
            lynis_deep_scan_check(locate_host_program("lynis").is_some(), distribution_family),
            chkrootkit_deep_scan_check(
                locate_host_program("chkrootkit").is_some(),
                distribution_family,
            ),
        ],
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
    fn apt_periodic_values_are_classified() {
        assert_eq!(
            parse_apt_periodic_state("APT::Periodic::Unattended-Upgrade \"1\";\n"),
            AptPeriodicState::UpgradesEnabled
        );
        assert_eq!(
            parse_apt_periodic_state("APT::Periodic::Unattended-Upgrade \"true\";\n"),
            AptPeriodicState::UpgradesEnabled
        );
        assert_eq!(
            parse_apt_periodic_state("APT::Periodic::Unattended-Upgrade \"0\";\n"),
            AptPeriodicState::UpgradesDisabled
        );
        assert_eq!(
            parse_apt_periodic_state(""),
            AptPeriodicState::NotConfigured
        );
    }

    #[test]
    fn update_rows_suggest_commands_for_the_detected_mechanism() {
        assert_eq!(
            suggested_commands(&update_mechanism_check(
                UpdateMechanismEvidence::NixosUpgradeAbsent,
                DistributionFamily::NixosFamily
            )),
            vec!["system.autoUpgrade.enable = true;"]
        );
        assert_eq!(
            suggested_commands(&update_mechanism_check(
                UpdateMechanismEvidence::DnfTimerInactive,
                DistributionFamily::FedoraWorkstation
            )),
            vec!["sudo systemctl enable --now dnf-automatic.timer"]
        );
        assert_eq!(
            update_mechanism_check(
                UpdateMechanismEvidence::MechanismUndetermined,
                DistributionFamily::ArchFamily
            )
            .check_status,
            AuditStatus::StatusUnknown
        );
        assert!(
            suggested_commands(&update_mechanism_check(
                UpdateMechanismEvidence::MechanismUndetermined,
                DistributionFamily::ArchFamily
            ))
            .is_empty()
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

    #[test]
    fn effective_sshd_output_keeps_the_first_value_of_each_key() {
        let sshd_settings = parse_sshd_effective_output(
            "permitrootlogin no\nPasswordAuthentication yes\npermitrootlogin yes\nempty\n",
        );
        assert_eq!(
            sshd_settings.get("permitrootlogin").map(String::as_str),
            Some("no")
        );
        assert_eq!(
            sshd_settings
                .get("passwordauthentication")
                .map(String::as_str),
            Some("yes")
        );
        assert!(!sshd_settings.contains_key("empty"));
    }

    #[test]
    fn sshd_config_files_skip_comments_and_stop_at_match_blocks() {
        let sshd_settings = parse_sshd_config_file(
            "# PermitRootLogin yes\n\n  X11Forwarding   yes\nmatch User deploy\nPermitRootLogin \
             yes\n",
        );
        assert_eq!(
            sshd_settings.get("x11forwarding").map(String::as_str),
            Some("yes")
        );
        assert!(!sshd_settings.contains_key("permitrootlogin"));
    }

    #[test]
    fn ssh_rows_use_the_openssh_defaults_when_a_setting_is_absent() {
        assert_eq!(
            row_statuses(&ssh_configuration_checks(
                &SshConfigEvidence::EffectiveSettings(SshdSettings::new()),
                DistributionFamily::DebianFamily
            )),
            vec![
                AuditStatus::CheckPassed,
                AuditStatus::NeedsReview,
                AuditStatus::CheckPassed
            ]
        );
    }

    #[test]
    fn ssh_rows_compare_values_case_insensitively() {
        let hardened_settings =
            parse_sshd_config_file("PermitRootLogin No\nPasswordAuthentication NO\n");
        assert_eq!(
            row_statuses(&ssh_configuration_checks(
                &SshConfigEvidence::EffectiveSettings(hardened_settings),
                DistributionFamily::DebianFamily
            )),
            vec![
                AuditStatus::CheckPassed,
                AuditStatus::CheckPassed,
                AuditStatus::CheckPassed
            ]
        );
    }

    #[test]
    fn permissive_ssh_settings_are_reported_with_distribution_guidance() {
        let open_settings = parse_sshd_effective_output(
            "permitrootlogin yes\npasswordauthentication yes\nx11forwarding yes\n",
        );
        let ssh_rows = ssh_configuration_checks(
            &SshConfigEvidence::EffectiveSettings(open_settings),
            DistributionFamily::NixosFamily,
        );
        assert_eq!(
            row_statuses(&ssh_rows),
            vec![
                AuditStatus::CheckFailed,
                AuditStatus::NeedsReview,
                AuditStatus::NeedsReview
            ]
        );
        assert_eq!(
            suggested_commands(&ssh_rows[0]),
            vec!["services.openssh.settings.PermitRootLogin = \"no\";"]
        );
        assert_eq!(ssh_rows[0].status_detail, "Root login is allowed (yes)");
    }

    #[test]
    fn included_config_files_downgrade_confidence_in_the_file_reading() {
        let included_settings =
            parse_sshd_config_file("Include /etc/ssh/extra.conf\nPermitRootLogin no\n");
        let ssh_rows = ssh_configuration_checks(
            &SshConfigEvidence::ConfigFileSettings(included_settings),
            DistributionFamily::DebianFamily,
        );
        assert_eq!(ssh_rows.len(), 4);
        assert_eq!(ssh_rows[0].check_status, AuditStatus::StatusUnknown);
        assert_eq!(
            suggested_commands(&ssh_rows[0]),
            vec![SSHD_EFFECTIVE_CONFIG_COMMAND]
        );
        assert_eq!(
            row_statuses(&ssh_configuration_checks(
                &SshConfigEvidence::ConfigUnreadable,
                DistributionFamily::DebianFamily
            )),
            vec![AuditStatus::StatusUnknown]
        );
    }

    #[test]
    fn portmaster_follows_the_service_state_only() {
        assert_eq!(
            portmaster_service_check(UnitState::UnitActive, DistributionFamily::DebianFamily)
                .check_status,
            AuditStatus::CheckPassed
        );
        assert_eq!(
            portmaster_service_check(UnitState::UnitInactive, DistributionFamily::DebianFamily)
                .check_status,
            AuditStatus::NeedsReview
        );
        assert_eq!(
            portmaster_service_check(UnitState::UnitNotFound, DistributionFamily::DebianFamily)
                .check_status,
            AuditStatus::CheckSkipped
        );
        assert_eq!(
            portmaster_service_check(
                UnitState::SystemdUnavailable,
                DistributionFamily::UnrecognizedFamily
            )
            .check_status,
            AuditStatus::CheckSkipped
        );
    }

    #[test]
    fn deep_scans_are_copy_only_and_never_claim_a_result() {
        let installed_row = lynis_deep_scan_check(true, DistributionFamily::DebianFamily);
        assert_eq!(installed_row.check_status, AuditStatus::CheckSkipped);
        assert_eq!(
            suggested_commands(&installed_row),
            vec!["sudo lynis audit system"]
        );
        assert_eq!(
            suggested_commands(&lynis_deep_scan_check(
                false,
                DistributionFamily::FedoraWorkstation
            )),
            vec!["sudo dnf install lynis", "sudo lynis audit system"]
        );
        assert_eq!(
            suggested_commands(&chkrootkit_deep_scan_check(
                true,
                DistributionFamily::DebianFamily
            )),
            vec!["sudo chkrootkit -q"]
        );
        assert!(
            suggested_commands(&chkrootkit_deep_scan_check(
                false,
                DistributionFamily::NixosFamily
            ))
            .is_empty()
        );
    }
}

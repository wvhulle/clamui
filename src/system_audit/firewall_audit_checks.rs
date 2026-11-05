use gettextrs::gettext;

use crate::{
    clamav_components::distribution_install_guides::DistributionFamily,
    system_audit::{
        audit_report_model::{AuditCategory, AuditCheck, AuditSection, AuditStatus},
        host_command_probes::{first_active_unit, systemd_is_available},
        suggested_audit_commands::{SuggestedRemedy, suggested_command},
    },
};

const NIXOS_FIREWALL_UNIT: &str = "firewall.service";
const FIREWALL_SERVICE_UNITS: [&str; 5] = [
    NIXOS_FIREWALL_UNIT,
    "firewalld.service",
    "ufw.service",
    "nftables.service",
    "iptables.service",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewallServiceEvidence {
    ActiveUnit(&'static str),
    NoActiveUnit,
    SystemdMissing,
}

pub fn firewall_service_check(
    service_evidence: FirewallServiceEvidence,
    distribution_family: DistributionFamily,
) -> AuditCheck {
    let check_name = gettext("Firewall Service");
    match service_evidence {
        FirewallServiceEvidence::ActiveUnit(NIXOS_FIREWALL_UNIT)
            if distribution_family == DistributionFamily::NixosFamily =>
        {
            AuditCheck::new(
                check_name,
                AuditStatus::CheckPassed,
                gettext("The NixOS firewall service is active; allowed ports were not evaluated."),
            )
        }
        FirewallServiceEvidence::ActiveUnit(service_unit) => AuditCheck::new(
            check_name,
            AuditStatus::StatusUnknown,
            gettext("Service {name} is active; its rules were not inspected.")
                .replace("{name}", service_unit),
        ),
        FirewallServiceEvidence::NoActiveUnit => AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            gettext("No known firewall service is active; rules may still be loaded another way."),
        )
        .with_recommendation(gettext("Enable the firewall"))
        .with_suggested_commands(suggested_command(
            SuggestedRemedy::FirewallServiceEnable,
            distribution_family,
        )),
        FirewallServiceEvidence::SystemdMissing => AuditCheck::new(
            check_name,
            AuditStatus::CheckSkipped,
            gettext("Firewall services could not be listed without systemd."),
        ),
    }
}

async fn inspect_firewall_service() -> FirewallServiceEvidence {
    if !systemd_is_available() {
        return FirewallServiceEvidence::SystemdMissing;
    }
    first_active_unit(&FIREWALL_SERVICE_UNITS).await.map_or(
        FirewallServiceEvidence::NoActiveUnit,
        FirewallServiceEvidence::ActiveUnit,
    )
}

pub async fn audit_firewall(distribution_family: DistributionFamily) -> AuditSection {
    AuditSection {
        audit_category: AuditCategory::FirewallProtection,
        section_checks: vec![firewall_service_check(
            inspect_firewall_service().await,
            distribution_family,
        )],
    }
}

#[cfg(test)]
mod firewall_audit_checks_tests {
    use super::*;

    #[test]
    fn firewall_service_row_never_claims_protection_from_a_generic_active_unit() {
        assert_eq!(
            firewall_service_check(
                FirewallServiceEvidence::ActiveUnit("firewall.service"),
                DistributionFamily::NixosFamily
            )
            .check_status,
            AuditStatus::CheckPassed
        );
        assert_eq!(
            firewall_service_check(
                FirewallServiceEvidence::ActiveUnit("ufw.service"),
                DistributionFamily::DebianFamily
            )
            .check_status,
            AuditStatus::StatusUnknown
        );
        assert_eq!(
            firewall_service_check(
                FirewallServiceEvidence::ActiveUnit("firewall.service"),
                DistributionFamily::DebianFamily
            )
            .check_status,
            AuditStatus::StatusUnknown
        );
        assert_eq!(
            firewall_service_check(
                FirewallServiceEvidence::NoActiveUnit,
                DistributionFamily::DebianFamily
            )
            .check_status,
            AuditStatus::NeedsReview
        );
        assert_eq!(
            firewall_service_check(
                FirewallServiceEvidence::SystemdMissing,
                DistributionFamily::UnrecognizedFamily
            )
            .check_status,
            AuditStatus::CheckSkipped
        );
    }
}

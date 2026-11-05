use crate::clamav_components::distribution_install_guides::DistributionFamily;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuggestedRemedy {
    ClamavDaemonStart,
    FreshclamUpdatesEnable,
    FirewallServiceEnable,
    IntrusionPreventionInstall,
    Fail2banServiceStart,
    CrowdsecServiceStart,
    OnAccessScanningEnable,
    OnAccessPreventionEnable,
    ScheduledScanEnable,
    BackgroundAlertsEnable,
}

fn non_nixos_or_option(
    distribution_family: DistributionFamily,
    nixos_option: &'static str,
    generic_command: &'static str,
) -> Option<&'static str> {
    if distribution_family == DistributionFamily::NixosFamily {
        Some(nixos_option)
    } else {
        Some(generic_command)
    }
}

pub const fn rootkit_check_command(distribution_family: DistributionFamily) -> &'static str {
    match distribution_family {
        DistributionFamily::NixosFamily => "sudo nix-store --verify --check-contents",
        DistributionFamily::DebianFamily
        | DistributionFamily::FedoraWorkstation
        | DistributionFamily::FedoraAtomic
        | DistributionFamily::ArchFamily
        | DistributionFamily::UnrecognizedFamily => "sudo chkrootkit -q",
    }
}

pub fn suggested_command(
    suggested_remedy: SuggestedRemedy,
    distribution_family: DistributionFamily,
) -> Option<&'static str> {
    use DistributionFamily::{
        ArchFamily, DebianFamily, FedoraAtomic, FedoraWorkstation, NixosFamily, UnrecognizedFamily,
    };
    match suggested_remedy {
        SuggestedRemedy::ClamavDaemonStart => match distribution_family {
            DebianFamily | ArchFamily => Some("sudo systemctl start clamav-daemon"),
            FedoraWorkstation | FedoraAtomic => Some("sudo systemctl start clamd@scan"),
            NixosFamily => Some("services.clamav.daemon.enable = true;"),
            UnrecognizedFamily => None,
        },
        SuggestedRemedy::FreshclamUpdatesEnable => match distribution_family {
            DebianFamily | FedoraWorkstation | FedoraAtomic | ArchFamily => {
                Some("sudo systemctl enable --now clamav-freshclam")
            }
            NixosFamily => Some("services.clamav.updater.enable = true;"),
            UnrecognizedFamily => None,
        },
        SuggestedRemedy::FirewallServiceEnable => match distribution_family {
            DebianFamily => Some("sudo apt install ufw && sudo ufw enable"),
            FedoraWorkstation => {
                Some("sudo dnf install firewalld && sudo systemctl enable --now firewalld")
            }
            FedoraAtomic => Some("sudo systemctl enable --now firewalld"),
            ArchFamily => Some("sudo pacman -S firewalld && sudo systemctl enable --now firewalld"),
            NixosFamily => Some("networking.firewall.enable = true;"),
            UnrecognizedFamily => None,
        },
        SuggestedRemedy::IntrusionPreventionInstall => match distribution_family {
            DebianFamily => Some("sudo apt install fail2ban"),
            FedoraWorkstation => Some("sudo dnf install fail2ban"),
            FedoraAtomic => Some("sudo rpm-ostree install fail2ban\nsudo systemctl reboot"),
            ArchFamily => Some("sudo pacman -S fail2ban"),
            NixosFamily => Some("services.fail2ban.enable = true;"),
            UnrecognizedFamily => None,
        },
        SuggestedRemedy::Fail2banServiceStart => non_nixos_or_option(
            distribution_family,
            "services.fail2ban.enable = true;",
            "sudo systemctl start fail2ban",
        ),
        SuggestedRemedy::CrowdsecServiceStart => non_nixos_or_option(
            distribution_family,
            "services.crowdsec.enable = true;",
            "sudo systemctl start crowdsec",
        ),
        SuggestedRemedy::OnAccessScanningEnable => non_nixos_or_option(
            distribution_family,
            "services.clamav.clamonacc.enable = true;",
            "sudo systemctl enable --now clamav-clamonacc",
        ),
        SuggestedRemedy::OnAccessPreventionEnable => match distribution_family {
            NixosFamily => Some("services.clamav.daemon.settings.OnAccessPrevention = true;"),
            DebianFamily | FedoraWorkstation | FedoraAtomic | ArchFamily | UnrecognizedFamily => {
                None
            }
        },
        SuggestedRemedy::BackgroundAlertsEnable => non_nixos_or_option(
            distribution_family,
            "services.clamui.enable = true;",
            "systemctl --user enable --now clamui.service",
        ),
        SuggestedRemedy::ScheduledScanEnable => match distribution_family {
            NixosFamily => Some("services.clamav.scanner.enable = true;"),
            DebianFamily | FedoraWorkstation | FedoraAtomic | ArchFamily | UnrecognizedFamily => {
                None
            }
        },
    }
}

#[cfg(test)]
mod suggested_audit_commands_tests {
    use super::*;

    const ALL_REMEDIES: [SuggestedRemedy; 10] = [
        SuggestedRemedy::ClamavDaemonStart,
        SuggestedRemedy::FreshclamUpdatesEnable,
        SuggestedRemedy::FirewallServiceEnable,
        SuggestedRemedy::IntrusionPreventionInstall,
        SuggestedRemedy::Fail2banServiceStart,
        SuggestedRemedy::CrowdsecServiceStart,
        SuggestedRemedy::OnAccessScanningEnable,
        SuggestedRemedy::OnAccessPreventionEnable,
        SuggestedRemedy::ScheduledScanEnable,
        SuggestedRemedy::BackgroundAlertsEnable,
    ];

    fn remedies_for(distribution_family: DistributionFamily) -> Vec<&'static str> {
        ALL_REMEDIES
            .into_iter()
            .filter_map(|suggested_remedy| suggested_command(suggested_remedy, distribution_family))
            .collect()
    }

    fn assert_family_avoids_tools(distribution_family: DistributionFamily, foreign_tools: &[&str]) {
        remedies_for(distribution_family)
            .iter()
            .for_each(|family_command| {
                foreign_tools.iter().for_each(|foreign_tool| {
                    assert!(!family_command.contains(foreign_tool), "{family_command}");
                });
            });
    }

    #[test]
    fn nixos_suggestions_are_configuration_options_rather_than_imperative_commands() {
        let nixos_suggestions = remedies_for(DistributionFamily::NixosFamily);
        assert!(!nixos_suggestions.is_empty());
        nixos_suggestions.iter().for_each(|nixos_suggestion| {
            assert!(
                nixos_suggestion.ends_with(';') && !nixos_suggestion.contains("sudo"),
                "{nixos_suggestion}"
            );
        });
    }

    #[test]
    fn package_managers_never_leak_into_other_families() {
        assert_family_avoids_tools(
            DistributionFamily::DebianFamily,
            &["dnf", "pacman", "rpm-ostree"],
        );
        assert_family_avoids_tools(
            DistributionFamily::FedoraWorkstation,
            &["apt ", "pacman", "rpm-ostree"],
        );
        assert_family_avoids_tools(
            DistributionFamily::FedoraAtomic,
            &["apt ", "dnf ", "pacman"],
        );
        assert_family_avoids_tools(
            DistributionFamily::ArchFamily,
            &["apt ", "dnf", "rpm-ostree"],
        );
    }

    #[test]
    fn unrecognized_systems_get_no_package_manager_guess() {
        remedies_for(DistributionFamily::UnrecognizedFamily)
            .iter()
            .for_each(|generic_command| {
                assert!(!generic_command.contains("install"), "{generic_command}");
            });
    }
}

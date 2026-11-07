use crate::host_services::clamav_programs::distribution_install_guides::DistributionFamily;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuggestedRemedy {
    ClamavDaemonStart,
    ClamavDaemonRestart,
    FreshclamUpdatesEnable,
    OnAccessScanningEnable,
    OnAccessPreventionEnable,
    OnAccessWatchedPathAdd,
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
        SuggestedRemedy::ClamavDaemonRestart => match distribution_family {
            DebianFamily | ArchFamily => Some("sudo systemctl restart clamav-daemon"),
            FedoraWorkstation | FedoraAtomic => Some("sudo systemctl restart clamd@scan"),
            NixosFamily | UnrecognizedFamily => None,
        },
        SuggestedRemedy::FreshclamUpdatesEnable => match distribution_family {
            DebianFamily | FedoraWorkstation | FedoraAtomic | ArchFamily => {
                Some("sudo systemctl enable --now clamav-freshclam")
            }
            NixosFamily => Some("services.clamav.updater.enable = true;"),
            UnrecognizedFamily => None,
        },
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
        SuggestedRemedy::OnAccessWatchedPathAdd => match distribution_family {
            NixosFamily => {
                Some("services.clamav.daemon.settings.OnAccessIncludePath = [ \"/home\" ];")
            }
            DebianFamily | FedoraWorkstation | FedoraAtomic | ArchFamily | UnrecognizedFamily => {
                None
            }
        },
        SuggestedRemedy::BackgroundAlertsEnable => non_nixos_or_option(
            distribution_family,
            "services.lazaret.enable = true;",
            "systemctl --user enable --now lazaret.service",
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
mod suggested_remedy_commands_tests {
    use super::*;

    const ALL_REMEDIES: [SuggestedRemedy; 8] = [
        SuggestedRemedy::ClamavDaemonStart,
        SuggestedRemedy::ClamavDaemonRestart,
        SuggestedRemedy::FreshclamUpdatesEnable,
        SuggestedRemedy::OnAccessScanningEnable,
        SuggestedRemedy::OnAccessPreventionEnable,
        SuggestedRemedy::OnAccessWatchedPathAdd,
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

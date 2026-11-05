use crate::clamav_components::distribution_install_guides::DistributionFamily;

pub const FRESHCLAM_UPDATE_COMMAND: &str = "sudo freshclam";
pub const LYNIS_AUDIT_COMMAND: &str = "sudo lynis audit system";
pub const CHKROOTKIT_SCAN_COMMAND: &str = "sudo chkrootkit -q";
pub const UFW_STATUS_COMMAND: &str = "sudo ufw status verbose";
pub const UFW_ENABLE_COMMAND: &str = "sudo ufw enable";
pub const FIREWALLD_STATUS_COMMAND: &str = "sudo firewall-cmd --list-all";
pub const NFTABLES_RULESET_COMMAND: &str = "sudo nft list ruleset";
pub const IPTABLES_RULESET_COMMAND: &str = "sudo iptables-save";
pub const IP6TABLES_RULESET_COMMAND: &str = "sudo ip6tables-save";
pub const SSHD_EFFECTIVE_CONFIG_COMMAND: &str = "sudo sshd -T";
pub const UNATTENDED_RECONFIGURE_COMMAND: &str = "sudo dpkg-reconfigure unattended-upgrades";
pub const DNF_AUTOMATIC_ENABLE_COMMAND: &str = "sudo systemctl enable --now dnf-automatic.timer";
pub const RPM_OSTREE_AUTOMATIC_ENABLE_COMMAND: &str =
    "sudo systemctl enable --now rpm-ostreed-automatic.timer";

const SSHD_CONFIG_EDIT_COMMAND: &str = "sudoedit /etc/ssh/sshd_config";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuggestedRemedy {
    ClamavDaemonStart,
    FreshclamUpdatesEnable,
    FirewallServiceEnable,
    AutomaticUpdatesEnable,
    IntrusionPreventionInstall,
    Fail2banServiceStart,
    CrowdsecServiceStart,
    PortmasterServiceStart,
    LynisProgramInstall,
    ChkrootkitProgramInstall,
    SshRootLoginDisable,
    SshPasswordLoginDisable,
    SshX11ForwardingDisable,
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
        SuggestedRemedy::AutomaticUpdatesEnable => match distribution_family {
            DebianFamily => Some("sudo apt install unattended-upgrades"),
            FedoraWorkstation => Some("sudo dnf install dnf-automatic"),
            FedoraAtomic => Some(RPM_OSTREE_AUTOMATIC_ENABLE_COMMAND),
            NixosFamily => Some("system.autoUpgrade.enable = true;"),
            ArchFamily | UnrecognizedFamily => None,
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
        SuggestedRemedy::PortmasterServiceStart => non_nixos_or_option(
            distribution_family,
            "services.portmaster.enable = true;",
            "sudo systemctl start portmaster",
        ),
        SuggestedRemedy::LynisProgramInstall => match distribution_family {
            DebianFamily => Some("sudo apt install lynis"),
            FedoraWorkstation => Some("sudo dnf install lynis"),
            FedoraAtomic => Some("sudo rpm-ostree install lynis\nsudo systemctl reboot"),
            ArchFamily => Some("sudo pacman -S lynis"),
            NixosFamily => Some("environment.systemPackages = [ pkgs.lynis ];"),
            UnrecognizedFamily => None,
        },
        SuggestedRemedy::ChkrootkitProgramInstall => match distribution_family {
            DebianFamily => Some("sudo apt install chkrootkit"),
            FedoraWorkstation => Some("sudo dnf install chkrootkit"),
            FedoraAtomic => Some("sudo rpm-ostree install chkrootkit\nsudo systemctl reboot"),
            ArchFamily | NixosFamily | UnrecognizedFamily => None,
        },
        SuggestedRemedy::SshRootLoginDisable => non_nixos_or_option(
            distribution_family,
            "services.openssh.settings.PermitRootLogin = \"no\";",
            SSHD_CONFIG_EDIT_COMMAND,
        ),
        SuggestedRemedy::SshPasswordLoginDisable => non_nixos_or_option(
            distribution_family,
            "services.openssh.settings.PasswordAuthentication = false;",
            SSHD_CONFIG_EDIT_COMMAND,
        ),
        SuggestedRemedy::SshX11ForwardingDisable => non_nixos_or_option(
            distribution_family,
            "services.openssh.settings.X11Forwarding = false;",
            SSHD_CONFIG_EDIT_COMMAND,
        ),
    }
}

#[cfg(test)]
mod suggested_audit_commands_tests {
    use super::*;

    const ALL_REMEDIES: [SuggestedRemedy; 13] = [
        SuggestedRemedy::ClamavDaemonStart,
        SuggestedRemedy::FreshclamUpdatesEnable,
        SuggestedRemedy::FirewallServiceEnable,
        SuggestedRemedy::AutomaticUpdatesEnable,
        SuggestedRemedy::IntrusionPreventionInstall,
        SuggestedRemedy::Fail2banServiceStart,
        SuggestedRemedy::CrowdsecServiceStart,
        SuggestedRemedy::PortmasterServiceStart,
        SuggestedRemedy::LynisProgramInstall,
        SuggestedRemedy::ChkrootkitProgramInstall,
        SuggestedRemedy::SshRootLoginDisable,
        SuggestedRemedy::SshPasswordLoginDisable,
        SuggestedRemedy::SshX11ForwardingDisable,
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

    #[test]
    fn removed_or_unpackaged_tools_have_no_install_suggestion() {
        assert_eq!(
            suggested_command(
                SuggestedRemedy::ChkrootkitProgramInstall,
                DistributionFamily::NixosFamily
            ),
            None
        );
        assert_eq!(
            suggested_command(
                SuggestedRemedy::ChkrootkitProgramInstall,
                DistributionFamily::ArchFamily
            ),
            None
        );
    }
}

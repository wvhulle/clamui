use crate::clamav_components::component_availability::ClamavComponent;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DistributionFamily {
    DebianFamily,
    FedoraWorkstation,
    FedoraAtomic,
    ArchFamily,
    NixosFamily,
    UnrecognizedFamily,
}

#[derive(Clone, Copy, Debug)]
pub struct DistributionInstallGuide {
    pub distribution_family: DistributionFamily,
    pub distribution_label: &'static str,
    pub install_command: &'static str,
}

const fn install_guide(
    distribution_family: DistributionFamily,
    distribution_label: &'static str,
    install_command: &'static str,
) -> DistributionInstallGuide {
    DistributionInstallGuide {
        distribution_family,
        distribution_label,
        install_command,
    }
}

const DEBIAN_LABEL: &str = "Ubuntu/Debian";
const FEDORA_LABEL: &str = "Fedora Workstation";
const ATOMIC_LABEL: &str = "Fedora Atomic";
const ARCH_LABEL: &str = "Arch Linux";
const NIXOS_LABEL: &str = "NixOS";

const CLAMSCAN_GUIDES: [DistributionInstallGuide; 5] = [
    install_guide(
        DistributionFamily::DebianFamily,
        DEBIAN_LABEL,
        "sudo apt install clamav",
    ),
    install_guide(
        DistributionFamily::FedoraWorkstation,
        FEDORA_LABEL,
        "sudo dnf install clamav",
    ),
    install_guide(
        DistributionFamily::FedoraAtomic,
        ATOMIC_LABEL,
        "sudo rpm-ostree install clamav\nsudo systemctl reboot",
    ),
    install_guide(
        DistributionFamily::ArchFamily,
        ARCH_LABEL,
        "sudo pacman -S clamav",
    ),
    install_guide(
        DistributionFamily::NixosFamily,
        NIXOS_LABEL,
        "environment.systemPackages = [ pkgs.clamav ];",
    ),
];
const FRESHCLAM_GUIDES: [DistributionInstallGuide; 5] = [
    install_guide(
        DistributionFamily::DebianFamily,
        DEBIAN_LABEL,
        "sudo apt install clamav-freshclam",
    ),
    install_guide(
        DistributionFamily::FedoraWorkstation,
        FEDORA_LABEL,
        "sudo dnf install clamav-freshclam",
    ),
    install_guide(
        DistributionFamily::FedoraAtomic,
        ATOMIC_LABEL,
        "sudo rpm-ostree install clamav-freshclam\nsudo systemctl reboot",
    ),
    install_guide(
        DistributionFamily::ArchFamily,
        ARCH_LABEL,
        "sudo pacman -S clamav",
    ),
    install_guide(
        DistributionFamily::NixosFamily,
        NIXOS_LABEL,
        "services.clamav.updater.enable = true;",
    ),
];
const CLAMDSCAN_GUIDES: [DistributionInstallGuide; 5] = [
    install_guide(
        DistributionFamily::DebianFamily,
        DEBIAN_LABEL,
        "sudo apt install clamav-daemon",
    ),
    install_guide(
        DistributionFamily::FedoraWorkstation,
        FEDORA_LABEL,
        "sudo dnf install clamd",
    ),
    install_guide(
        DistributionFamily::FedoraAtomic,
        ATOMIC_LABEL,
        "sudo rpm-ostree install clamd\nsudo systemctl reboot",
    ),
    install_guide(
        DistributionFamily::ArchFamily,
        ARCH_LABEL,
        "sudo pacman -S clamav",
    ),
    install_guide(
        DistributionFamily::NixosFamily,
        NIXOS_LABEL,
        "services.clamav.daemon.enable = true;",
    ),
];
const CLAMD_GUIDES: [DistributionInstallGuide; 5] = [
    install_guide(
        DistributionFamily::DebianFamily,
        DEBIAN_LABEL,
        "sudo apt install clamav-daemon\nsudo systemctl enable clamav-daemon\nsudo systemctl \
         start clamav-daemon",
    ),
    install_guide(
        DistributionFamily::FedoraWorkstation,
        FEDORA_LABEL,
        "sudo dnf install clamd clamav-freshclam\nsudo freshclam\nsudo systemctl enable \
         clamd@scan\nsudo systemctl start clamd@scan",
    ),
    install_guide(
        DistributionFamily::FedoraAtomic,
        ATOMIC_LABEL,
        "sudo rpm-ostree install clamd clamav-freshclam\nsudo systemctl reboot",
    ),
    install_guide(
        DistributionFamily::ArchFamily,
        ARCH_LABEL,
        "sudo pacman -S clamav\nsudo systemctl enable clamav-daemon\nsudo systemctl start \
         clamav-daemon",
    ),
    install_guide(
        DistributionFamily::NixosFamily,
        NIXOS_LABEL,
        "services.clamav.daemon.enable = true;",
    ),
];

pub fn component_install_guides(component: ClamavComponent) -> &'static [DistributionInstallGuide] {
    match component {
        ClamavComponent::ClamscanScanner => &CLAMSCAN_GUIDES,
        ClamavComponent::FreshclamUpdater => &FRESHCLAM_GUIDES,
        ClamavComponent::ClamdscanClient => &CLAMDSCAN_GUIDES,
        ClamavComponent::ClamdDaemon => &CLAMD_GUIDES,
    }
}

fn os_release_value<'release>(os_release_text: &'release str, release_key: &str) -> &'release str {
    os_release_text
        .lines()
        .filter_map(|release_line| release_line.split_once('='))
        .find(|key_and_value| key_and_value.0.trim() == release_key)
        .map_or("", |key_and_value| key_and_value.1.trim().trim_matches('"'))
}

pub fn parse_distribution_family(os_release_text: &str) -> DistributionFamily {
    let distribution_id = os_release_value(os_release_text, "ID").to_ascii_lowercase();
    let variant_id = os_release_value(os_release_text, "VARIANT_ID").to_ascii_lowercase();
    let related_ids = os_release_value(os_release_text, "ID_LIKE").to_ascii_lowercase();
    let is_related_to = |family_id: &str| {
        related_ids
            .split_whitespace()
            .any(|related_id| related_id == family_id)
    };
    match distribution_id.as_str() {
        "nixos" => DistributionFamily::NixosFamily,
        "debian" | "ubuntu" | "linuxmint" | "pop" => DistributionFamily::DebianFamily,
        "fedora"
            if matches!(
                variant_id.as_str(),
                "silverblue" | "kinoite" | "sericea" | "onyx" | "cosmic-atomic"
            ) =>
        {
            DistributionFamily::FedoraAtomic
        }
        "fedora" => DistributionFamily::FedoraWorkstation,
        "arch" | "manjaro" | "endeavouros" => DistributionFamily::ArchFamily,
        _other_id if is_related_to("debian") || is_related_to("ubuntu") => {
            DistributionFamily::DebianFamily
        }
        _other_id if is_related_to("fedora") => DistributionFamily::FedoraWorkstation,
        _other_id if is_related_to("arch") => DistributionFamily::ArchFamily,
        _other_id => DistributionFamily::UnrecognizedFamily,
    }
}

pub fn detect_distribution_family() -> DistributionFamily {
    std::fs::read_to_string("/etc/os-release")
        .map_or(DistributionFamily::UnrecognizedFamily, |os_release_text| {
            parse_distribution_family(&os_release_text)
        })
}

#[cfg(test)]
mod distribution_install_guides_tests {
    use super::*;

    #[test]
    fn os_release_maps_to_the_expected_family() {
        assert_eq!(
            parse_distribution_family("ID=nixos\n"),
            DistributionFamily::NixosFamily
        );
        assert_eq!(
            parse_distribution_family("ID=\"ubuntu\"\n"),
            DistributionFamily::DebianFamily
        );
        assert_eq!(
            parse_distribution_family("ID=fedora\nVARIANT_ID=silverblue\n"),
            DistributionFamily::FedoraAtomic
        );
        assert_eq!(
            parse_distribution_family("ID=fedora\nVARIANT_ID=workstation\n"),
            DistributionFamily::FedoraWorkstation
        );
        assert_eq!(
            parse_distribution_family("ID=zorin\nID_LIKE=\"ubuntu debian\"\n"),
            DistributionFamily::DebianFamily
        );
        assert_eq!(
            parse_distribution_family("ID=plan9\n"),
            DistributionFamily::UnrecognizedFamily
        );
    }

    #[test]
    fn every_component_has_a_guide_for_every_recognized_family() {
        [
            ClamavComponent::ClamscanScanner,
            ClamavComponent::FreshclamUpdater,
            ClamavComponent::ClamdscanClient,
            ClamavComponent::ClamdDaemon,
        ]
        .into_iter()
        .for_each(|component| {
            [
                DistributionFamily::DebianFamily,
                DistributionFamily::FedoraWorkstation,
                DistributionFamily::FedoraAtomic,
                DistributionFamily::ArchFamily,
                DistributionFamily::NixosFamily,
            ]
            .into_iter()
            .for_each(|distribution_family| {
                assert!(
                    component_install_guides(component)
                        .iter()
                        .any(|guide| guide.distribution_family == distribution_family)
                );
            });
        });
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DistributionFamily {
    DebianFamily,
    FedoraWorkstation,
    FedoraAtomic,
    ArchFamily,
    NixosFamily,
    UnrecognizedFamily,
}

use crate::host_services::desktop::flatpak_sandbox::readable_host_path;

#[derive(Clone, Copy, Debug)]
pub struct DistributionInstallGuide {
    pub distribution_family: DistributionFamily,
    pub install_command: &'static str,
}

const fn install_guide(
    distribution_family: DistributionFamily,
    install_command: &'static str,
) -> DistributionInstallGuide {
    DistributionInstallGuide {
        distribution_family,
        install_command,
    }
}

const CLAMSCAN_GUIDES: [DistributionInstallGuide; 5] = [
    install_guide(DistributionFamily::DebianFamily, "sudo apt install clamav"),
    install_guide(
        DistributionFamily::FedoraWorkstation,
        "sudo dnf install clamav",
    ),
    install_guide(
        DistributionFamily::FedoraAtomic,
        "sudo rpm-ostree install clamav\nsudo systemctl reboot",
    ),
    install_guide(DistributionFamily::ArchFamily, "sudo pacman -S clamav"),
    install_guide(
        DistributionFamily::NixosFamily,
        "environment.systemPackages = [ pkgs.clamav ];",
    ),
];

pub fn engine_install_guides() -> &'static [DistributionInstallGuide] {
    &CLAMSCAN_GUIDES
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
    std::fs::read_to_string(readable_host_path("/etc/os-release"))
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
    fn the_engine_has_a_guide_for_every_recognized_family() {
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
                engine_install_guides()
                    .iter()
                    .any(|guide| guide.distribution_family == distribution_family)
            );
        });
    }
}

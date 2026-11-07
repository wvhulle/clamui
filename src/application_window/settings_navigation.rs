use gettextrs::gettext;
use relm4::{adw, adw::prelude::*, gtk};

use crate::application_window::application_pages::ApplicationPage;

pub const OPEN_SETTINGS_ACTION_NAME: &str = "open-settings";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingsSubpage {
    ScanExclusions,
    ScanSchedule,
    DeviceAutoScan,
    ScannerEngine,
    DetectionChoices,
    OnAccessScanning,
    SignatureUpdates,
    TrustedDetections,
}

const ALL_SETTINGS_SUBPAGES: [SettingsSubpage; 8] = [
    SettingsSubpage::ScanExclusions,
    SettingsSubpage::ScanSchedule,
    SettingsSubpage::DeviceAutoScan,
    SettingsSubpage::ScannerEngine,
    SettingsSubpage::DetectionChoices,
    SettingsSubpage::OnAccessScanning,
    SettingsSubpage::SignatureUpdates,
    SettingsSubpage::TrustedDetections,
];

impl SettingsSubpage {
    pub const fn action_target(self) -> &'static str {
        match self {
            Self::ScanExclusions => "scan-exclusions",
            Self::ScanSchedule => "scan-schedule",
            Self::DeviceAutoScan => "device-auto-scan",
            Self::ScannerEngine => "scanner-engine",
            Self::DetectionChoices => "detection",
            Self::OnAccessScanning => "on-access-scanning",
            Self::SignatureUpdates => "signature-updates",
            Self::TrustedDetections => "trusted-detections",
        }
    }

    pub fn from_action_target(action_target: &str) -> Option<Self> {
        ALL_SETTINGS_SUBPAGES
            .into_iter()
            .find(|settings_subpage| settings_subpage.action_target() == action_target)
    }

    pub const fn owning_page(self) -> ApplicationPage {
        match self {
            Self::ScanExclusions => ApplicationPage::Scan,
            Self::DeviceAutoScan => ApplicationPage::RemovableDrives,
            Self::ScanSchedule => ApplicationPage::ScheduledScans,
            Self::ScannerEngine | Self::DetectionChoices => ApplicationPage::ScanEngine,
            Self::OnAccessScanning => ApplicationPage::OnAccessScanning,
            Self::TrustedDetections => ApplicationPage::Analysis,
            Self::SignatureUpdates => ApplicationPage::DatabaseUpdates,
        }
    }

    pub fn subpage_title(self) -> String {
        match self {
            Self::ScanExclusions => gettext("Exclusions"),
            Self::ScanSchedule => gettext("Scheduled Scans"),
            Self::DeviceAutoScan => gettext("Device Auto-Scan"),
            Self::ScannerEngine => gettext("Scanner Engine"),
            Self::DetectionChoices => gettext("Detection"),
            Self::OnAccessScanning => gettext("On-Access Scanning"),
            Self::SignatureUpdates => gettext("Signature Updates"),
            Self::TrustedDetections => gettext("Trusted Detections"),
        }
    }

    pub const fn needs_administrator(self) -> bool {
        matches!(
            self,
            Self::ScannerEngine
                | Self::DetectionChoices
                | Self::OnAccessScanning
                | Self::SignatureUpdates
                | Self::TrustedDetections
        )
    }

    fn link_subtitle(self) -> String {
        match self {
            Self::ScanExclusions => gettext("Folders and patterns that Lazaret scans skip"),
            Self::ScanSchedule => gettext("Scan automatically with a systemd timer"),
            Self::DeviceAutoScan => gettext("Scan removable drives when they are connected"),
            Self::ScannerEngine => gettext("clamd settings for every scan on this computer"),
            Self::DetectionChoices => {
                gettext("Unwanted programs, macros, encrypted files and archives")
            }
            Self::OnAccessScanning => gettext("Which folders clamonacc watches, and how it blocks"),
            Self::SignatureUpdates => gettext("How freshclam downloads signatures"),
            Self::TrustedDetections => gettext("Files and detections that ClamAV never reports"),
        }
    }
}

pub fn settings_link_row(settings_subpage: SettingsSubpage) -> adw::ActionRow {
    let link_row = adw::ActionRow::builder()
        .title(settings_subpage.subpage_title())
        .subtitle(settings_subpage.link_subtitle())
        .activatable(true)
        .action_name(format!("win.{OPEN_SETTINGS_ACTION_NAME}"))
        .action_target(&settings_subpage.action_target().to_variant())
        .build();
    if settings_subpage.needs_administrator() {
        link_row.add_prefix(&gtk::Image::from_icon_name("changes-prevent-symbolic"));
    }
    link_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    link_row
}

pub fn system_settings_group(settings_subpages: &[SettingsSubpage]) -> adw::PreferencesGroup {
    let system_group = settings_link_group(gettext("System"), settings_subpages);
    system_group.set_description(Some(&gettext(
        "ClamAV configuration shared by all users. Changes need administrator approval.",
    )));
    system_group
}

pub fn settings_link_group(
    group_title: String,
    settings_subpages: &[SettingsSubpage],
) -> adw::PreferencesGroup {
    let link_group = adw::PreferencesGroup::builder().title(group_title).build();
    settings_subpages
        .iter()
        .for_each(|settings_subpage| link_group.add(&settings_link_row(*settings_subpage)));
    link_group
}

#[cfg(test)]
mod settings_navigation_tests {
    use super::*;

    #[test]
    fn every_subpage_round_trips_through_its_action_target() {
        ALL_SETTINGS_SUBPAGES
            .into_iter()
            .for_each(|settings_subpage| {
                assert_eq!(
                    SettingsSubpage::from_action_target(settings_subpage.action_target()),
                    Some(settings_subpage)
                );
            });
        assert_eq!(SettingsSubpage::from_action_target("unknown"), None);
    }

    #[test]
    fn every_settings_link_opens_the_page_that_owns_it() {
        assert_eq!(
            SettingsSubpage::ScanSchedule.owning_page(),
            ApplicationPage::ScheduledScans
        );
        assert_eq!(
            SettingsSubpage::ScanExclusions.owning_page(),
            ApplicationPage::Scan
        );
        assert_eq!(
            SettingsSubpage::DeviceAutoScan.owning_page(),
            ApplicationPage::RemovableDrives
        );
        assert_eq!(
            SettingsSubpage::ScannerEngine.owning_page(),
            ApplicationPage::ScanEngine
        );
        assert_eq!(
            SettingsSubpage::DetectionChoices.owning_page(),
            ApplicationPage::ScanEngine
        );
        assert_eq!(
            SettingsSubpage::OnAccessScanning.owning_page(),
            ApplicationPage::OnAccessScanning
        );
        assert_eq!(
            SettingsSubpage::SignatureUpdates.owning_page(),
            ApplicationPage::DatabaseUpdates
        );
    }

    #[test]
    fn the_trusted_detections_link_opens_the_analysis_page() {
        let trusted_link = SettingsSubpage::from_action_target("trusted-detections")
            .expect("the deep link target is known");
        assert_eq!(trusted_link, SettingsSubpage::TrustedDetections);
        assert_eq!(trusted_link.owning_page(), ApplicationPage::Analysis);
        assert_eq!(trusted_link.owning_page().page_name(), "analysis");
    }
}

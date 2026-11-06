use gettextrs::gettext;
use relm4::{adw, adw::prelude::*, gtk};

pub const OPEN_SETTINGS_ACTION_NAME: &str = "open-settings";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingsSubpage {
    ScanExclusions,
    ScanSchedule,
    DeviceAutoScan,
    ScannerEngine,
    OnAccessScanning,
    SignatureUpdates,
}

const ALL_SETTINGS_SUBPAGES: [SettingsSubpage; 6] = [
    SettingsSubpage::ScanExclusions,
    SettingsSubpage::ScanSchedule,
    SettingsSubpage::DeviceAutoScan,
    SettingsSubpage::ScannerEngine,
    SettingsSubpage::OnAccessScanning,
    SettingsSubpage::SignatureUpdates,
];

impl SettingsSubpage {
    pub const fn action_target(self) -> &'static str {
        match self {
            Self::ScanExclusions => "scan-exclusions",
            Self::ScanSchedule => "scan-schedule",
            Self::DeviceAutoScan => "device-auto-scan",
            Self::ScannerEngine => "scanner-engine",
            Self::OnAccessScanning => "on-access-scanning",
            Self::SignatureUpdates => "signature-updates",
        }
    }

    pub fn from_action_target(action_target: &str) -> Option<Self> {
        ALL_SETTINGS_SUBPAGES
            .into_iter()
            .find(|settings_subpage| settings_subpage.action_target() == action_target)
    }

    pub const fn owning_page_name(self) -> &'static str {
        match self {
            Self::ScanExclusions
            | Self::ScanSchedule
            | Self::DeviceAutoScan
            | Self::ScannerEngine => "scan",
            Self::OnAccessScanning => "protection",
            Self::SignatureUpdates => "signatures",
        }
    }

    pub fn subpage_title(self) -> String {
        match self {
            Self::ScanExclusions => gettext("Exclusions"),
            Self::ScanSchedule => gettext("Scheduled Scans"),
            Self::DeviceAutoScan => gettext("Device Auto-Scan"),
            Self::ScannerEngine => gettext("Scanner Engine"),
            Self::OnAccessScanning => gettext("On-Access Scanning"),
            Self::SignatureUpdates => gettext("Signature Updates"),
        }
    }

    fn link_subtitle(self) -> String {
        match self {
            Self::ScanExclusions => gettext("Folders and patterns that ClamUI scans skip"),
            Self::ScanSchedule => gettext("Scan automatically with a systemd timer"),
            Self::DeviceAutoScan => gettext("Scan removable drives when they are connected"),
            Self::ScannerEngine => {
                gettext("clamd configuration; changes need administrator approval")
            }
            Self::OnAccessScanning => {
                gettext("clamd on-access configuration; changes need administrator approval")
            }
            Self::SignatureUpdates => {
                gettext("freshclam configuration; changes need administrator approval")
            }
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
    link_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    link_row
}

pub fn settings_link_group(settings_subpages: &[SettingsSubpage]) -> adw::PreferencesGroup {
    let link_group = adw::PreferencesGroup::builder()
        .title(gettext("Settings"))
        .build();
    settings_subpages
        .iter()
        .for_each(|settings_subpage| link_group.add(&settings_link_row(*settings_subpage)));
    link_group
}

pub fn settings_subpage_frame(
    settings_subpage: SettingsSubpage,
    subpage_content: &impl IsA<gtk::Widget>,
) -> adw::NavigationPage {
    let subpage_view = adw::ToolbarView::new();
    subpage_view.add_top_bar(&adw::HeaderBar::new());
    subpage_view.set_content(Some(subpage_content));
    adw::NavigationPage::builder()
        .title(settings_subpage.subpage_title())
        .tag(settings_subpage.action_target())
        .child(&subpage_view)
        .build()
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
    fn scan_settings_open_on_the_scan_page() {
        assert_eq!(SettingsSubpage::ScanSchedule.owning_page_name(), "scan");
        assert_eq!(
            SettingsSubpage::SignatureUpdates.owning_page_name(),
            "signatures"
        );
    }
}

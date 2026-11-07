use gettextrs::gettext;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationPage {
    SignatureSources,
    DatabaseUpdates,
    ScanEngine,
    OnAccessScanning,
    ScheduledScans,
    ManualScan,
    RemovableDrives,
    Detections,
    Quarantine,
    TrustedDetections,
    SentSamples,
}

pub const ALL_APPLICATION_PAGES: [ApplicationPage; 11] = [
    ApplicationPage::SignatureSources,
    ApplicationPage::DatabaseUpdates,
    ApplicationPage::ScanEngine,
    ApplicationPage::OnAccessScanning,
    ApplicationPage::ScheduledScans,
    ApplicationPage::ManualScan,
    ApplicationPage::RemovableDrives,
    ApplicationPage::Detections,
    ApplicationPage::Quarantine,
    ApplicationPage::TrustedDetections,
    ApplicationPage::SentSamples,
];

impl ApplicationPage {
    pub const fn page_name(self) -> &'static str {
        match self {
            Self::SignatureSources => "signature-sources",
            Self::DatabaseUpdates => "database-updates",
            Self::ScanEngine => "scan-engine",
            Self::OnAccessScanning => "on-access",
            Self::ScheduledScans => "scheduled-scans",
            Self::ManualScan => "manual-scan",
            Self::RemovableDrives => "removable-drives",
            Self::Detections => "detections",
            Self::Quarantine => "quarantine",
            Self::TrustedDetections => "trusted-detections",
            Self::SentSamples => "sent-samples",
        }
    }

    pub fn from_page_name(page_name: &str) -> Option<Self> {
        ALL_APPLICATION_PAGES
            .into_iter()
            .find(|application_page| application_page.page_name() == page_name)
    }

    pub fn page_title(self) -> String {
        match self {
            Self::SignatureSources => gettext("Signature Sources"),
            Self::DatabaseUpdates => gettext("Database Updates"),
            Self::ScanEngine => gettext("Scan Engine"),
            Self::OnAccessScanning => gettext("On-Access Scanning"),
            Self::ScheduledScans => gettext("Scheduled Scans"),
            Self::ManualScan => gettext("Manual Scan"),
            Self::RemovableDrives => gettext("Removable Drives"),
            Self::Detections => gettext("Detections"),
            Self::Quarantine => gettext("Quarantine"),
            Self::TrustedDetections => gettext("Trusted Detections"),
            Self::SentSamples => gettext("Sent Samples"),
        }
    }

    pub const fn page_icon(self) -> &'static str {
        match self {
            Self::SignatureSources => "drive-harddisk-symbolic",
            Self::DatabaseUpdates => "software-update-available-symbolic",
            Self::ScanEngine => "system-run-symbolic",
            Self::OnAccessScanning => "folder-visiting-symbolic",
            Self::ScheduledScans => "alarm-symbolic",
            Self::ManualScan => "system-search-symbolic",
            Self::RemovableDrives => "drive-removable-media-symbolic",
            Self::Detections => "dialog-warning-symbolic",
            Self::Quarantine => "folder-symbolic",
            Self::TrustedDetections => "security-medium-symbolic",
            Self::SentSamples => "document-send-symbolic",
        }
    }

    pub fn keyboard_accelerators(self) -> &'static [&'static str] {
        const SIDEBAR_ACCELERATORS: [&str; 10] = [
            "<Control>1",
            "<Control>2",
            "<Control>3",
            "<Control>4",
            "<Control>5",
            "<Control>6",
            "<Control>7",
            "<Control>8",
            "<Control>9",
            "<Control>0",
        ];
        let page_position = ALL_APPLICATION_PAGES
            .iter()
            .position(|application_page| *application_page == self)
            .unwrap_or(SIDEBAR_ACCELERATORS.len());
        SIDEBAR_ACCELERATORS
            .get(page_position..=page_position)
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod application_pages_tests {
    use super::*;

    #[test]
    fn every_page_round_trips_through_its_name() {
        ALL_APPLICATION_PAGES
            .into_iter()
            .for_each(|application_page| {
                assert_eq!(
                    ApplicationPage::from_page_name(application_page.page_name()),
                    Some(application_page)
                );
            });
        assert_eq!(ApplicationPage::from_page_name("preferences"), None);
    }

    #[test]
    fn the_first_ten_entries_get_control_digits_in_sidebar_order() {
        let accelerators = ALL_APPLICATION_PAGES
            .into_iter()
            .map(ApplicationPage::keyboard_accelerators)
            .collect::<Vec<_>>();
        assert_eq!(accelerators[0], ["<Control>1"]);
        assert_eq!(accelerators[8], ["<Control>9"]);
        assert_eq!(accelerators[9], ["<Control>0"]);
        assert!(accelerators[10].is_empty());
        assert_eq!(
            ApplicationPage::Detections.keyboard_accelerators(),
            ["<Control>8"]
        );
    }
}

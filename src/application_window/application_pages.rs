use gettextrs::gettext;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationPage {
    Protection,
    Detections,
    Scan,
    RemovableDrives,
    Logs,
    Quarantine,
    TrustedDetections,
    OnlineLookups,
    Submissions,
    Signatures,
    DatabaseUpdates,
    ScanEngine,
    OnAccessScanning,
    ScheduledScans,
    Hardening,
}

pub const ALL_APPLICATION_PAGES: [ApplicationPage; 15] = [
    ApplicationPage::Protection,
    ApplicationPage::Detections,
    ApplicationPage::Scan,
    ApplicationPage::RemovableDrives,
    ApplicationPage::Logs,
    ApplicationPage::Quarantine,
    ApplicationPage::TrustedDetections,
    ApplicationPage::OnlineLookups,
    ApplicationPage::Submissions,
    ApplicationPage::Signatures,
    ApplicationPage::DatabaseUpdates,
    ApplicationPage::ScanEngine,
    ApplicationPage::OnAccessScanning,
    ApplicationPage::ScheduledScans,
    ApplicationPage::Hardening,
];

impl ApplicationPage {
    pub const fn page_name(self) -> &'static str {
        match self {
            Self::Protection => "protection",
            Self::Detections => "detections",
            Self::Scan => "scan",
            Self::RemovableDrives => "removable-drives",
            Self::Logs => "logs",
            Self::Quarantine => "quarantine",
            Self::TrustedDetections => "trusted-detections",
            Self::OnlineLookups => "online-lookups",
            Self::Submissions => "submissions",
            Self::Signatures => "signatures",
            Self::DatabaseUpdates => "database-updates",
            Self::ScanEngine => "scan-engine",
            Self::OnAccessScanning => "on-access",
            Self::ScheduledScans => "scheduled-scans",
            Self::Hardening => "hardening",
        }
    }

    pub fn from_page_name(page_name: &str) -> Option<Self> {
        ALL_APPLICATION_PAGES
            .into_iter()
            .find(|application_page| application_page.page_name() == page_name)
    }

    pub fn page_title(self) -> String {
        match self {
            Self::Protection => gettext("Protection"),
            Self::Detections => gettext("Detections"),
            Self::Scan => gettext("Scan"),
            Self::RemovableDrives => gettext("Removable Drives"),
            Self::Logs => gettext("Logs"),
            Self::Quarantine => gettext("Quarantine"),
            Self::TrustedDetections => gettext("Trusted Detections"),
            Self::OnlineLookups => gettext("Online Lookups"),
            Self::Submissions => gettext("Submissions"),
            Self::Signatures => gettext("Signatures"),
            Self::DatabaseUpdates => gettext("Database Updates"),
            Self::ScanEngine => gettext("Scan Engine"),
            Self::OnAccessScanning => gettext("On-Access Scanning"),
            Self::ScheduledScans => gettext("Scheduled Scans"),
            Self::Hardening => gettext("Hardening"),
        }
    }

    pub const fn page_icon(self) -> &'static str {
        match self {
            Self::Protection => "security-high-symbolic",
            Self::Detections => "dialog-warning-symbolic",
            Self::Scan => "system-search-symbolic",
            Self::RemovableDrives => "drive-removable-media-symbolic",
            Self::Logs => "document-open-recent-symbolic",
            Self::Quarantine => "folder-symbolic",
            Self::TrustedDetections => "security-medium-symbolic",
            Self::OnlineLookups => "edit-find-symbolic",
            Self::Submissions => "document-send-symbolic",
            Self::Signatures => "drive-harddisk-symbolic",
            Self::DatabaseUpdates => "software-update-available-symbolic",
            Self::ScanEngine => "system-run-symbolic",
            Self::OnAccessScanning => "folder-visiting-symbolic",
            Self::ScheduledScans => "alarm-symbolic",
            Self::Hardening => "channel-secure-symbolic",
        }
    }

    pub const fn keyboard_accelerators(self) -> &'static [&'static str] {
        match self {
            Self::Protection => &["<Control>1"],
            Self::Detections => &["<Control>2"],
            Self::Scan => &["<Control>3"],
            Self::Logs => &["<Control>4"],
            Self::Quarantine => &["<Control>5"],
            Self::Signatures => &["<Control>6"],
            Self::DatabaseUpdates => &["<Control>7"],
            Self::ScanEngine => &["<Control>8"],
            Self::OnAccessScanning => &["<Control>9"],
            Self::ScheduledScans => &["<Control>0"],
            Self::RemovableDrives
            | Self::TrustedDetections
            | Self::OnlineLookups
            | Self::Submissions
            | Self::Hardening => &[],
        }
    }

    pub fn sidebar_position(self) -> i32 {
        ALL_APPLICATION_PAGES
            .into_iter()
            .position(|application_page| application_page == self)
            .and_then(|page_position| i32::try_from(page_position).ok())
            .unwrap_or_default()
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
    fn sidebar_positions_follow_the_page_order() {
        assert_eq!(ApplicationPage::Protection.sidebar_position(), 0);
        assert_eq!(ApplicationPage::Scan.sidebar_position(), 2);
        assert_eq!(ApplicationPage::RemovableDrives.sidebar_position(), 3);
        assert_eq!(ApplicationPage::TrustedDetections.sidebar_position(), 6);
        assert_eq!(ApplicationPage::OnlineLookups.sidebar_position(), 7);
        assert_eq!(ApplicationPage::Submissions.sidebar_position(), 8);
        assert_eq!(ApplicationPage::DatabaseUpdates.sidebar_position(), 10);
        assert_eq!(ApplicationPage::ScanEngine.sidebar_position(), 11);
        assert_eq!(ApplicationPage::OnAccessScanning.sidebar_position(), 12);
        assert_eq!(ApplicationPage::ScheduledScans.sidebar_position(), 13);
        assert_eq!(ApplicationPage::Hardening.sidebar_position(), 14);
    }
}

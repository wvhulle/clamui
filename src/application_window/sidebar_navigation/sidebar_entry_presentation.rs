use gettextrs::gettext;

use crate::application_window::{
    application_pages::ApplicationPage,
    sidebar_area_status::{AreaStatus, AreaSummary, SidebarAreaSummary},
};

pub const SCAN_FILES_ACTION: &str = "win.scan-files";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SidebarGroup {
    SignaturesGroup,
    ScansGroup,
    FindingsGroup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SidebarRowKind {
    ScanFilesAction,
    PageEntry(ApplicationPage),
}

impl SidebarGroup {
    pub fn group_title(self) -> String {
        match self {
            Self::SignaturesGroup => gettext("Signatures"),
            Self::ScansGroup => gettext("Scans"),
            Self::FindingsGroup => gettext("Findings"),
        }
    }

    pub fn group_description(self) -> String {
        match self {
            Self::SignaturesGroup => gettext("Where detections come from"),
            Self::ScansGroup => gettext("How files get checked"),
            Self::FindingsGroup => gettext("What was found"),
        }
    }

    pub fn group_rows(self) -> Vec<SidebarRowKind> {
        match self {
            Self::SignaturesGroup => vec![
                SidebarRowKind::PageEntry(ApplicationPage::SignatureSources),
                SidebarRowKind::PageEntry(ApplicationPage::DatabaseUpdates),
            ],
            Self::ScansGroup => vec![
                SidebarRowKind::ScanFilesAction,
                SidebarRowKind::PageEntry(ApplicationPage::ScanEngine),
                SidebarRowKind::PageEntry(ApplicationPage::OnAccessScanning),
                SidebarRowKind::PageEntry(ApplicationPage::ScheduledScans),
                SidebarRowKind::PageEntry(ApplicationPage::ManualScan),
                SidebarRowKind::PageEntry(ApplicationPage::RemovableDrives),
            ],
            Self::FindingsGroup => vec![
                SidebarRowKind::PageEntry(ApplicationPage::Detections),
                SidebarRowKind::PageEntry(ApplicationPage::Quarantine),
                SidebarRowKind::PageEntry(ApplicationPage::TrustedDetections),
                SidebarRowKind::PageEntry(ApplicationPage::SentSamples),
            ],
        }
    }

    pub fn row_position_of(self, application_page: ApplicationPage) -> Option<i32> {
        self.group_rows()
            .into_iter()
            .position(|row_kind| row_kind == SidebarRowKind::PageEntry(application_page))
            .and_then(|row_position| i32::try_from(row_position).ok())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SidebarStatusImage {
    NoStatusImage,
    WarningImage,
    ErrorImage,
    WaitingImage,
}

impl SidebarStatusImage {
    pub const fn for_area_status(area_status: AreaStatus) -> Self {
        match area_status {
            AreaStatus::AreaHealthy => Self::NoStatusImage,
            AreaStatus::AreaNeedsReview | AreaStatus::AreaUnknown => Self::WarningImage,
            AreaStatus::AreaFailing => Self::ErrorImage,
            AreaStatus::AreaWaiting => Self::WaitingImage,
        }
    }

    pub const fn is_shown(self) -> bool {
        match self {
            Self::NoStatusImage => false,
            Self::WarningImage | Self::ErrorImage | Self::WaitingImage => true,
        }
    }

    pub const fn icon_name(self) -> &'static str {
        match self {
            Self::NoStatusImage | Self::WarningImage => "dialog-warning-symbolic",
            Self::ErrorImage => "dialog-error-symbolic",
            Self::WaitingImage => "content-loading-symbolic",
        }
    }

    pub const fn css_classes(self) -> &'static [&'static str] {
        match self {
            Self::NoStatusImage => &[],
            Self::WarningImage => &["warning"],
            Self::ErrorImage => &["error"],
            Self::WaitingImage => &["dim-label"],
        }
    }

    pub fn tooltip_text(self) -> String {
        match self {
            Self::NoStatusImage => String::new(),
            Self::WarningImage => gettext("Needs review"),
            Self::ErrorImage => gettext("Not working"),
            Self::WaitingImage => gettext("Waiting for another part"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntrySummary {
    SummaryPending,
    SummaryKnown(AreaSummary),
}

impl EntrySummary {
    pub fn for_page(
        application_page: ApplicationPage,
        area_summaries: &[SidebarAreaSummary],
    ) -> Self {
        area_summaries
            .iter()
            .find(|sidebar_summary| sidebar_summary.application_page == application_page)
            .map_or(Self::SummaryPending, |sidebar_summary| {
                Self::SummaryKnown(sidebar_summary.area_summary.clone())
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SidebarRowPresentation {
    pub row_title: String,
    pub row_subtitle: String,
    pub prefix_icon: &'static str,
    pub status_image: SidebarStatusImage,
}

pub fn sidebar_row_presentation(
    row_kind: SidebarRowKind,
    entry_summary: &EntrySummary,
) -> SidebarRowPresentation {
    match (row_kind, entry_summary) {
        (SidebarRowKind::ScanFilesAction, _) => SidebarRowPresentation {
            row_title: gettext("Scan Files…"),
            row_subtitle: gettext("Choose files or folders to check now"),
            prefix_icon: "document-open-symbolic",
            status_image: SidebarStatusImage::NoStatusImage,
        },
        (SidebarRowKind::PageEntry(application_page), EntrySummary::SummaryPending) => {
            SidebarRowPresentation {
                row_title: application_page.page_title(),
                row_subtitle: gettext("Checking…"),
                prefix_icon: application_page.page_icon(),
                status_image: SidebarStatusImage::NoStatusImage,
            }
        }
        (SidebarRowKind::PageEntry(application_page), EntrySummary::SummaryKnown(area_summary)) => {
            SidebarRowPresentation {
                row_title: application_page.page_title(),
                row_subtitle: area_summary.live_state_text.clone(),
                prefix_icon: application_page.page_icon(),
                status_image: SidebarStatusImage::for_area_status(area_summary.area_status),
            }
        }
    }
}

#[cfg(test)]
mod sidebar_entry_presentation_tests {
    use super::*;
    use crate::application_window::application_pages::ALL_APPLICATION_PAGES;

    const ALL_SIDEBAR_GROUPS: [SidebarGroup; 3] = [
        SidebarGroup::SignaturesGroup,
        SidebarGroup::ScansGroup,
        SidebarGroup::FindingsGroup,
    ];

    fn known_summary(area_status: AreaStatus, live_state_text: &str) -> EntrySummary {
        EntrySummary::SummaryKnown(AreaSummary {
            area_status,
            live_state_text: live_state_text.to_owned(),
        })
    }

    #[test]
    fn groups_hold_every_page_once_in_sidebar_order() {
        let grouped_pages = ALL_SIDEBAR_GROUPS
            .into_iter()
            .flat_map(SidebarGroup::group_rows)
            .filter_map(|row_kind| match row_kind {
                SidebarRowKind::PageEntry(application_page) => Some(application_page),
                SidebarRowKind::ScanFilesAction => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(grouped_pages, ALL_APPLICATION_PAGES.to_vec());
    }

    #[test]
    fn each_group_has_its_title_description_and_members() {
        assert_eq!(
            ALL_SIDEBAR_GROUPS.map(|sidebar_group| (
                sidebar_group.group_title(),
                sidebar_group.group_description()
            )),
            [
                (
                    "Signatures".to_owned(),
                    "Where detections come from".to_owned()
                ),
                ("Scans".to_owned(), "How files get checked".to_owned()),
                ("Findings".to_owned(), "What was found".to_owned()),
            ]
        );
        assert_eq!(
            SidebarGroup::ScansGroup.group_rows()[0],
            SidebarRowKind::ScanFilesAction
        );
        assert_eq!(
            SidebarGroup::FindingsGroup.group_rows(),
            vec![
                SidebarRowKind::PageEntry(ApplicationPage::Detections),
                SidebarRowKind::PageEntry(ApplicationPage::Quarantine),
                SidebarRowKind::PageEntry(ApplicationPage::TrustedDetections),
                SidebarRowKind::PageEntry(ApplicationPage::SentSamples),
            ]
        );
    }

    #[test]
    fn a_selected_page_is_found_only_in_its_own_group() {
        assert_eq!(
            SidebarGroup::ScansGroup.row_position_of(ApplicationPage::ScanEngine),
            Some(1)
        );
        assert_eq!(
            SidebarGroup::FindingsGroup.row_position_of(ApplicationPage::SentSamples),
            Some(3)
        );
        assert_eq!(
            SidebarGroup::SignaturesGroup.row_position_of(ApplicationPage::Detections),
            None
        );
    }

    #[test]
    fn each_area_status_has_its_status_image() {
        let presented_image = |area_status| {
            sidebar_row_presentation(
                SidebarRowKind::PageEntry(ApplicationPage::ScanEngine),
                &known_summary(area_status, "clamd answering"),
            )
            .status_image
        };
        assert_eq!(
            presented_image(AreaStatus::AreaHealthy),
            SidebarStatusImage::NoStatusImage
        );
        assert!(!SidebarStatusImage::NoStatusImage.is_shown());
        [AreaStatus::AreaNeedsReview, AreaStatus::AreaUnknown]
            .into_iter()
            .for_each(|area_status| {
                let status_image = presented_image(area_status);
                assert_eq!(status_image, SidebarStatusImage::WarningImage);
                assert_eq!(status_image.icon_name(), "dialog-warning-symbolic");
                assert_eq!(status_image.css_classes(), ["warning"]);
            });
        let error_image = presented_image(AreaStatus::AreaFailing);
        assert_eq!(error_image.icon_name(), "dialog-error-symbolic");
        assert_eq!(error_image.css_classes(), ["error"]);
        let waiting_image = presented_image(AreaStatus::AreaWaiting);
        assert_eq!(waiting_image, SidebarStatusImage::WaitingImage);
        assert!(waiting_image.is_shown());
        assert_eq!(waiting_image.css_classes(), ["dim-label"]);
    }

    #[test]
    fn a_page_row_shows_its_title_icon_and_live_state() {
        assert_eq!(
            sidebar_row_presentation(
                SidebarRowKind::PageEntry(ApplicationPage::Detections),
                &known_summary(AreaStatus::AreaNeedsReview, "2 need a decision"),
            ),
            SidebarRowPresentation {
                row_title: "Detections".to_owned(),
                row_subtitle: "2 need a decision".to_owned(),
                prefix_icon: ApplicationPage::Detections.page_icon(),
                status_image: SidebarStatusImage::WarningImage,
            }
        );
        let pending_row = sidebar_row_presentation(
            SidebarRowKind::PageEntry(ApplicationPage::Quarantine),
            &EntrySummary::SummaryPending,
        );
        assert_eq!(pending_row.row_subtitle, "Checking…");
        assert_eq!(pending_row.status_image, SidebarStatusImage::NoStatusImage);
        assert_eq!(
            sidebar_row_presentation(
                SidebarRowKind::ScanFilesAction,
                &EntrySummary::SummaryPending
            )
            .row_title,
            "Scan Files…"
        );
    }

    #[test]
    fn entry_summaries_come_from_the_shell_summaries() {
        let area_summaries = vec![SidebarAreaSummary {
            application_page: ApplicationPage::Quarantine,
            area_summary: AreaSummary {
                area_status: AreaStatus::AreaHealthy,
                live_state_text: "1 item".to_owned(),
            },
        }];
        assert_eq!(
            EntrySummary::for_page(ApplicationPage::Quarantine, &area_summaries),
            known_summary(AreaStatus::AreaHealthy, "1 item")
        );
        assert_eq!(
            EntrySummary::for_page(ApplicationPage::Detections, &area_summaries),
            EntrySummary::SummaryPending
        );
    }
}

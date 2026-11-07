use std::time::Duration;

use gettextrs::{gettext, ngettext};
use relm4::gtk;

use crate::host_services::clamav_scanner::{
    scan_progress_estimates::{file_progress_text, remaining_time_text},
    scan_target_enumeration::EnumerationProgress,
    scanner_output_parser::sanitize_scanner_line,
};

#[derive(Clone, Debug, PartialEq)]
pub enum ScanProgressView {
    PreparingScan,
    FindingFiles {
        found_file_count: u64,
        current_directory: String,
    },
    ScanningFiles {
        inspected_file_count: u64,
        planned_file_count: u64,
        elapsed_time: Duration,
        current_file_text: String,
    },
}

impl ScanProgressView {
    pub fn finding_files(enumeration_progress: &EnumerationProgress) -> Self {
        Self::FindingFiles {
            found_file_count: enumeration_progress.found_file_count,
            current_directory: sanitize_scanner_line(
                &enumeration_progress.current_directory.to_string_lossy(),
            ),
        }
    }

    pub fn progress_text(&self) -> String {
        match self {
            Self::PreparingScan => gettext("Preparing…"),
            Self::FindingFiles {
                found_file_count, ..
            } => ngettext(
                "Finding files… {count} found",
                "Finding files… {count} found",
                u32::try_from(*found_file_count).unwrap_or(u32::MAX),
            )
            .replace("{count}", &found_file_count.to_string()),
            Self::ScanningFiles {
                inspected_file_count,
                planned_file_count,
                ..
            } => file_progress_text(*inspected_file_count, *planned_file_count),
        }
    }

    pub fn detail_text(&self) -> String {
        match self {
            Self::PreparingScan => String::new(),
            Self::FindingFiles {
                current_directory, ..
            } => current_directory.clone(),
            Self::ScanningFiles {
                inspected_file_count,
                planned_file_count,
                elapsed_time,
                current_file_text,
            } => [current_file_text.clone()]
                .into_iter()
                .chain(remaining_time_text(
                    *elapsed_time,
                    *inspected_file_count,
                    *planned_file_count,
                ))
                .filter(|detail_part| !detail_part.is_empty())
                .collect::<Vec<_>>()
                .join(" · "),
        }
    }

    pub fn completed_fraction(&self) -> f64 {
        match self {
            Self::PreparingScan | Self::FindingFiles { .. } => 0.0,
            Self::ScanningFiles {
                planned_file_count: 0,
                ..
            } => 0.0,
            Self::ScanningFiles {
                inspected_file_count,
                planned_file_count,
                ..
            } => (*inspected_file_count as f64 / *planned_file_count as f64).clamp(0.0, 1.0),
        }
    }
}

pub trait ScanProgressBar {
    fn show_scan_progress(&self, scan_progress_view: &ScanProgressView);
}

impl ScanProgressBar for gtk::ProgressBar {
    fn show_scan_progress(&self, scan_progress_view: &ScanProgressView) {
        match scan_progress_view {
            ScanProgressView::FindingFiles { .. } => self.pulse(),
            ScanProgressView::PreparingScan | ScanProgressView::ScanningFiles { .. } => {
                self.set_fraction(scan_progress_view.completed_fraction());
            }
        }
        self.set_text(Some(&scan_progress_view.progress_text()));
    }
}

#[cfg(test)]
mod scan_progress_view_tests {
    use super::*;

    #[test]
    fn the_fraction_stays_between_zero_and_one() {
        let scanning_view =
            |inspected_file_count, planned_file_count| ScanProgressView::ScanningFiles {
                inspected_file_count,
                planned_file_count,
                elapsed_time: Duration::from_secs(1),
                current_file_text: String::new(),
            };
        assert!((scanning_view(5, 10).completed_fraction() - 0.5).abs() < f64::EPSILON);
        assert!((scanning_view(12, 10).completed_fraction() - 1.0).abs() < f64::EPSILON);
        assert!(scanning_view(3, 0).completed_fraction().abs() < f64::EPSILON);
    }

    #[test]
    fn preparation_shows_no_detail() {
        assert!(ScanProgressView::PreparingScan.detail_text().is_empty());
    }
}

use crate::{
    host_services::activity_history::activity_history_database::{
        ActivityEntryRecord, ActivityHistoryFailure, ActivityRecord, ScanOrigin,
    },
    shared_widgets::loading_indicators::{
        LOAD_FAILED_PAGE_NAME, LOADED_PAGE_NAME, LOADING_PAGE_NAME,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityHistoryFilter {
    ManualScans,
    ScheduledScans,
    DeviceScans,
}

impl ActivityHistoryFilter {
    const fn listed_scan_origin(self) -> ScanOrigin {
        match self {
            Self::ManualScans => ScanOrigin::ManualScan,
            Self::ScheduledScans => ScanOrigin::ScheduledScan,
            Self::DeviceScans => ScanOrigin::DeviceScan,
        }
    }

    const fn lists_skipped_runs(self) -> bool {
        match self {
            Self::ScheduledScans => true,
            Self::ManualScans | Self::DeviceScans => false,
        }
    }

    pub fn keeps_record(self, activity_record: &ActivityRecord) -> bool {
        match activity_record {
            ActivityRecord::ScanActivity { scan_origin, .. } => {
                *scan_origin == self.listed_scan_origin()
            }
            ActivityRecord::SkippedScan { .. } => self.lists_skipped_runs(),
            ActivityRecord::UpdateActivity { .. } => false,
        }
    }
}

pub fn filtered_history_entries(
    activity_entries: Vec<ActivityEntryRecord>,
    history_filter: ActivityHistoryFilter,
) -> Vec<ActivityEntryRecord> {
    let mut kept_entries = activity_entries
        .into_iter()
        .filter(|activity_entry| history_filter.keeps_record(&activity_entry.activity_record))
        .collect::<Vec<_>>();
    kept_entries.sort_by(|earlier_entry, later_entry| {
        (later_entry.started_at, later_entry.entry_id)
            .cmp(&(earlier_entry.started_at, earlier_entry.entry_id))
    });
    kept_entries
}

#[derive(Debug)]
pub enum FilteredHistoryView {
    HistoryLoading,
    HistoryLoaded(Vec<ActivityEntryRecord>),
    HistoryLoadFailed(ActivityHistoryFailure),
}

impl FilteredHistoryView {
    pub fn from_load_outcome(
        load_outcome: Result<Vec<ActivityEntryRecord>, ActivityHistoryFailure>,
        history_filter: ActivityHistoryFilter,
    ) -> Self {
        match load_outcome {
            Ok(activity_entries) => {
                Self::HistoryLoaded(filtered_history_entries(activity_entries, history_filter))
            }
            Err(load_failure) => Self::HistoryLoadFailed(load_failure),
        }
    }

    pub fn listed_entries(&self) -> &[ActivityEntryRecord] {
        match self {
            Self::HistoryLoaded(listed_entries) => listed_entries,
            Self::HistoryLoading | Self::HistoryLoadFailed(_) => &[],
        }
    }

    pub const fn placeholder_page_name(&self) -> &'static str {
        match self {
            Self::HistoryLoading => LOADING_PAGE_NAME,
            Self::HistoryLoaded(_) => LOADED_PAGE_NAME,
            Self::HistoryLoadFailed(_) => LOAD_FAILED_PAGE_NAME,
        }
    }
}

#[cfg(test)]
mod activity_history_filter_tests {
    use std::path::PathBuf;

    use jiff::Timestamp;

    use super::*;
    use crate::host_services::activity_history::activity_history_database::{
        ScanActivityStatus, UpdateActivityStatus,
    };

    fn history_entry(
        entry_id: i64,
        started_seconds: i64,
        activity_record: ActivityRecord,
    ) -> ActivityEntryRecord {
        ActivityEntryRecord {
            entry_id,
            started_at: Timestamp::constant(started_seconds, 0),
            activity_record,
            duration_millis: 1000,
            activity_output: String::new(),
        }
    }

    fn scan_with(scan_origin: ScanOrigin) -> ActivityRecord {
        ActivityRecord::ScanActivity {
            scan_targets: vec![PathBuf::from("/tmp")],
            inspected_file_count: 3,
            scan_status: ScanActivityStatus::ScanClean,
            scan_origin,
        }
    }

    fn mixed_history() -> Vec<ActivityEntryRecord> {
        vec![
            history_entry(1, 100, scan_with(ScanOrigin::ManualScan)),
            history_entry(2, 400, scan_with(ScanOrigin::ScheduledScan)),
            history_entry(
                3,
                300,
                ActivityRecord::SkippedScan {
                    scan_targets: vec![PathBuf::from("/home")],
                },
            ),
            history_entry(
                4,
                500,
                ActivityRecord::UpdateActivity {
                    update_status: UpdateActivityStatus::UpdateApplied,
                },
            ),
            history_entry(5, 200, scan_with(ScanOrigin::ManualScan)),
            history_entry(6, 600, scan_with(ScanOrigin::DeviceScan)),
            history_entry(7, 50, scan_with(ScanOrigin::DeviceScan)),
        ]
    }

    fn listed_ids(history_filter: ActivityHistoryFilter) -> Vec<i64> {
        filtered_history_entries(mixed_history(), history_filter)
            .iter()
            .map(|activity_entry| activity_entry.entry_id)
            .collect()
    }

    #[test]
    fn manual_history_lists_only_manual_scans_newest_first() {
        assert_eq!(listed_ids(ActivityHistoryFilter::ManualScans), vec![5, 1]);
    }

    #[test]
    fn scheduled_history_lists_scheduled_and_skipped_runs_newest_first() {
        assert_eq!(
            listed_ids(ActivityHistoryFilter::ScheduledScans),
            vec![2, 3]
        );
    }

    #[test]
    fn device_history_lists_only_device_scans_newest_first() {
        assert_eq!(listed_ids(ActivityHistoryFilter::DeviceScans), vec![6, 7]);
    }

    #[test]
    fn a_failed_load_lists_nothing_and_shows_the_failure() {
        let history_view = FilteredHistoryView::from_load_outcome(
            Err(ActivityHistoryFailure::DatabasePathNotUtf8),
            ActivityHistoryFilter::ManualScans,
        );
        assert!(history_view.listed_entries().is_empty());
        assert_eq!(history_view.placeholder_page_name(), LOAD_FAILED_PAGE_NAME);
        assert_eq!(
            FilteredHistoryView::HistoryLoading.placeholder_page_name(),
            LOADING_PAGE_NAME
        );
    }
}

use crate::activity_history::activity_history_database::ActivityEntryRecord;

const SECONDS_PER_HOUR: i64 = 3600;
const SECONDS_PER_DAY: i64 = 24 * SECONDS_PER_HOUR;
const ALL_TIME_BUCKET_COUNT: i64 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatisticsTimeframe {
    LastDay,
    LastWeek,
    LastMonth,
    AllTime,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScanActivityBucket {
    pub bucket_start_unix: i64,
    pub bucket_end_unix: i64,
    pub scan_count: u64,
    pub threat_count: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanActivityStatistics {
    pub total_scans: u64,
    pub files_scanned: u64,
    pub threats_detected: u64,
    pub clean_scans: u64,
    pub average_duration_millis: u64,
    pub period_start_unix: i64,
    pub activity_buckets: Vec<ScanActivityBucket>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionLevel {
    Protected,
    AtRisk,
    Unprotected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionReason {
    NoCompletedScans,
    LastScanOverMonthOld,
    LastScanOverWeekOld,
    DefinitionsOverWeekOld,
    DefinitionsOverDayOld,
    EverythingCurrent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefinitionFreshness {
    FreshnessUnknown,
    DefinitionsAged { age_days: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionAssessment {
    pub protection_level: ProtectionLevel,
    pub protection_reason: ProtectionReason,
}

struct BucketLayout {
    first_bucket_start: i64,
    bucket_seconds: i64,
    bucket_count: i64,
}

fn bucket_layout(
    timeframe: StatisticsTimeframe,
    earliest_scan_unix: i64,
    current_unix: i64,
) -> BucketLayout {
    let rolling_layout = |bucket_seconds: i64, bucket_count: i64| BucketLayout {
        first_bucket_start: current_unix - bucket_seconds * bucket_count,
        bucket_seconds,
        bucket_count,
    };
    match timeframe {
        StatisticsTimeframe::LastDay => rolling_layout(4 * SECONDS_PER_HOUR, 6),
        StatisticsTimeframe::LastWeek => rolling_layout(SECONDS_PER_DAY, 7),
        StatisticsTimeframe::LastMonth => rolling_layout(3 * SECONDS_PER_DAY, 10),
        StatisticsTimeframe::AllTime => {
            let covered_seconds = (current_unix - earliest_scan_unix + 1).max(SECONDS_PER_DAY);
            let bucket_seconds =
                (covered_seconds + ALL_TIME_BUCKET_COUNT - 1) / ALL_TIME_BUCKET_COUNT;
            BucketLayout {
                first_bucket_start: current_unix - bucket_seconds * ALL_TIME_BUCKET_COUNT,
                bucket_seconds,
                bucket_count: ALL_TIME_BUCKET_COUNT,
            }
        }
    }
}

pub fn summarize_scan_activity(
    activity_entries: &[ActivityEntryRecord],
    timeframe: StatisticsTimeframe,
    current_unix: i64,
) -> ScanActivityStatistics {
    let scan_entries = activity_entries
        .iter()
        .filter(|activity_entry| activity_entry.activity_status.is_virus_scan());
    let earliest_scan_unix = scan_entries
        .clone()
        .map(|scan_entry| scan_entry.started_at_unix)
        .min()
        .unwrap_or(current_unix);
    let layout = bucket_layout(timeframe, earliest_scan_unix, current_unix);
    let empty_statistics = ScanActivityStatistics {
        period_start_unix: layout.first_bucket_start,
        activity_buckets: (0..layout.bucket_count)
            .map(|bucket_position| ScanActivityBucket {
                bucket_start_unix: layout.first_bucket_start
                    + bucket_position * layout.bucket_seconds,
                bucket_end_unix: layout.first_bucket_start
                    + (bucket_position + 1) * layout.bucket_seconds,
                scan_count: 0,
                threat_count: 0,
            })
            .collect(),
        ..ScanActivityStatistics::default()
    };
    let mut total_duration_millis = 0_u64;
    let mut summarized_statistics = scan_entries
        .filter(|scan_entry| {
            (layout.first_bucket_start..=current_unix).contains(&scan_entry.started_at_unix)
        })
        .fold(empty_statistics, |mut statistics, scan_entry| {
            statistics.total_scans += 1;
            statistics.files_scanned += scan_entry.inspected_file_count;
            statistics.threats_detected += scan_entry.threat_count;
            statistics.clean_scans += u64::from(
                scan_entry.threat_count == 0 && scan_entry.activity_status.is_completed_scan(),
            );
            total_duration_millis += scan_entry.duration_millis;
            let bucket_position = ((scan_entry.started_at_unix - layout.first_bucket_start)
                / layout.bucket_seconds)
                .min(layout.bucket_count - 1) as usize;
            statistics.activity_buckets[bucket_position].scan_count += 1;
            statistics.activity_buckets[bucket_position].threat_count += scan_entry.threat_count;
            statistics
        });
    summarized_statistics.average_duration_millis = total_duration_millis
        .checked_div(summarized_statistics.total_scans)
        .unwrap_or(0);
    summarized_statistics
}

pub fn newest_completed_scan(
    activity_entries: &[ActivityEntryRecord],
) -> Option<&ActivityEntryRecord> {
    activity_entries
        .iter()
        .filter(|activity_entry| activity_entry.activity_status.is_completed_scan())
        .max_by_key(|activity_entry| activity_entry.started_at_unix)
}

fn definition_reason(definition_freshness: DefinitionFreshness) -> ProtectionAssessment {
    let at_risk_because = |protection_reason| ProtectionAssessment {
        protection_level: ProtectionLevel::AtRisk,
        protection_reason,
    };
    match definition_freshness {
        DefinitionFreshness::DefinitionsAged { age_days } if age_days > 7 => {
            at_risk_because(ProtectionReason::DefinitionsOverWeekOld)
        }
        DefinitionFreshness::DefinitionsAged { age_days } if age_days > 1 => {
            at_risk_because(ProtectionReason::DefinitionsOverDayOld)
        }
        DefinitionFreshness::DefinitionsAged { .. } | DefinitionFreshness::FreshnessUnknown => {
            ProtectionAssessment {
                protection_level: ProtectionLevel::Protected,
                protection_reason: ProtectionReason::EverythingCurrent,
            }
        }
    }
}

pub fn assess_protection(
    activity_entries: &[ActivityEntryRecord],
    definition_freshness: DefinitionFreshness,
    current_unix: i64,
) -> ProtectionAssessment {
    let Some(newest_scan) = newest_completed_scan(activity_entries) else {
        return ProtectionAssessment {
            protection_level: ProtectionLevel::Unprotected,
            protection_reason: ProtectionReason::NoCompletedScans,
        };
    };
    let scan_age_seconds = current_unix - newest_scan.started_at_unix;
    if scan_age_seconds > 30 * SECONDS_PER_DAY {
        ProtectionAssessment {
            protection_level: ProtectionLevel::Unprotected,
            protection_reason: ProtectionReason::LastScanOverMonthOld,
        }
    } else if scan_age_seconds > 7 * SECONDS_PER_DAY {
        ProtectionAssessment {
            protection_level: ProtectionLevel::AtRisk,
            protection_reason: ProtectionReason::LastScanOverWeekOld,
        }
    } else {
        definition_reason(definition_freshness)
    }
}

#[cfg(test)]
mod scan_activity_statistics_tests {
    use super::*;
    use crate::activity_history::activity_history_database::ActivityStatus;

    const CURRENT_UNIX: i64 = 1_000_000_000;

    fn activity_entry(
        activity_status: ActivityStatus,
        seconds_ago: i64,
        threat_count: u64,
    ) -> ActivityEntryRecord {
        ActivityEntryRecord {
            entry_id: seconds_ago,
            started_at_unix: CURRENT_UNIX - seconds_ago,
            activity_status,
            activity_targets: String::new(),
            inspected_file_count: 10,
            threat_count,
            duration_millis: 2000,
            activity_output: String::new(),
        }
    }

    #[test]
    fn totals_only_cover_scans_inside_the_timeframe() {
        let activity_entries = [
            activity_entry(ActivityStatus::ScanClean, 60, 0),
            activity_entry(ActivityStatus::ScanInfected, 3 * SECONDS_PER_HOUR, 2),
            activity_entry(ActivityStatus::UpdateApplied, 60, 0),
            activity_entry(ActivityStatus::ScanClean, 3 * SECONDS_PER_DAY, 0),
        ];
        let statistics = summarize_scan_activity(
            &activity_entries,
            StatisticsTimeframe::LastDay,
            CURRENT_UNIX,
        );
        assert_eq!(statistics.total_scans, 2);
        assert_eq!(statistics.files_scanned, 20);
        assert_eq!(statistics.threats_detected, 2);
        assert_eq!(statistics.clean_scans, 1);
        assert_eq!(statistics.average_duration_millis, 2000);
    }

    #[test]
    fn buckets_place_scans_by_age_and_cover_the_timeframe() {
        let activity_entries = [
            activity_entry(ActivityStatus::ScanClean, 60, 0),
            activity_entry(ActivityStatus::ScanInfected, SECONDS_PER_DAY + 60, 3),
        ];
        let statistics = summarize_scan_activity(
            &activity_entries,
            StatisticsTimeframe::LastWeek,
            CURRENT_UNIX,
        );
        assert_eq!(statistics.activity_buckets.len(), 7);
        assert_eq!(statistics.activity_buckets[6].scan_count, 1);
        assert_eq!(statistics.activity_buckets[5].scan_count, 1);
        assert_eq!(statistics.activity_buckets[5].threat_count, 3);
        assert_eq!(statistics.activity_buckets[6].bucket_end_unix, CURRENT_UNIX);
    }

    #[test]
    fn all_time_includes_the_earliest_scan() {
        let activity_entries = [activity_entry(
            ActivityStatus::ScanClean,
            400 * SECONDS_PER_DAY,
            0,
        )];
        let statistics = summarize_scan_activity(
            &activity_entries,
            StatisticsTimeframe::AllTime,
            CURRENT_UNIX,
        );
        assert_eq!(statistics.total_scans, 1);
        assert_eq!(statistics.activity_buckets.len(), 12);
    }

    #[test]
    fn an_empty_history_has_no_division_by_zero() {
        let statistics = summarize_scan_activity(&[], StatisticsTimeframe::AllTime, CURRENT_UNIX);
        assert_eq!(statistics.average_duration_millis, 0);
        assert_eq!(statistics.total_scans, 0);
    }

    #[test]
    fn protection_follows_scan_age_before_definition_age() {
        let assess = |activity_entries: &[ActivityEntryRecord], age_days| {
            assess_protection(
                activity_entries,
                DefinitionFreshness::DefinitionsAged { age_days },
                CURRENT_UNIX,
            )
            .protection_reason
        };
        assert_eq!(assess(&[], 0), ProtectionReason::NoCompletedScans);
        assert_eq!(
            assess(
                &[activity_entry(
                    ActivityStatus::ScanClean,
                    31 * SECONDS_PER_DAY,
                    0
                )],
                0
            ),
            ProtectionReason::LastScanOverMonthOld
        );
        assert_eq!(
            assess(
                &[activity_entry(
                    ActivityStatus::ScanClean,
                    8 * SECONDS_PER_DAY,
                    0
                )],
                9
            ),
            ProtectionReason::LastScanOverWeekOld
        );
        assert_eq!(
            assess(&[activity_entry(ActivityStatus::ScanClean, 60, 0)], 9),
            ProtectionReason::DefinitionsOverWeekOld
        );
        assert_eq!(
            assess(&[activity_entry(ActivityStatus::ScanClean, 60, 0)], 2),
            ProtectionReason::DefinitionsOverDayOld
        );
        assert_eq!(
            assess(&[activity_entry(ActivityStatus::ScanClean, 60, 0)], 0),
            ProtectionReason::EverythingCurrent
        );
    }

    #[test]
    fn failed_and_cancelled_scans_do_not_count_as_protection() {
        let activity_entries = [
            activity_entry(ActivityStatus::ScanFailed, 60, 0),
            activity_entry(ActivityStatus::ScanCancelled, 60, 0),
        ];
        assert_eq!(
            assess_protection(
                &activity_entries,
                DefinitionFreshness::FreshnessUnknown,
                CURRENT_UNIX
            )
            .protection_level,
            ProtectionLevel::Unprotected
        );
    }
}

use bytesize::ByteSize;
use jiff::{SignedDuration, Timestamp};

use crate::{
    host_services::{
        desktop::locale_formatting::MomentFormatters,
        protection_evidence::{
            clamav_engine_evidence::DatabaseEvidence,
            host_protection_evidence::{
                DaemonEvidence, EngineInstallation, LoadedSignatures, OnAccessConfig,
                OnAccessEvidence, OnAccessResponse, OnAccessScanner, OnAccessSizeLimit,
                ProgramTrustInspection, ProtectionEvidence, RuntimeReductions, ScanServiceEvidence,
                ScanUnitResult, ScheduledScanEvidence, SignatureEvidence,
                ThirdPartySignatureListing, TimerState, WatchScope, WatchedLocation,
            },
            service_run_journal::ScanRunHistory,
        },
        systemd_bus::host_systemd_units::{UnitActivity, UnitState, UnitTimestamp},
    },
    sharing::analysis_page::trusted_detections_page::trust_list_contents::{
        LazaretListReading, TrustListContents, TrustListReading,
    },
};

pub const REFERENCE_MOMENT: Timestamp = Timestamp::constant(1_794_200_000, 0);

pub fn english_formatters() -> &'static MomentFormatters {
    static ENGLISH_FORMATTERS: std::sync::OnceLock<MomentFormatters> = std::sync::OnceLock::new();
    ENGLISH_FORMATTERS.get_or_init(|| {
        MomentFormatters::try_for_locales(&icu::locale::locale!("en"), &icu::locale::locale!("en"))
            .unwrap()
    })
}

pub fn healthy_evidence() -> ProtectionEvidence {
    ProtectionEvidence {
        program_trust: ProgramTrustInspection::ProgramsChecked(Vec::new()),
        trust_list: TrustListReading::ListsRead(empty_trust_list()),
        runtime_reductions: RuntimeReductions::NothingReduced,
        account_setting_findings: Vec::new(),
        engine_installation: EngineInstallation::VersionReported {
            version_banner: "ClamAV 1.5.4/28174".to_owned(),
        },
        signature_evidence: SignatureEvidence {
            database_evidence: DatabaseEvidence::BuiltAt {
                built_at: REFERENCE_MOMENT - SignedDuration::from_hours(5),
            },
            updater_evidence: Vec::new(),
            third_party_listing: ThirdPartySignatureListing::FilesListed(Vec::new()),
        },
        daemon_evidence: DaemonEvidence::ClamdAnswering {
            loaded_signatures: LoadedSignatures::MatchesDisk,
        },
        on_access_evidence: OnAccessEvidence {
            on_access_scanner: OnAccessScanner::MonitorRunning,
            on_access_config: OnAccessConfig::ConfigRead {
                watch_scope: WatchScope::WatchedLocations {
                    first_location: WatchedLocation::WatchedFolder {
                        folder_path: "/home/user/Downloads".to_owned(),
                    },
                    other_locations: Vec::new(),
                },
                blocking_response: OnAccessResponse::BlockAccess,
                size_limit: OnAccessSizeLimit::ConfiguredLimit {
                    size_limit: ByteSize::mib(100),
                },
            },
        },
        scheduled_scan_evidence: ScheduledScanEvidence::SystemTimer {
            service_unit: "clamdscan.service",
            timer_state: TimerState::TimerActive {
                next_run: UnitTimestamp::RecordedAt {
                    recorded_at: REFERENCE_MOMENT + SignedDuration::from_hours(6),
                },
            },
            scan_service: ScanServiceEvidence::ServiceConfigured {
                scan_targets: vec!["/tmp".to_owned(), "/var/tmp".to_owned()],
                last_result: ScanUnitResult::NothingFound,
            },
            last_completed_run: ScanRunHistory::NoCompletedScan,
        },
        background_service_state: UnitState::UnitLoaded(UnitActivity::UnitActive),
    }
}

pub fn empty_trust_list() -> TrustListContents {
    TrustListContents {
        trusted_files: LazaretListReading::ListRead(Vec::new()),
        ignored_signatures: LazaretListReading::ListRead(Vec::new()),
        foreign_allowlists: Vec::new(),
    }
}

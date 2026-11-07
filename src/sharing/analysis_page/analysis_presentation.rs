use gettextrs::{gettext, ngettext};

use crate::{
    host_services::threat_intel::service_key_storage::{
        KeyStorageFailure, ResolvedApiKey, describe_key_failure,
    },
    shared_widgets::step_timeline::{
        step_evidence_builders::{CheckedCondition, evidence_row, plain_rows},
        timeline_step_contents::{
            ActionConsequence, SettledNodeState, SettledStep, StepActionButton, StepActionSlot,
            StepEvidenceRow, TimelineStep,
        },
    },
    sharing::analysis_page::trusted_detections_section::{
        trust_list_contents::{
            AllowlistEntries, ForeignAllowlistFile, LazaretListReading, TrustListContents,
            TrustListReading,
        },
        trusted_detections_group::trust_list_failure_text,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisStepAction {}

impl StepActionButton for AnalysisStepAction {
    fn button_label(&self) -> String {
        match *self {}
    }

    fn action_consequence(&self) -> ActionConsequence {
        match *self {}
    }
}

pub type AnalysisStep = TimelineStep<AnalysisStepAction>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookupService {
    CirclHashlookup,
    MalwareBazaar,
    VirusTotal,
}

impl LookupService {
    pub const fn service_name(self) -> &'static str {
        match self {
            Self::CirclHashlookup => "CIRCL hashlookup",
            Self::MalwareBazaar => "MalwareBazaar",
            Self::VirusTotal => "VirusTotal",
        }
    }

    pub fn received_data_text(self) -> String {
        match self {
            Self::CirclHashlookup => gettext("Receives the file's SHA-256 hash"),
            Self::MalwareBazaar => {
                gettext("Receives the detection's signature name or the file's SHA-256 hash")
            }
            Self::VirusTotal => gettext("Receives the file's SHA-256 hash"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceKeyStatus {
    KeyChecking,
    KeyConfigured,
    KeyMissing,
    KeyUnreadable { failure_text: String },
}

impl ServiceKeyStatus {
    pub fn from_key_reading(key_reading: &Result<ResolvedApiKey, KeyStorageFailure>) -> Self {
        match key_reading {
            Ok(ResolvedApiKey::FromKeyFile(_) | ResolvedApiKey::FromKeyring(_)) => {
                Self::KeyConfigured
            }
            Ok(ResolvedApiKey::NotConfigured) => Self::KeyMissing,
            Err(key_failure) => Self::KeyUnreadable {
                failure_text: describe_key_failure(key_failure),
            },
        }
    }

    pub fn status_text(&self) -> String {
        match self {
            Self::KeyChecking => gettext("Checking the API key…"),
            Self::KeyConfigured => gettext("API key configured"),
            Self::KeyMissing => gettext("No API key, so lookups with this service are off"),
            Self::KeyUnreadable { failure_text } => {
                gettext("The API key can't be read: {reason}").replace("{reason}", failure_text)
            }
        }
    }

    pub const fn needs_attention(&self) -> bool {
        match self {
            Self::KeyChecking | Self::KeyConfigured | Self::KeyMissing => false,
            Self::KeyUnreadable { .. } => true,
        }
    }
}

pub fn keyed_service_subtitle(
    lookup_service: LookupService,
    key_status: &ServiceKeyStatus,
) -> String {
    format!(
        "{}\n{}",
        lookup_service.received_data_text(),
        key_status.status_text()
    )
}

pub fn keyless_service_subtitle(lookup_service: LookupService) -> String {
    format!(
        "{}\n{}",
        lookup_service.received_data_text(),
        gettext("No API key needed")
    )
}

struct TrustListVerdict {
    checked_condition: CheckedCondition,
    status_text: String,
    evidence_rows: Vec<StepEvidenceRow>,
}

fn lazaret_list_failure_row<ListEntry>(
    list_label: String,
    list_reading: &LazaretListReading<ListEntry>,
) -> Option<StepEvidenceRow> {
    match list_reading {
        LazaretListReading::ListRead(_) => None,
        LazaretListReading::ListUnreadable(read_failure) => Some(evidence_row(
            list_label,
            trust_list_failure_text(read_failure),
        )),
    }
}

fn foreign_allowlist_evidence_row(foreign_allowlist: &ForeignAllowlistFile) -> StepEvidenceRow {
    match &foreign_allowlist.allowlist_entries {
        AllowlistEntries::EntriesCounted { .. } => evidence_row(
            gettext("Other allowlist"),
            foreign_allowlist.file_name.clone(),
        ),
        AllowlistEntries::FileUnreadable(read_failure) => evidence_row(
            gettext("Other allowlist"),
            gettext("{file}: {reason}")
                .replace("{file}", &foreign_allowlist.file_name)
                .replace("{reason}", &trust_list_failure_text(read_failure)),
        ),
    }
}

fn trust_list_contents_verdict(trust_list: &TrustListContents) -> Option<TrustListVerdict> {
    let evidence_rows = [
        lazaret_list_failure_row(gettext("Trusted files"), &trust_list.trusted_files),
        lazaret_list_failure_row(
            gettext("Ignored detections"),
            &trust_list.ignored_signatures,
        ),
    ]
    .into_iter()
    .flatten()
    .chain(
        trust_list
            .foreign_allowlists
            .iter()
            .map(foreign_allowlist_evidence_row),
    )
    .collect();
    if !trust_list.foreign_allowlists.is_empty() {
        return Some(TrustListVerdict {
            checked_condition: CheckedCondition::ReviewSuggested,
            status_text: gettext(
                "An allowlist that Lazaret didn't write tells ClamAV to stay silent",
            ),
            evidence_rows,
        });
    }
    match (&trust_list.trusted_files, &trust_list.ignored_signatures) {
        (
            LazaretListReading::ListRead(trusted_files),
            LazaretListReading::ListRead(ignored_signatures),
        ) => {
            let lazaret_entries = trusted_files.len() + ignored_signatures.len();
            (lazaret_entries > 0).then(|| TrustListVerdict {
                checked_condition: CheckedCondition::ConditionMet,
                status_text: ngettext(
                    "{count} file or detection is never reported",
                    "{count} files or detections are never reported",
                    u32::try_from(lazaret_entries).unwrap_or(u32::MAX),
                )
                .replace("{count}", &lazaret_entries.to_string()),
                evidence_rows,
            })
        }
        (LazaretListReading::ListUnreadable(_), _)
        | (LazaretListReading::ListRead(_), LazaretListReading::ListUnreadable(_)) => {
            Some(TrustListVerdict {
                checked_condition: CheckedCondition::EvidenceUnknown,
                status_text: gettext(
                    "Lazaret can't read its own allowlist, so it can't tell what ClamAV stays \
                     silent about",
                ),
                evidence_rows,
            })
        }
    }
}

fn trust_list_verdict(trust_list_reading: &TrustListReading) -> Option<TrustListVerdict> {
    match trust_list_reading {
        TrustListReading::ListsRead(trust_list) => trust_list_contents_verdict(trust_list),
        TrustListReading::FolderMissing => None,
        TrustListReading::FolderUnreadable(read_failure) => Some(TrustListVerdict {
            checked_condition: CheckedCondition::EvidenceUnknown,
            status_text: gettext(
                "Lazaret can't read the signature folder, so it can't tell what ClamAV stays \
                 silent about",
            ),
            evidence_rows: vec![evidence_row(
                gettext("Signature folder"),
                trust_list_failure_text(read_failure),
            )],
        }),
    }
}

pub fn trust_list_condition(trust_list_reading: &TrustListReading) -> CheckedCondition {
    trust_list_verdict(trust_list_reading)
        .map_or(CheckedCondition::ConditionMet, |trust_list_verdict| {
            trust_list_verdict.checked_condition
        })
}

pub fn trust_list_step<StepAction: StepActionButton>(
    trust_list_reading: &TrustListReading,
    header_action: impl FnOnce(CheckedCondition) -> StepActionSlot<StepAction>,
) -> Option<TimelineStep<StepAction>> {
    let TrustListVerdict {
        checked_condition,
        status_text,
        evidence_rows,
    } = trust_list_verdict(trust_list_reading)?;
    Some(TimelineStep::settled(
        gettext("Trusted detections"),
        trust_list_mechanism_text(),
        status_text,
        SettledStep {
            evidence_rows: plain_rows(evidence_rows),
            header_action: header_action(checked_condition),
            ..SettledStep::without_offers(checked_condition.node_state())
        },
    ))
}

fn trust_list_mechanism_text() -> String {
    gettext(
        "Files and detection names on ClamAV's allowlists are never reported, by any scan. \
         Malware that gets administrator rights could hide itself this way, so check that every \
         entry was added on purpose.",
    )
}

fn nothing_trusted_step() -> AnalysisStep {
    TimelineStep::settled(
        gettext("Trusted detections"),
        trust_list_mechanism_text(),
        gettext("ClamAV reports everything it detects"),
        SettledStep::without_offers(SettledNodeState::Completed),
    )
}

pub fn analysis_status_steps(trust_list_reading: &TrustListReading) -> Vec<AnalysisStep> {
    vec![
        trust_list_step(trust_list_reading, |_checked_condition| {
            StepActionSlot::NoAction
        })
        .unwrap_or_else(nothing_trusted_step),
    ]
}

#[cfg(test)]
mod analysis_presentation_tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        host_services::protection_evidence::protection_evidence_fixtures::empty_trust_list,
        shared_widgets::step_timeline::timeline_step_contents::StepNodeState,
        sharing::analysis_page::trusted_detections_section::trust_list_contents::TrustListReadFailure,
    };

    fn trust_review_steps(trust_list_reading: &TrustListReading) -> Vec<AnalysisStep> {
        trust_list_step(trust_list_reading, |_checked_condition| {
            StepActionSlot::NoAction
        })
        .into_iter()
        .collect()
    }

    #[test]
    fn a_foreign_allowlist_needs_review() {
        let review_steps = trust_review_steps(&TrustListReading::ListsRead(TrustListContents {
            foreign_allowlists: vec![ForeignAllowlistFile {
                file_name: "local.ign2".to_owned(),
                allowlist_entries: AllowlistEntries::EntriesCounted { entry_count: 3 },
            }],
            ..empty_trust_list()
        }));
        assert_eq!(review_steps.len(), 1);
        assert_eq!(review_steps[0].node_state(), StepNodeState::NeedsReview);
    }

    #[test]
    fn an_unreadable_foreign_allowlist_keeps_its_warning() {
        let review_steps = trust_review_steps(&TrustListReading::ListsRead(TrustListContents {
            foreign_allowlists: vec![ForeignAllowlistFile {
                file_name: "local.ign2".to_owned(),
                allowlist_entries: AllowlistEntries::FileUnreadable(
                    TrustListReadFailure::AccessDenied,
                ),
            }],
            ..empty_trust_list()
        }));
        assert_eq!(review_steps.len(), 1);
        assert_eq!(review_steps[0].node_state(), StepNodeState::NeedsReview);
        assert_eq!(
            review_steps[0].status_text,
            "An allowlist that Lazaret didn't write tells ClamAV to stay silent"
        );
    }

    #[test]
    fn an_unreadable_signature_folder_is_not_shown_as_nothing_trusted() {
        let review_steps = trust_review_steps(&TrustListReading::FolderUnreadable(
            TrustListReadFailure::AccessDenied,
        ));
        assert_eq!(review_steps.len(), 1);
        assert_eq!(review_steps[0].node_state(), StepNodeState::NeedsReview);
        assert_eq!(
            trust_list_condition(&TrustListReading::FolderUnreadable(
                TrustListReadFailure::AccessDenied
            )),
            CheckedCondition::EvidenceUnknown
        );
    }

    #[test]
    fn an_unreadable_lazaret_list_needs_review() {
        let review_steps = trust_review_steps(&TrustListReading::ListsRead(TrustListContents {
            ignored_signatures: LazaretListReading::ListUnreadable(
                TrustListReadFailure::AccessDenied,
            ),
            ..empty_trust_list()
        }));
        assert_eq!(review_steps.len(), 1);
        assert_eq!(review_steps[0].node_state(), StepNodeState::NeedsReview);
    }

    #[test]
    fn empty_readable_trust_lists_add_no_review_step() {
        assert!(trust_review_steps(&TrustListReading::ListsRead(empty_trust_list())).is_empty());
        assert!(trust_review_steps(&TrustListReading::FolderMissing).is_empty());
        let status_steps = analysis_status_steps(&TrustListReading::FolderMissing);
        assert_eq!(status_steps.len(), 1);
        assert_eq!(status_steps[0].node_state(), StepNodeState::Completed);
        assert_eq!(
            status_steps[0].status_text,
            "ClamAV reports everything it detects"
        );
    }

    #[test]
    fn key_status_rows_tell_configured_missing_and_unreadable_apart() {
        let configured_status = ServiceKeyStatus::from_key_reading(&Ok(
            ResolvedApiKey::FromKeyring("0123456789abcdef".to_owned()),
        ));
        assert_eq!(configured_status, ServiceKeyStatus::KeyConfigured);
        assert_eq!(
            keyed_service_subtitle(LookupService::VirusTotal, &configured_status),
            "Receives the file's SHA-256 hash\nAPI key configured"
        );
        assert!(!configured_status.needs_attention());
        let missing_status = ServiceKeyStatus::from_key_reading(&Ok(ResolvedApiKey::NotConfigured));
        assert_eq!(missing_status, ServiceKeyStatus::KeyMissing);
        assert_eq!(
            keyed_service_subtitle(LookupService::MalwareBazaar, &missing_status),
            "Receives the detection's signature name or the file's SHA-256 hash\nNo API key, so \
             lookups with this service are off"
        );
        let unreadable_status =
            ServiceKeyStatus::from_key_reading(&Err(KeyStorageFailure::KeyFilePermissionDenied {
                key_file_path: PathBuf::from("/run/agenix/abuse-ch"),
            }));
        assert!(unreadable_status.needs_attention());
        assert!(
            unreadable_status
                .status_text()
                .starts_with("The API key can't be read: ")
        );
        assert_eq!(
            keyless_service_subtitle(LookupService::CirclHashlookup),
            "Receives the file's SHA-256 hash\nNo API key needed"
        );
    }
}

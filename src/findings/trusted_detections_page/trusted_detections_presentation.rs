use gettextrs::{gettext, ngettext};

use crate::{
    findings::trusted_detections_page::trusted_detections_section::{
        trust_list_contents::{
            AllowlistEntries, ForeignAllowlistFile, LazaretListReading, TrustListContents,
            TrustListReading,
        },
        trusted_detections_group::trust_list_failure_text,
    },
    shared_widgets::step_timeline::{
        step_evidence_builders::{CheckedCondition, evidence_row, plain_rows},
        timeline_step_contents::{
            ActionConsequence, SettledNodeState, SettledStep, StepActionButton, StepActionSlot,
            StepEvidenceRow, TimelineStep,
        },
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedDetectionsStepAction {}

impl StepActionButton for TrustedDetectionsStepAction {
    fn button_label(&self) -> String {
        match *self {}
    }

    fn action_consequence(&self) -> ActionConsequence {
        match *self {}
    }
}

pub type TrustedDetectionsStep = TimelineStep<TrustedDetectionsStepAction>;

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

fn nothing_trusted_step() -> TrustedDetectionsStep {
    TimelineStep::settled(
        gettext("Trusted detections"),
        trust_list_mechanism_text(),
        gettext("ClamAV reports everything it detects"),
        SettledStep::without_offers(SettledNodeState::Completed),
    )
}

pub fn trusted_detections_status_steps(
    trust_list_reading: &TrustListReading,
) -> Vec<TrustedDetectionsStep> {
    vec![
        trust_list_step(trust_list_reading, |_checked_condition| {
            StepActionSlot::NoAction
        })
        .unwrap_or_else(nothing_trusted_step),
    ]
}

#[cfg(test)]
mod trusted_detections_presentation_tests {
    use super::*;
    use crate::{
        findings::trusted_detections_page::trusted_detections_section::trust_list_contents::TrustListReadFailure,
        host_services::protection_evidence::protection_evidence_fixtures::empty_trust_list,
        shared_widgets::step_timeline::timeline_step_contents::StepNodeState,
    };

    fn trust_review_steps(trust_list_reading: &TrustListReading) -> Vec<TrustedDetectionsStep> {
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
        let status_steps = trusted_detections_status_steps(&TrustListReading::FolderMissing);
        assert_eq!(status_steps.len(), 1);
        assert_eq!(status_steps[0].node_state(), StepNodeState::Completed);
        assert_eq!(
            status_steps[0].status_text,
            "ClamAV reports everything it detects"
        );
    }
}

use std::collections::BTreeSet;

use gettextrs::gettext;

use crate::{
    detections_page::detected_file_state::{DetectedFileState, FileAccess, FileOwner},
    host_services::{
        clamav_programs::distribution_install_guides::DistributionFamily,
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        desktop::locale_formatting::exact_local_time_text,
        detection_journal::detection_history_store::{
            DetectionSources, DetectionState, ResolutionKind, StoredDetection,
        },
        threat_intel::{
            malware_bazaar_client::{KnownSampleLookup, MalwareBazaarFailure},
            service_key_storage::{KeyStorageFailure, describe_key_failure},
        },
    },
    shared_widgets::step_timeline::timeline_step_contents::{
        StepActionSlot, StepChoiceRow, StepEvidenceRow, StepNodeState, TimelineStep,
        TimelineStepAction,
    },
    signatures_page::signature_provider_catalogue::provider_of_signature,
};

const TEST_SIGNATURE_MARKER: &str = "Eicar-Test-Signature";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayedDetection {
    pub stored_detection: StoredDetection,
    pub file_state: DetectedFileState,
}

#[derive(Debug)]
pub enum SignatureLookupState {
    NotLookedUp,
    LookingUp,
    KeyMissing,
    KeyUnreadable(KeyStorageFailure),
    LookupFinished(KnownSampleLookup),
    BazaarLookupFailed(MalwareBazaarFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeletionPrompt {
    NotAsked,
    AwaitingAnswer,
}

pub fn signature_is_test_pattern(signature_name: &str) -> bool {
    signature_name.contains(TEST_SIGNATURE_MARKER)
}

pub fn detection_needs_attention(displayed_detection: &DisplayedDetection) -> bool {
    displayed_detection
        .stored_detection
        .detection_state
        .awaits_user_decision()
        && displayed_detection.file_state != DetectedFileState::NoLongerThere
}

pub fn displayed_file_path(stored_detection: &StoredDetection) -> String {
    sanitize_scanner_line(&stored_detection.file_path.to_string_lossy())
}

pub fn displayed_file_name(stored_detection: &StoredDetection) -> String {
    stored_detection.file_path.file_name().map_or_else(
        || displayed_file_path(stored_detection),
        |file_name| sanitize_scanner_line(&file_name.to_string_lossy()),
    )
}

pub fn detection_state_text(displayed_detection: &DisplayedDetection) -> String {
    let stored_detection = &displayed_detection.stored_detection;
    match &stored_detection.detection_state {
        DetectionState::Resolved {
            resolution_kind: ResolutionKind::MovedToQuarantine,
            ..
        } if displayed_detection.file_state.file_is_present() => {
            gettext("Restored from quarantine")
        }
        DetectionState::Resolved {
            resolution_kind: ResolutionKind::MovedToQuarantine,
            ..
        } => gettext("Moved to quarantine"),
        DetectionState::Resolved {
            resolution_kind: ResolutionKind::DeletedByUser,
            ..
        } => gettext("Deleted"),
        DetectionState::Resolved {
            resolution_kind: ResolutionKind::DismissedByUser,
            ..
        } => gettext("Kept by you"),
        DetectionState::Open | DetectionState::StoredStateUnreadable { .. } => {
            match displayed_detection.file_state {
                DetectedFileState::Present {
                    owner: FileOwner::OtherUser,
                    ..
                } => gettext("Belongs to another user"),
                DetectedFileState::Present {
                    access: FileAccess::BlockedOnAccess,
                    owner: FileOwner::CurrentUser,
                } => gettext("Blocked, needs a decision"),
                DetectedFileState::Present {
                    access: FileAccess::Readable,
                    owner: FileOwner::CurrentUser,
                } => gettext("Not blocked, needs a decision"),
                DetectedFileState::Present {
                    access: FileAccess::NotOpened,
                    owner: FileOwner::CurrentUser,
                } => gettext("Needs a decision"),
                DetectedFileState::NoLongerThere => gettext("No longer there"),
                DetectedFileState::StateUnknown => gettext("File could not be checked"),
            }
        }
    }
}

pub fn detection_summary_text(displayed_detection: &DisplayedDetection) -> String {
    let stored_detection = &displayed_detection.stored_detection;
    let signature_text = sanitize_scanner_line(&stored_detection.signature_name);
    let state_text = detection_state_text(displayed_detection);
    if signature_is_test_pattern(&stored_detection.signature_name) {
        gettext("{signature} (test file) · {state}")
            .replace("{signature}", &signature_text)
            .replace("{state}", &state_text)
    } else {
        gettext("{signature} · {state}")
            .replace("{signature}", &signature_text)
            .replace("{state}", &state_text)
    }
}

fn evidence_row(evidence_name: String, evidence_value: String) -> StepEvidenceRow {
    StepEvidenceRow::current_fact(evidence_name, evidence_value)
}

fn plain_step(
    step_title: String,
    mechanism_details: String,
    node_state: StepNodeState,
    status_text: String,
) -> TimelineStep {
    TimelineStep {
        step_title,
        mechanism_details,
        node_state,
        status_text,
        evidence_rows: Vec::new(),
        guidance_commands: Vec::new(),
        choice_rows: Vec::new(),
        action_slot: StepActionSlot::NoAction,
    }
}

fn source_text(stored_detection: &StoredDetection) -> String {
    match stored_detection.detection_sources {
        DetectionSources::OnAccessAndSchedule => {
            gettext("On-access scanning and the scheduled scan")
        }
        DetectionSources::OnAccessOnly => gettext("On-access scanning"),
        DetectionSources::ScheduleOnly => gettext("The scheduled scan"),
        DetectionSources::NoSourceRecorded => gettext("Not recorded"),
    }
}

fn detected_step(stored_detection: &StoredDetection) -> TimelineStep {
    let signature_text = sanitize_scanner_line(&stored_detection.signature_name);
    TimelineStep {
        evidence_rows: vec![
            evidence_row(gettext("File"), displayed_file_path(stored_detection)),
            evidence_row(
                gettext("Signature source"),
                provider_of_signature(&stored_detection.signature_name).to_owned(),
            ),
            evidence_row(gettext("Found by"), source_text(stored_detection)),
            evidence_row(
                gettext("Last seen"),
                exact_local_time_text(stored_detection.last_seen),
            ),
            evidence_row(
                gettext("Times seen"),
                stored_detection.sighting_count.to_string(),
            ),
        ],
        ..plain_step(
            gettext("Detected"),
            if signature_is_test_pattern(&stored_detection.signature_name) {
                gettext(
                    "This signature matches the harmless EICAR test pattern, which exists to \
                     check that detection works.",
                )
            } else {
                gettext(
                    "ClamAV matched this file against a signature. A match is strong evidence, \
                     but false positives happen, especially with packed or administrative tools.",
                )
            },
            StepNodeState::Completed,
            gettext("{signature}, first seen {time}")
                .replace("{signature}", &signature_text)
                .replace(
                    "{time}",
                    &exact_local_time_text(stored_detection.first_seen),
                ),
        )
    }
}

fn blocked_step(displayed_detection: &DisplayedDetection) -> TimelineStep {
    let stored_detection = &displayed_detection.stored_detection;
    let (node_state, status_text) = match displayed_detection.file_state {
        DetectedFileState::Present {
            access: FileAccess::BlockedOnAccess,
            ..
        } => (
            StepNodeState::Completed,
            gettext("Opening this file is refused, which is why it won't open"),
        ),
        DetectedFileState::Present {
            access: FileAccess::NotOpened,
            ..
        } => (
            StepNodeState::Completed,
            gettext("Not opened again after your decision"),
        ),
        DetectedFileState::NoLongerThere => (
            StepNodeState::Completed,
            gettext("The file is no longer there"),
        ),
        DetectedFileState::Present {
            access: FileAccess::Readable,
            ..
        } if stored_detection.detection_sources == DetectionSources::ScheduleOnly => (
            StepNodeState::NeedsReview,
            gettext("Not blocked: the scheduled scan found it, and it can still be opened"),
        ),
        DetectedFileState::Present {
            access: FileAccess::Readable,
            ..
        } => (
            StepNodeState::NeedsReview,
            gettext("Not blocked right now: it can still be opened"),
        ),
        DetectedFileState::StateUnknown => (
            StepNodeState::NeedsReview,
            gettext("Could not check whether the file is blocked"),
        ),
    };
    plain_step(
        gettext("Blocked"),
        gettext(
            "With on-access prevention, the kernel refuses to open a detected file in a watched \
             folder. The file stays where it is until you decide what to do with it.",
        ),
        node_state,
        status_text,
    )
}

fn false_positive_snippet(
    stored_detection: &StoredDetection,
    distribution_family: DistributionFamily,
) -> String {
    let shown_path = displayed_file_path(stored_detection);
    if distribution_family == DistributionFamily::NixosFamily {
        format!(
            "services.clamav.daemon.settings.OnAccessExcludePath = [ \"{}\" ];",
            shown_path.replace('\\', "\\\\").replace('"', "\\\"")
        )
    } else {
        format!("OnAccessExcludePath {shown_path}")
    }
}

fn describe_bazaar_lookup_failure(bazaar_failure: &MalwareBazaarFailure) -> String {
    match bazaar_failure {
        MalwareBazaarFailure::RequestFailed(request_failure) => {
            gettext("MalwareBazaar could not be reached: {error}")
                .replace("{error}", &request_failure.to_string())
        }
        MalwareBazaarFailure::AnswerUnreadable => {
            gettext("MalwareBazaar sent an answer that could not be read")
        }
        MalwareBazaarFailure::KeyRefused => gettext("MalwareBazaar refused the API key"),
        MalwareBazaarFailure::QueryRefused { query_status } => {
            gettext("MalwareBazaar answered: {status}").replace("{status}", query_status)
        }
    }
}

fn lookup_summary_text(lookup_state: &SignatureLookupState) -> Option<String> {
    match lookup_state {
        SignatureLookupState::NotLookedUp => None,
        SignatureLookupState::LookingUp => Some(gettext("Looking up…")),
        SignatureLookupState::KeyMissing => Some(gettext(
            "Add your abuse.ch key in Preferences to look up detections.",
        )),
        SignatureLookupState::KeyUnreadable(key_failure) => {
            Some(sanitize_scanner_line(&describe_key_failure(key_failure)))
        }
        SignatureLookupState::BazaarLookupFailed(bazaar_failure) => Some(sanitize_scanner_line(
            &describe_bazaar_lookup_failure(bazaar_failure),
        )),
        SignatureLookupState::LookupFinished(KnownSampleLookup::NoKnownSamples) => {
            Some(gettext("No known samples match this signature."))
        }
        SignatureLookupState::LookupFinished(KnownSampleLookup::SamplesFound { known_samples }) => {
            let families = known_samples
                .iter()
                .map(|known_sample| sanitize_scanner_line(&known_sample.malware_family))
                .filter(|malware_family| !malware_family.is_empty())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ");
            let earliest_seen = known_samples
                .iter()
                .map(|known_sample| known_sample.first_seen.as_str())
                .filter(|first_seen| !first_seen.is_empty())
                .min()
                .map(sanitize_scanner_line)
                .unwrap_or_default();
            Some(
                gettext("{count} known samples. Families: {families}. Earliest seen: {date}.")
                    .replace("{count}", &known_samples.len().to_string())
                    .replace("{families}", &families)
                    .replace("{date}", &earliest_seen),
            )
        }
    }
}

fn lookup_choices() -> Vec<StepChoiceRow> {
    let signature_lookup = StepChoiceRow {
        choice_description: gettext(
            "Ask MalwareBazaar about this signature. Only its name is sent.",
        ),
        choice_label: gettext("Look Up"),
        chosen_action: TimelineStepAction::LookUpIncidentSignature,
        choice_destructive: false,
    };
    vec![signature_lookup]
}

fn decision_choices(
    deletion_prompt: DeletionPrompt,
    file_state: DetectedFileState,
) -> Vec<StepChoiceRow> {
    if !file_state.user_can_move_or_delete() {
        return vec![StepChoiceRow {
            choice_description: gettext("Stop asking about this file"),
            choice_label: gettext("Keep"),
            chosen_action: TimelineStepAction::DismissIncident,
            choice_destructive: false,
        }];
    }
    match deletion_prompt {
        DeletionPrompt::AwaitingAnswer => vec![
            StepChoiceRow {
                choice_description: gettext("Delete this file permanently? This can't be undone."),
                choice_label: gettext("Delete Permanently"),
                chosen_action: TimelineStepAction::DeleteIncidentFile,
                choice_destructive: true,
            },
            StepChoiceRow {
                choice_description: gettext("Go back without deleting"),
                choice_label: gettext("Cancel"),
                chosen_action: TimelineStepAction::CancelIncidentDeletion,
                choice_destructive: false,
            },
        ],
        DeletionPrompt::NotAsked => vec![
            StepChoiceRow {
                choice_description: gettext("Move it somewhere safe. You can restore it later."),
                choice_label: gettext("Quarantine"),
                chosen_action: TimelineStepAction::QuarantineIncident,
                choice_destructive: false,
            },
            StepChoiceRow {
                choice_description: gettext("Remove it for good"),
                choice_label: gettext("Delete…"),
                chosen_action: TimelineStepAction::AskIncidentDeletion,
                choice_destructive: false,
            },
            StepChoiceRow {
                choice_description: gettext("You know this file is fine"),
                choice_label: gettext("Keep"),
                chosen_action: TimelineStepAction::DismissIncident,
                choice_destructive: false,
            },
        ],
    }
}

fn review_step(
    displayed_detection: &DisplayedDetection,
    deletion_prompt: DeletionPrompt,
    lookup_state: &SignatureLookupState,
    distribution_family: DistributionFamily,
) -> TimelineStep {
    let stored_detection = &displayed_detection.stored_detection;
    let step_title = gettext("Your decision");
    let mechanism_details = gettext(
        "If it's unfamiliar, quarantine it. Keeping a file only stops Lazaret asking: on-access \
         scanning keeps blocking it until the path is excluded in the ClamAV configuration, as \
         shown here.",
    );
    if !detection_needs_attention(displayed_detection) {
        return plain_step(
            step_title,
            gettext(
                "Quarantined files can be restored from the Quarantine page. A file you kept is \
                 still blocked by on-access scanning until its path is excluded in the ClamAV \
                 configuration.",
            ),
            StepNodeState::Completed,
            detection_state_text(displayed_detection),
        );
    }
    let status_text = match displayed_detection.file_state {
        DetectedFileState::Present {
            owner: FileOwner::OtherUser,
            ..
        } => gettext("This file belongs to another user, so Lazaret can't move or delete it"),
        DetectedFileState::StateUnknown => {
            gettext("Lazaret couldn't check this file, so it can't move or delete it")
        }
        DetectedFileState::Present {
            owner: FileOwner::CurrentUser,
            ..
        }
        | DetectedFileState::NoLongerThere => gettext("Choose what happens to this file"),
    };
    TimelineStep {
        choice_rows: decision_choices(deletion_prompt, displayed_detection.file_state)
            .into_iter()
            .chain(lookup_choices())
            .collect(),
        evidence_rows: lookup_summary_text(lookup_state)
            .map(|lookup_summary| evidence_row(gettext("MalwareBazaar"), lookup_summary))
            .into_iter()
            .collect(),
        guidance_commands: vec![false_positive_snippet(
            stored_detection,
            distribution_family,
        )],
        ..plain_step(
            step_title,
            mechanism_details,
            StepNodeState::ActNext,
            status_text,
        )
    }
}

fn resolved_step(displayed_detection: &DisplayedDetection) -> TimelineStep {
    let stored_detection = &displayed_detection.stored_detection;
    let step_title = gettext("Resolved");
    let mechanism_details = gettext(
        "A resolved detection opens again if ClamAV finds the same file again later, for example \
         after you download it a second time.",
    );
    if detection_needs_attention(displayed_detection) {
        return plain_step(
            step_title,
            mechanism_details,
            StepNodeState::AwaitingPrerequisite,
            gettext("Waiting for your decision"),
        );
    }
    let status_text = match &stored_detection.detection_state {
        DetectionState::Resolved { resolved_at, .. } => gettext("{state}, {time}")
            .replace("{state}", &detection_state_text(displayed_detection))
            .replace("{time}", &exact_local_time_text(*resolved_at)),
        DetectionState::Open | DetectionState::StoredStateUnreadable { .. } => {
            detection_state_text(displayed_detection)
        }
    };
    plain_step(
        step_title,
        mechanism_details,
        StepNodeState::Completed,
        status_text,
    )
}

pub fn incident_timeline(
    displayed_detection: &DisplayedDetection,
    deletion_prompt: DeletionPrompt,
    lookup_state: &SignatureLookupState,
    distribution_family: DistributionFamily,
) -> Vec<TimelineStep> {
    vec![
        detected_step(&displayed_detection.stored_detection),
        blocked_step(displayed_detection),
        review_step(
            displayed_detection,
            deletion_prompt,
            lookup_state,
            distribution_family,
        ),
        resolved_step(displayed_detection),
    ]
}

#[cfg(test)]
mod incident_timeline_presentation_tests {
    use std::path::PathBuf;

    use super::*;
    use crate::host_services::detection_journal::detection_history_store::StoredStateInconsistency;

    const BLOCKED_POSITION: usize = 1;
    const REVIEW_POSITION: usize = 2;
    const RESOLVED_POSITION: usize = 3;

    fn blocked_detection() -> DisplayedDetection {
        DisplayedDetection {
            stored_detection: StoredDetection {
                detection_id: 1,
                file_path: PathBuf::from("/home/user/Downloads/invoice.exe"),
                signature_name: "Win.Trojan.Agent-1".to_owned(),
                detection_sources: DetectionSources::OnAccessOnly,
                first_seen: jiff::Timestamp::constant(1_793_869_222, 0),
                last_seen: jiff::Timestamp::constant(1_793_869_225, 0),
                sighting_count: 6,
                detection_state: DetectionState::Open,
            },
            file_state: DetectedFileState::Present {
                access: FileAccess::BlockedOnAccess,
                owner: FileOwner::CurrentUser,
            },
        }
    }

    fn choice_actions(
        displayed_detection: &DisplayedDetection,
        deletion_prompt: DeletionPrompt,
    ) -> Vec<TimelineStepAction> {
        incident_timeline(
            displayed_detection,
            deletion_prompt,
            &SignatureLookupState::NotLookedUp,
            DistributionFamily::NixosFamily,
        )[REVIEW_POSITION]
            .choice_rows
            .iter()
            .map(|choice_row| choice_row.chosen_action)
            .filter(|chosen_action| {
                !matches!(chosen_action, TimelineStepAction::LookUpIncidentSignature)
            })
            .collect()
    }

    #[test]
    fn a_blocked_file_explains_itself_and_asks_for_a_decision() {
        let incident_steps = incident_timeline(
            &blocked_detection(),
            DeletionPrompt::NotAsked,
            &SignatureLookupState::NotLookedUp,
            DistributionFamily::NixosFamily,
        );
        assert_eq!(
            incident_steps[BLOCKED_POSITION].node_state,
            StepNodeState::Completed
        );
        assert!(
            incident_steps[BLOCKED_POSITION]
                .status_text
                .contains("won't open")
        );
        assert_eq!(
            incident_steps[REVIEW_POSITION].node_state,
            StepNodeState::ActNext
        );
        assert_eq!(
            incident_steps[RESOLVED_POSITION].node_state,
            StepNodeState::AwaitingPrerequisite
        );
    }

    #[test]
    fn deleting_takes_two_explicit_choices() {
        let first_choices = choice_actions(&blocked_detection(), DeletionPrompt::NotAsked);
        assert!(first_choices.contains(&TimelineStepAction::AskIncidentDeletion));
        assert!(!first_choices.contains(&TimelineStepAction::DeleteIncidentFile));
        assert_eq!(
            choice_actions(&blocked_detection(), DeletionPrompt::AwaitingAnswer),
            vec![
                TimelineStepAction::DeleteIncidentFile,
                TimelineStepAction::CancelIncidentDeletion
            ]
        );
    }

    #[test]
    fn a_file_found_only_by_the_schedule_is_not_reported_as_blocked() {
        let displayed_detection = DisplayedDetection {
            stored_detection: StoredDetection {
                detection_sources: DetectionSources::ScheduleOnly,
                ..blocked_detection().stored_detection
            },
            file_state: DetectedFileState::Present {
                access: FileAccess::Readable,
                owner: FileOwner::CurrentUser,
            },
        };
        let incident_steps = incident_timeline(
            &displayed_detection,
            DeletionPrompt::NotAsked,
            &SignatureLookupState::NotLookedUp,
            DistributionFamily::NixosFamily,
        );
        assert_eq!(
            incident_steps[BLOCKED_POSITION].node_state,
            StepNodeState::NeedsReview
        );
        assert!(
            incident_steps[BLOCKED_POSITION]
                .status_text
                .contains("Not blocked")
        );
    }

    #[test]
    fn a_foreign_file_offers_no_move_or_delete_even_when_blocked() {
        [FileAccess::BlockedOnAccess, FileAccess::Readable]
            .into_iter()
            .for_each(|file_access| {
                let displayed_detection = DisplayedDetection {
                    file_state: DetectedFileState::Present {
                        access: file_access,
                        owner: FileOwner::OtherUser,
                    },
                    ..blocked_detection()
                };
                assert_eq!(
                    choice_actions(&displayed_detection, DeletionPrompt::NotAsked),
                    vec![TimelineStepAction::DismissIncident]
                );
            });
    }

    #[test]
    fn an_unresolved_file_that_could_not_be_checked_still_needs_attention() {
        let displayed_detection = DisplayedDetection {
            file_state: DetectedFileState::StateUnknown,
            ..blocked_detection()
        };
        assert!(detection_needs_attention(&displayed_detection));
        assert_eq!(
            choice_actions(&displayed_detection, DeletionPrompt::NotAsked),
            vec![TimelineStepAction::DismissIncident]
        );
    }

    #[test]
    fn a_vanished_or_resolved_file_needs_no_attention() {
        assert!(detection_needs_attention(&blocked_detection()));
        assert!(!detection_needs_attention(&DisplayedDetection {
            file_state: DetectedFileState::NoLongerThere,
            ..blocked_detection()
        }));
        assert!(!detection_needs_attention(&DisplayedDetection {
            stored_detection: StoredDetection {
                detection_state: DetectionState::Resolved {
                    resolution_kind: ResolutionKind::DismissedByUser,
                    resolved_at: jiff::Timestamp::constant(1_793_869_300, 0),
                },
                ..blocked_detection().stored_detection
            },
            ..blocked_detection()
        }));
    }

    #[test]
    fn an_unreadable_stored_state_still_asks_for_a_decision() {
        let displayed_detection = DisplayedDetection {
            stored_detection: StoredDetection {
                detection_state: DetectionState::StoredStateUnreadable {
                    stored_inconsistency: StoredStateInconsistency::ResolvedWithoutTime {
                        resolution_kind: ResolutionKind::MovedToQuarantine,
                    },
                },
                ..blocked_detection().stored_detection
            },
            ..blocked_detection()
        };
        assert!(detection_needs_attention(&displayed_detection));
        assert_eq!(
            detection_state_text(&displayed_detection),
            "Blocked, needs a decision"
        );
    }

    #[test]
    fn a_readable_file_without_a_recorded_source_is_not_blamed_on_the_schedule() {
        let displayed_detection = DisplayedDetection {
            stored_detection: StoredDetection {
                detection_sources: DetectionSources::NoSourceRecorded,
                ..blocked_detection().stored_detection
            },
            file_state: DetectedFileState::Present {
                access: FileAccess::Readable,
                owner: FileOwner::CurrentUser,
            },
        };
        let incident_steps = incident_timeline(
            &displayed_detection,
            DeletionPrompt::NotAsked,
            &SignatureLookupState::NotLookedUp,
            DistributionFamily::NixosFamily,
        );
        assert!(
            !incident_steps[BLOCKED_POSITION]
                .status_text
                .contains("scheduled scan")
        );
    }

    #[test]
    fn a_quarantined_file_that_came_back_reads_as_restored() {
        let displayed_detection = DisplayedDetection {
            stored_detection: StoredDetection {
                detection_state: DetectionState::Resolved {
                    resolution_kind: ResolutionKind::MovedToQuarantine,
                    resolved_at: jiff::Timestamp::constant(1_793_869_300, 0),
                },
                ..blocked_detection().stored_detection
            },
            file_state: DetectedFileState::Present {
                access: FileAccess::Readable,
                owner: FileOwner::CurrentUser,
            },
        };
        assert_eq!(
            detection_state_text(&displayed_detection),
            "Restored from quarantine"
        );
    }

    #[test]
    fn the_exclusion_snippet_matches_the_distribution_and_escapes_quotes() {
        let stored_detection = StoredDetection {
            file_path: PathBuf::from("/home/user/a\"b.exe"),
            ..blocked_detection().stored_detection
        };
        assert_eq!(
            false_positive_snippet(&stored_detection, DistributionFamily::NixosFamily),
            "services.clamav.daemon.settings.OnAccessExcludePath = [ \"/home/user/a\\\"b.exe\" ];"
        );
        assert_eq!(
            false_positive_snippet(&stored_detection, DistributionFamily::DebianFamily),
            "OnAccessExcludePath /home/user/a\"b.exe"
        );
    }

    #[test]
    fn test_patterns_are_labelled_in_the_summary() {
        let displayed_detection = DisplayedDetection {
            stored_detection: StoredDetection {
                signature_name: "Eicar-Test-Signature".to_owned(),
                ..blocked_detection().stored_detection
            },
            ..blocked_detection()
        };
        assert!(detection_summary_text(&displayed_detection).contains("test file"));
    }

    #[test]
    fn the_only_lookup_sends_the_signature_name() {
        let lookup_actions = lookup_choices()
            .into_iter()
            .map(|choice_row| choice_row.chosen_action)
            .collect::<Vec<_>>();
        assert_eq!(
            lookup_actions,
            vec![TimelineStepAction::LookUpIncidentSignature]
        );
    }

    #[test]
    fn lookup_results_summarise_families_and_the_earliest_date() {
        let known_sample = |malware_family: &str, first_seen: &str| {
            crate::host_services::threat_intel::malware_bazaar_client::SampleSummary {
                malware_family: malware_family.to_owned(),
                first_seen: first_seen.to_owned(),
                file_type: "exe".to_owned(),
                sample_tags: Vec::new(),
            }
        };
        assert_eq!(
            lookup_summary_text(&SignatureLookupState::LookupFinished(
                KnownSampleLookup::SamplesFound {
                    known_samples: vec![
                        known_sample("AgentTesla", "2026-10-02"),
                        known_sample("AgentTesla", "2026-10-01"),
                    ],
                }
            )),
            Some("2 known samples. Families: AgentTesla. Earliest seen: 2026-10-01.".to_owned())
        );
        assert_eq!(
            lookup_summary_text(&SignatureLookupState::NotLookedUp),
            None
        );
    }
}

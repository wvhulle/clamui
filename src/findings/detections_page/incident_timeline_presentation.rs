use std::collections::BTreeSet;

use gettextrs::gettext;

use crate::{
    findings::detections_page::detected_file_state::{DetectedFileState, FileAccess, FileOwner},
    host_services::{
        clamav_programs::{
            distribution_install_guides::DistributionFamily,
            signature_provider_catalogue::{provider_of_signature, signature_source_name},
        },
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        desktop::locale_formatting::exact_local_time_text,
        detection_journal::detection_history_store::{
            DetectionSources, DetectionState, ResolutionKind, StoredDetection,
        },
        threat_intel::{
            file_reputation_check::malware_family_text,
            malware_bazaar_client::{KnownSampleLookup, MalwareBazaarFailure, SampleFirstSeen},
            service_key_storage::{KeyStorageFailure, describe_key_failure},
        },
    },
    shared_widgets::step_timeline::timeline_step_contents::{
        ActionConsequence, ActionableEvidenceRow, SettledNodeState, SettledStep, StepActionButton,
        StepChoiceRow, StepEvidenceRow, TimelineStep,
    },
};

const TEST_SIGNATURE_MARKER: &str = "Eicar-Test-Signature";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncidentStepAction {
    QuarantineIncident,
    AskIncidentDeletion,
    DeleteIncidentFile,
    CancelIncidentDeletion,
    DismissIncident,
    LookUpIncidentSignature,
    OpenOnlineServices,
    SubmitIncidentSample,
}

impl StepActionButton for IncidentStepAction {
    fn button_label(&self) -> String {
        match self {
            Self::QuarantineIncident => gettext("Quarantine"),
            Self::AskIncidentDeletion => gettext("Delete…"),
            Self::DeleteIncidentFile => gettext("Delete Permanently"),
            Self::CancelIncidentDeletion => gettext("Cancel"),
            Self::DismissIncident => gettext("Keep"),
            Self::LookUpIncidentSignature => gettext("Look Up"),
            Self::OpenOnlineServices => gettext("Add Key…"),
            Self::SubmitIncidentSample => gettext("Submit…"),
        }
    }

    fn action_consequence(&self) -> ActionConsequence {
        match self {
            Self::DeleteIncidentFile => ActionConsequence::DestructiveAction,
            Self::QuarantineIncident
            | Self::AskIncidentDeletion
            | Self::CancelIncidentDeletion
            | Self::DismissIncident
            | Self::LookUpIncidentSignature
            | Self::OpenOnlineServices
            | Self::SubmitIncidentSample => ActionConsequence::OrdinaryAction,
        }
    }
}

pub type IncidentStep = TimelineStep<IncidentStepAction>;

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
        DetectionState::Open => match displayed_detection.file_state {
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
        },
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

fn evidence_row(
    evidence_name: String,
    evidence_value: String,
) -> ActionableEvidenceRow<IncidentStepAction> {
    StepEvidenceRow::current_fact(evidence_name, evidence_value).into()
}

fn plain_step(
    step_title: String,
    mechanism_details: String,
    node_state: SettledNodeState,
    status_text: String,
) -> IncidentStep {
    TimelineStep::settled(
        step_title,
        mechanism_details,
        status_text,
        SettledStep::without_offers(node_state),
    )
}

fn source_text(stored_detection: &StoredDetection) -> String {
    match stored_detection.detection_sources {
        DetectionSources::OnAccessAndSchedule => {
            gettext("On-access scanning and the scheduled scan")
        }
        DetectionSources::OnAccessOnly => gettext("On-access scanning"),
        DetectionSources::ScheduleOnly => gettext("The scheduled scan"),
    }
}

fn detected_step(stored_detection: &StoredDetection) -> IncidentStep {
    let signature_text = sanitize_scanner_line(&stored_detection.signature_name);
    let evidence_rows = vec![
        evidence_row(gettext("File"), displayed_file_path(stored_detection)),
        evidence_row(
            gettext("Signature source"),
            signature_source_name(provider_of_signature(&stored_detection.signature_name)),
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
    ];
    TimelineStep::settled(
        gettext("Detected"),
        if signature_is_test_pattern(&stored_detection.signature_name) {
            gettext(
                "This signature matches the harmless EICAR test pattern, which exists to check \
                 that detection works.",
            )
        } else {
            gettext(
                "ClamAV matched this file against a signature. A match is strong evidence, but \
                 false positives happen, especially with packed or administrative tools.",
            )
        },
        gettext("{signature}, first seen {time}")
            .replace("{signature}", &signature_text)
            .replace(
                "{time}",
                &exact_local_time_text(stored_detection.first_seen),
            ),
        SettledStep {
            evidence_rows,
            ..SettledStep::without_offers(SettledNodeState::Completed)
        },
    )
}

fn blocked_step(displayed_detection: &DisplayedDetection) -> IncidentStep {
    let stored_detection = &displayed_detection.stored_detection;
    let (node_state, status_text) = match displayed_detection.file_state {
        DetectedFileState::Present {
            access: FileAccess::BlockedOnAccess,
            ..
        } => (
            SettledNodeState::Completed,
            gettext("Opening this file is refused, which is why it won't open"),
        ),
        DetectedFileState::Present {
            access: FileAccess::NotOpened,
            ..
        } => (
            SettledNodeState::Completed,
            gettext("Not opened again after your decision"),
        ),
        DetectedFileState::NoLongerThere => (
            SettledNodeState::Completed,
            gettext("The file is no longer there"),
        ),
        DetectedFileState::Present {
            access: FileAccess::Readable,
            ..
        } if stored_detection.detection_sources == DetectionSources::ScheduleOnly => (
            SettledNodeState::NeedsReview,
            gettext("Not blocked: the scheduled scan found it, and it can still be opened"),
        ),
        DetectedFileState::Present {
            access: FileAccess::Readable,
            ..
        } => (
            SettledNodeState::NeedsReview,
            gettext("Not blocked right now: it can still be opened"),
        ),
        DetectedFileState::StateUnknown => (
            SettledNodeState::NeedsReview,
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
                .map(|known_sample| &known_sample.malware_family)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(malware_family_text)
                .collect::<Vec<_>>()
                .join(", ");
            let earliest_seen = known_samples
                .iter()
                .filter_map(|known_sample| match &known_sample.first_seen {
                    SampleFirstSeen::SeenAt(seen_at) => Some(seen_at.as_str()),
                    SampleFirstSeen::FirstSeenUnknown => None,
                })
                .min()
                .map_or_else(|| gettext("unknown"), sanitize_scanner_line);
            Some(
                gettext("{count} known samples. Families: {families}. Earliest seen: {date}.")
                    .replace("{count}", &known_samples.len().to_string())
                    .replace("{families}", &families)
                    .replace("{date}", &earliest_seen),
            )
        }
    }
}

fn lookup_choices(lookup_state: &SignatureLookupState) -> Vec<StepChoiceRow<IncidentStepAction>> {
    let signature_lookup = StepChoiceRow {
        choice_description: gettext(
            "Ask MalwareBazaar about this signature. Only its name is sent.",
        ),
        chosen_action: IncidentStepAction::LookUpIncidentSignature,
    };
    match lookup_state {
        SignatureLookupState::KeyMissing => vec![
            signature_lookup,
            StepChoiceRow {
                choice_description: gettext("MalwareBazaar needs a free abuse.ch key"),
                chosen_action: IncidentStepAction::OpenOnlineServices,
            },
        ],
        SignatureLookupState::NotLookedUp
        | SignatureLookupState::LookingUp
        | SignatureLookupState::KeyUnreadable(_)
        | SignatureLookupState::LookupFinished(_)
        | SignatureLookupState::BazaarLookupFailed(_) => vec![signature_lookup],
    }
}

fn decision_choices(
    deletion_prompt: DeletionPrompt,
    file_state: DetectedFileState,
) -> Vec<StepChoiceRow<IncidentStepAction>> {
    if !file_state.user_can_move_or_delete() {
        return vec![StepChoiceRow {
            choice_description: gettext("Stop asking about this file"),
            chosen_action: IncidentStepAction::DismissIncident,
        }];
    }
    match deletion_prompt {
        DeletionPrompt::AwaitingAnswer => vec![
            StepChoiceRow {
                choice_description: gettext("Delete this file permanently? This can't be undone."),
                chosen_action: IncidentStepAction::DeleteIncidentFile,
            },
            StepChoiceRow {
                choice_description: gettext("Go back without deleting"),
                chosen_action: IncidentStepAction::CancelIncidentDeletion,
            },
        ],
        DeletionPrompt::NotAsked => vec![
            StepChoiceRow {
                choice_description: gettext("Move it somewhere safe. You can restore it later."),
                chosen_action: IncidentStepAction::QuarantineIncident,
            },
            StepChoiceRow {
                choice_description: gettext("Remove it for good"),
                chosen_action: IncidentStepAction::AskIncidentDeletion,
            },
            StepChoiceRow {
                choice_description: gettext(
                    "You know this file is fine. ClamAV still reports it at the next scan; trust \
                     it from Quarantine or a scan result to stop that.",
                ),
                chosen_action: IncidentStepAction::DismissIncident,
            },
        ],
    }
}

fn review_step(
    displayed_detection: &DisplayedDetection,
    deletion_prompt: DeletionPrompt,
    lookup_state: &SignatureLookupState,
    distribution_family: DistributionFamily,
) -> IncidentStep {
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
            SettledNodeState::Completed,
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
    TimelineStep::settled(
        step_title,
        mechanism_details,
        status_text,
        SettledStep {
            choice_rows: decision_choices(deletion_prompt, displayed_detection.file_state)
                .into_iter()
                .chain(lookup_choices(lookup_state))
                .collect(),
            evidence_rows: lookup_summary_text(lookup_state)
                .map(|lookup_summary| evidence_row(gettext("MalwareBazaar"), lookup_summary))
                .into_iter()
                .collect(),
            ..SettledStep::without_offers(SettledNodeState::ActNext)
        },
    )
    .with_guidance_commands(vec![false_positive_snippet(
        stored_detection,
        distribution_family,
    )])
}

fn resolved_step(displayed_detection: &DisplayedDetection) -> IncidentStep {
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
            SettledNodeState::AwaitingPrerequisite,
            gettext("Waiting for your decision"),
        );
    }
    let status_text = match &stored_detection.detection_state {
        DetectionState::Resolved { resolved_at, .. } => gettext("{state}, {time}")
            .replace("{state}", &detection_state_text(displayed_detection))
            .replace("{time}", &exact_local_time_text(*resolved_at)),
        DetectionState::Open => detection_state_text(displayed_detection),
    };
    let quarantined_copy_kept = matches!(
        stored_detection.detection_state,
        DetectionState::Resolved {
            resolution_kind: ResolutionKind::MovedToQuarantine,
            ..
        }
    ) && !displayed_detection.file_state.file_is_present();
    if !quarantined_copy_kept {
        return plain_step(
            step_title,
            mechanism_details,
            SettledNodeState::Completed,
            status_text,
        );
    }
    TimelineStep::settled(
        step_title,
        mechanism_details,
        status_text,
        SettledStep {
            choice_rows: vec![StepChoiceRow {
                choice_description: gettext(
                    "Send the quarantined copy to ClamAV, MalwareBazaar or VirusTotal. A false \
                     positive reported to ClamAV is fixed for everyone by a later signature \
                     update.",
                ),
                chosen_action: IncidentStepAction::SubmitIncidentSample,
            }],
            ..SettledStep::without_offers(SettledNodeState::Completed)
        },
    )
}

pub fn incident_timeline(
    displayed_detection: &DisplayedDetection,
    deletion_prompt: DeletionPrompt,
    lookup_state: &SignatureLookupState,
    distribution_family: DistributionFamily,
) -> Vec<IncidentStep> {
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
    use crate::{
        host_services::threat_intel::malware_bazaar_client::MalwareFamily,
        shared_widgets::step_timeline::timeline_step_contents::{
            ButtonStyle, StepNodeState, StepPhase,
        },
    };

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

    fn review_choices(
        displayed_detection: &DisplayedDetection,
        deletion_prompt: DeletionPrompt,
    ) -> Vec<StepChoiceRow<IncidentStepAction>> {
        let review_step = incident_timeline(
            displayed_detection,
            deletion_prompt,
            &SignatureLookupState::NotLookedUp,
            DistributionFamily::NixosFamily,
        )
        .remove(REVIEW_POSITION);
        match review_step.step_phase {
            StepPhase::StepSettled(settled_step) => settled_step.choice_rows,
            StepPhase::StepRunning(_) => panic!("the review step never runs"),
        }
    }

    fn choice_actions(
        displayed_detection: &DisplayedDetection,
        deletion_prompt: DeletionPrompt,
    ) -> Vec<IncidentStepAction> {
        review_choices(displayed_detection, deletion_prompt)
            .into_iter()
            .map(|choice_row| choice_row.chosen_action)
            .filter(|chosen_action| {
                !matches!(chosen_action, IncidentStepAction::LookUpIncidentSignature)
            })
            .collect()
    }

    #[test]
    fn permanent_deletion_is_always_shown_as_destructive() {
        let deletion_choices = review_choices(&blocked_detection(), DeletionPrompt::AwaitingAnswer);
        let choice_styles = deletion_choices
            .iter()
            .map(|choice_row| choice_row.offered_choice().button_style())
            .collect::<Vec<_>>();
        assert_eq!(
            choice_styles,
            vec![
                ButtonStyle::DestructiveButton,
                ButtonStyle::PlainButton,
                ButtonStyle::PlainButton
            ]
        );
        assert_eq!(
            deletion_choices[0].chosen_action.button_label(),
            "Delete Permanently"
        );
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
            incident_steps[BLOCKED_POSITION].node_state(),
            StepNodeState::Completed
        );
        assert!(
            incident_steps[BLOCKED_POSITION]
                .status_text
                .contains("won't open")
        );
        assert_eq!(
            incident_steps[REVIEW_POSITION].node_state(),
            StepNodeState::ActNext
        );
        assert_eq!(
            incident_steps[RESOLVED_POSITION].node_state(),
            StepNodeState::AwaitingPrerequisite
        );
    }

    #[test]
    fn deleting_takes_two_explicit_choices() {
        let first_choices = choice_actions(&blocked_detection(), DeletionPrompt::NotAsked);
        assert!(first_choices.contains(&IncidentStepAction::AskIncidentDeletion));
        assert!(!first_choices.contains(&IncidentStepAction::DeleteIncidentFile));
        assert_eq!(
            choice_actions(&blocked_detection(), DeletionPrompt::AwaitingAnswer),
            vec![
                IncidentStepAction::DeleteIncidentFile,
                IncidentStepAction::CancelIncidentDeletion
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
            incident_steps[BLOCKED_POSITION].node_state(),
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
                    vec![IncidentStepAction::DismissIncident]
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
            vec![IncidentStepAction::DismissIncident]
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
    fn a_readable_file_found_on_access_is_not_blamed_on_the_schedule() {
        let displayed_detection = DisplayedDetection {
            stored_detection: StoredDetection {
                detection_sources: DetectionSources::OnAccessOnly,
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
        let lookup_actions = |lookup_state| {
            lookup_choices(lookup_state)
                .into_iter()
                .map(|choice_row| choice_row.chosen_action)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            lookup_actions(&SignatureLookupState::NotLookedUp),
            vec![IncidentStepAction::LookUpIncidentSignature]
        );
        assert_eq!(
            lookup_actions(&SignatureLookupState::KeyMissing),
            vec![
                IncidentStepAction::LookUpIncidentSignature,
                IncidentStepAction::OpenOnlineServices
            ]
        );
    }

    #[test]
    fn lookup_results_summarise_families_and_the_earliest_date() {
        let known_sample = |malware_family: &str, first_seen: &str| {
            crate::host_services::threat_intel::malware_bazaar_client::SampleSummary {
                malware_family: MalwareFamily::NamedFamily(malware_family.to_owned()),
                first_seen: SampleFirstSeen::SeenAt(first_seen.to_owned()),
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
            lookup_summary_text(&SignatureLookupState::LookupFinished(
                KnownSampleLookup::SamplesFound {
                    known_samples: vec![
                        crate::host_services::threat_intel::malware_bazaar_client::SampleSummary {
                            malware_family: MalwareFamily::UnnamedFamily,
                            first_seen: SampleFirstSeen::FirstSeenUnknown,
                            sample_tags: Vec::new(),
                        }
                    ],
                }
            )),
            Some("1 known samples. Families: unnamed family. Earliest seen: unknown.".to_owned())
        );
        assert_eq!(
            lookup_summary_text(&SignatureLookupState::NotLookedUp),
            None
        );
    }
}

use gettextrs::gettext;

use crate::{
    host_services::{
        clamav_programs::trusted_program_lookup::ClamavProgram,
        protection_evidence::host_protection_evidence::{
            ProgramTrustFinding, ProgramTrustInspection,
        },
    },
    shared_widgets::step_timeline::{
        step_evidence_builders::{CheckedCondition, evidence_row, no_guidance_step, plain_rows},
        timeline_step_contents::{SettledStep, StepActionButton, StepEvidenceRow, TimelineStep},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedProgramGroup {
    ScannerPrograms,
    UpdaterPrograms,
}

impl TrustedProgramGroup {
    fn includes_program(self, program_name: &str) -> bool {
        let scanner_names = [
            ClamavProgram::ClamdClient.program_name(),
            ClamavProgram::StandaloneScanner.program_name(),
        ];
        match self {
            Self::ScannerPrograms => scanner_names.contains(&program_name),
            Self::UpdaterPrograms => program_name == ClamavProgram::SignatureUpdater.program_name(),
        }
    }
}

fn program_trust_rows(program_trust_finding: &ProgramTrustFinding) -> Vec<StepEvidenceRow> {
    match program_trust_finding {
        ProgramTrustFinding::ReplaceableProgramIgnored {
            program_name,
            trusted_path,
            ignored_paths,
        } => std::iter::once(evidence_row(
            gettext("{program} in use").replace("{program}", program_name),
            trusted_path.clone(),
        ))
        .chain(ignored_paths.iter().map(|ignored_path| {
            evidence_row(
                gettext("Ignored {program}").replace("{program}", program_name),
                ignored_path.clone(),
            )
        }))
        .collect(),
        ProgramTrustFinding::OnlyReplaceableProgram {
            program_name,
            replaceable_paths,
        } => replaceable_paths
            .iter()
            .map(|replaceable_path| {
                evidence_row(
                    gettext("Refused {program}").replace("{program}", program_name),
                    replaceable_path.clone(),
                )
            })
            .collect(),
    }
}

const fn finding_program_name(program_trust_finding: &ProgramTrustFinding) -> &'static str {
    match program_trust_finding {
        ProgramTrustFinding::ReplaceableProgramIgnored { program_name, .. }
        | ProgramTrustFinding::OnlyReplaceableProgram { program_name, .. } => program_name,
    }
}

fn program_findings_condition<'finding>(
    program_trust_findings: impl IntoIterator<Item = &'finding ProgramTrustFinding>,
) -> CheckedCondition {
    let found_conditions = program_trust_findings
        .into_iter()
        .map(|program_trust_finding| match program_trust_finding {
            ProgramTrustFinding::OnlyReplaceableProgram { .. } => CheckedCondition::ConditionFailed,
            ProgramTrustFinding::ReplaceableProgramIgnored { .. } => {
                CheckedCondition::ReviewSuggested
            }
        })
        .collect::<Vec<_>>();
    if found_conditions.contains(&CheckedCondition::ConditionFailed) {
        CheckedCondition::ConditionFailed
    } else if found_conditions.is_empty() {
        CheckedCondition::ConditionMet
    } else {
        CheckedCondition::ReviewSuggested
    }
}

pub fn program_trust_condition(
    program_trust: &ProgramTrustInspection,
    program_group: TrustedProgramGroup,
) -> CheckedCondition {
    match program_trust {
        ProgramTrustInspection::ProgramsChecked(program_trust_findings) => {
            program_findings_condition(program_trust_findings.iter().filter(
                |program_trust_finding| {
                    program_group.includes_program(finding_program_name(program_trust_finding))
                },
            ))
        }
        ProgramTrustInspection::CheckInterrupted => CheckedCondition::EvidenceUnknown,
    }
}

fn program_trust_title(program_group: TrustedProgramGroup) -> String {
    match program_group {
        TrustedProgramGroup::ScannerPrograms => gettext("Scanner programs can be trusted"),
        TrustedProgramGroup::UpdaterPrograms => gettext("freshclam can be trusted"),
    }
}

fn program_trust_details(program_group: TrustedProgramGroup) -> String {
    match program_group {
        TrustedProgramGroup::ScannerPrograms => gettext(
            "Malware running as you could put a fake clamdscan earlier on your search path that \
             reports every file as clean. Lazaret only runs ClamAV programs that your account \
             can't replace, such as the ones installed for the whole system.",
        ),
        TrustedProgramGroup::UpdaterPrograms => gettext(
            "Malware running as you could put a fake freshclam earlier on your search path that \
             pretends to fetch new signatures. Lazaret only runs ClamAV programs that your \
             account can't replace, such as the ones installed for the whole system.",
        ),
    }
}

pub fn program_trust_step<StepAction: StepActionButton>(
    program_trust: &ProgramTrustInspection,
    program_group: TrustedProgramGroup,
) -> Option<TimelineStep<StepAction>> {
    match program_trust {
        ProgramTrustInspection::ProgramsChecked(program_trust_findings) => program_findings_step(
            &program_trust_findings
                .iter()
                .filter(|program_trust_finding| {
                    program_group.includes_program(finding_program_name(program_trust_finding))
                })
                .collect::<Vec<_>>(),
            program_group,
        ),
        ProgramTrustInspection::CheckInterrupted => Some(no_guidance_step(
            program_trust_title(program_group),
            program_trust_details(program_group),
            program_trust_condition(program_trust, program_group).node_state(),
            gettext("Unknown, because checking the ClamAV programs stopped before it finished"),
        )),
    }
}

fn program_findings_step<StepAction: StepActionButton>(
    program_trust_findings: &[&ProgramTrustFinding],
    program_group: TrustedProgramGroup,
) -> Option<TimelineStep<StepAction>> {
    if program_trust_findings.is_empty() {
        return None;
    }
    let any_program_refused = program_trust_findings.iter().any(|program_trust_finding| {
        matches!(
            program_trust_finding,
            ProgramTrustFinding::OnlyReplaceableProgram { .. }
        )
    });
    let node_state =
        program_findings_condition(program_trust_findings.iter().copied()).node_state();
    let status_text = if any_program_refused {
        gettext("A ClamAV program can be replaced by your account, so Lazaret refuses to run it")
    } else {
        gettext(
            "A ClamAV program in your account shadows the system copy. Lazaret ignores it, but \
             check where it came from",
        )
    };
    Some(TimelineStep::settled(
        program_trust_title(program_group),
        program_trust_details(program_group),
        status_text,
        SettledStep {
            evidence_rows: plain_rows(
                program_trust_findings
                    .iter()
                    .flat_map(|program_trust_finding| program_trust_rows(program_trust_finding)),
            ),
            ..SettledStep::without_offers(node_state)
        },
    ))
}

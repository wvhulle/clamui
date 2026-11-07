use gettextrs::gettext;

use crate::{
    application_window::protection_evidence_refresh::GatheredEvidence,
    signatures::signature_sources_page::source_check_results::{
        AuditCheck, AuditStatus, overall_check_status,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceChecks {
    ChecksRunning,
    ChecksFinished(Vec<AuditCheck>),
}

impl SourceChecks {
    pub fn overall_status(&self) -> AuditStatus {
        match self {
            Self::ChecksRunning => AuditStatus::CheckInProgress,
            Self::ChecksFinished(source_checks) => overall_check_status(source_checks),
        }
    }

    pub const fn checks_running(&self) -> bool {
        match self {
            Self::ChecksRunning => true,
            Self::ChecksFinished(_) => false,
        }
    }
}

fn abuse_ch_key_purpose_text() -> String {
    gettext(
        "URLhaus signatures through fangfrisch, MalwareBazaar lookups and MalwareBazaar uploads \
         all use this key. It is kept and edited in Preferences, under Online Services.",
    )
}

pub fn abuse_ch_key_subtitle(gathered_evidence: &GatheredEvidence) -> String {
    let key_status_text = match gathered_evidence {
        GatheredEvidence::NotGatheredYet => gettext("Checking the API key…"),
        GatheredEvidence::Gathered {
            protection_evidence,
            ..
        } => protection_evidence
            .lookup_key_statuses
            .abuse_ch_key
            .status_text(),
    };
    format!("{}\n{key_status_text}", abuse_ch_key_purpose_text())
}

pub const fn abuse_ch_key_needs_attention(gathered_evidence: &GatheredEvidence) -> bool {
    match gathered_evidence {
        GatheredEvidence::NotGatheredYet => false,
        GatheredEvidence::Gathered {
            protection_evidence,
            ..
        } => protection_evidence
            .lookup_key_statuses
            .abuse_ch_key
            .needs_attention(),
    }
}

#[cfg(test)]
mod signature_sources_presentation_tests {
    use super::*;
    use crate::host_services::{
        protection_evidence::{
            host_protection_evidence::ProtectionEvidence,
            protection_evidence_fixtures::{REFERENCE_MOMENT, healthy_evidence},
        },
        threat_intel::service_key_status::{LookupKeyStatuses, ServiceKeyStatus},
    };

    fn gathered_with_abuse_ch_key(abuse_ch_key: ServiceKeyStatus) -> GatheredEvidence {
        GatheredEvidence::Gathered {
            protection_evidence: Box::new(ProtectionEvidence {
                lookup_key_statuses: LookupKeyStatuses {
                    abuse_ch_key,
                    virustotal_key: ServiceKeyStatus::KeyMissing,
                },
                ..healthy_evidence()
            }),
            gathered_at: REFERENCE_MOMENT,
        }
    }

    #[test]
    fn the_abuse_ch_key_row_reads_like_the_online_services_preferences() {
        let configured = gathered_with_abuse_ch_key(ServiceKeyStatus::KeyConfigured);
        assert!(abuse_ch_key_subtitle(&configured).ends_with("\nAPI key configured"));
        assert!(!abuse_ch_key_needs_attention(&configured));
        let missing = gathered_with_abuse_ch_key(ServiceKeyStatus::KeyMissing);
        assert!(abuse_ch_key_subtitle(&missing).ends_with("\nNo API key, so this service is off"));
        assert!(!abuse_ch_key_needs_attention(&missing));
        let unreadable = gathered_with_abuse_ch_key(ServiceKeyStatus::KeyUnreadable {
            failure_text: "permission denied".to_owned(),
        });
        assert!(
            abuse_ch_key_subtitle(&unreadable)
                .ends_with("\nThe API key can't be read: permission denied")
        );
        assert!(abuse_ch_key_needs_attention(&unreadable));
        assert!(
            abuse_ch_key_subtitle(&GatheredEvidence::NotGatheredYet)
                .ends_with("\nChecking the API key…")
        );
    }

    #[test]
    fn running_checks_show_progress_until_their_results_arrive() {
        assert_eq!(
            SourceChecks::ChecksRunning.overall_status(),
            AuditStatus::CheckInProgress
        );
        assert!(SourceChecks::ChecksRunning.checks_running());
        let finished = SourceChecks::ChecksFinished(vec![AuditCheck::new(
            "Sanesecurity".to_owned(),
            AuditStatus::CheckPassed,
            "In use".to_owned(),
        )]);
        assert_eq!(finished.overall_status(), AuditStatus::CheckPassed);
        assert!(!finished.checks_running());
    }
}

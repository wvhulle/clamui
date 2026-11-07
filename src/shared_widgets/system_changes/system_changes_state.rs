use crate::{
    host_services::settings_helper::helper_audit_records::{
        AuditedAction, HelperAuditEntry, newest_helper_audit_entries,
    },
    shared_widgets::{
        loading_indicators::{LOAD_FAILED_PAGE_NAME, LOADED_PAGE_NAME, LOADING_PAGE_NAME},
        step_timeline::runtime_reduction_steps::ReducedSettingGroup,
    },
};

pub const SYSTEM_CHANGE_LIMIT: usize = 200;

#[derive(Debug, thiserror::Error)]
pub enum SystemChangesReadFailure {
    #[error("the system journal can't be read: {0}")]
    JournalUnreadable(#[from] systemd::Error),
    #[error("the system journal read stopped unexpectedly: {0}")]
    JournalReadInterrupted(#[from] tokio::task::JoinError),
}

#[derive(Debug)]
pub enum SystemChangesView {
    SystemChangesLoading,
    SystemChangesLoaded,
    SystemChangesFailed(SystemChangesReadFailure),
}

impl SystemChangesView {
    pub const fn placeholder_page_name(&self) -> &'static str {
        match self {
            Self::SystemChangesLoading => LOADING_PAGE_NAME,
            Self::SystemChangesLoaded => LOADED_PAGE_NAME,
            Self::SystemChangesFailed(_) => LOAD_FAILED_PAGE_NAME,
        }
    }
}

pub async fn read_system_changes() -> Result<Vec<HelperAuditEntry>, SystemChangesReadFailure> {
    tokio::task::spawn_blocking(|| newest_helper_audit_entries(SYSTEM_CHANGE_LIMIT))
        .await
        .map_err(SystemChangesReadFailure::from)
        .and_then(|journal_outcome| journal_outcome.map_err(SystemChangesReadFailure::from))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditTopic {
    EngineChanges,
    OnAccessChanges,
    TrustChanges,
}

fn changes_settings_of(audit_entry: &HelperAuditEntry, setting_group: ReducedSettingGroup) -> bool {
    audit_entry
        .changed_setting_keys()
        .into_iter()
        .any(|setting_key| setting_group.includes_setting(setting_key))
}

pub fn audit_entry_concerns_topic(audit_entry: &HelperAuditEntry, audit_topic: AuditTopic) -> bool {
    match (&audit_entry.audited_action, audit_topic) {
        (AuditedAction::ChangeSettings, AuditTopic::EngineChanges) => {
            changes_settings_of(audit_entry, ReducedSettingGroup::EngineSettings)
                || audit_entry.changed_setting_keys().is_empty()
        }
        (AuditedAction::ChangeSettings, AuditTopic::OnAccessChanges) => {
            changes_settings_of(audit_entry, ReducedSettingGroup::OnAccessSettings)
        }
        (
            AuditedAction::TrustFile { .. }
            | AuditedAction::IgnoreSignature { .. }
            | AuditedAction::ForgetTrustedFile { .. }
            | AuditedAction::StopIgnoringSignature { .. },
            audit_topic,
        ) => audit_topic == AuditTopic::TrustChanges,
        (AuditedAction::UnrecognizedAction { .. }, audit_topic) => {
            audit_topic == AuditTopic::EngineChanges
        }
        (AuditedAction::ChangeSettings, AuditTopic::TrustChanges) => false,
    }
}

pub fn audit_entries_for_topic(
    audit_entries: Vec<HelperAuditEntry>,
    audit_topic: AuditTopic,
) -> Vec<HelperAuditEntry> {
    audit_entries
        .into_iter()
        .filter(|audit_entry| audit_entry_concerns_topic(audit_entry, audit_topic))
        .collect()
}

#[cfg(test)]
mod system_changes_state_tests {
    use jiff::Timestamp;

    use super::*;
    use crate::host_services::settings_helper::helper_audit_records::{
        AuditedOutcome, RecordedReduction, Requester,
    };

    fn audit_entry(audited_action: AuditedAction, action_subject: &str) -> HelperAuditEntry {
        HelperAuditEntry {
            recorded_at: Timestamp::UNIX_EPOCH,
            audited_action,
            action_subject: action_subject.to_owned(),
            audited_outcome: AuditedOutcome::ActionApplied,
            requester: Requester::UnknownUser,
            recorded_reduction: RecordedReduction::ReductionNotRecorded,
        }
    }

    fn sample_entries() -> Vec<HelperAuditEntry> {
        vec![
            audit_entry(AuditedAction::ChangeSettings, "OnAccessPrevention no"),
            audit_entry(AuditedAction::ChangeSettings, "DetectPUA no"),
            audit_entry(
                AuditedAction::ChangeSettings,
                "MaxThreads 4, OnAccessMaxFileSize 5M",
            ),
            audit_entry(
                AuditedAction::IgnoreSignature {
                    signature_name: "Win.Test".to_owned(),
                },
                "ignore every detection named Win.Test",
            ),
            audit_entry(
                AuditedAction::ForgetTrustedFile {
                    sha256_hex: "ab".repeat(32),
                },
                "forget a trusted file",
            ),
            audit_entry(
                AuditedAction::UnrecognizedAction {
                    action_name: "FutureAction".to_owned(),
                },
                "something newer",
            ),
        ]
    }

    fn kept_subjects(audit_topic: AuditTopic) -> Vec<String> {
        audit_entries_for_topic(sample_entries(), audit_topic)
            .into_iter()
            .map(|audit_entry| audit_entry.action_subject)
            .collect()
    }

    #[test]
    fn engine_changes_keep_only_entries_with_an_engine_key() {
        assert_eq!(
            kept_subjects(AuditTopic::EngineChanges),
            vec![
                "DetectPUA no",
                "MaxThreads 4, OnAccessMaxFileSize 5M",
                "something newer"
            ]
        );
    }

    #[test]
    fn on_access_changes_keep_only_entries_with_an_on_access_key() {
        assert_eq!(
            kept_subjects(AuditTopic::OnAccessChanges),
            vec![
                "OnAccessPrevention no",
                "MaxThreads 4, OnAccessMaxFileSize 5M"
            ]
        );
    }

    #[test]
    fn trust_changes_belong_to_the_trusted_detections_page_only() {
        assert_eq!(
            kept_subjects(AuditTopic::TrustChanges),
            vec![
                "ignore every detection named Win.Test",
                "forget a trusted file"
            ]
        );
    }

    #[test]
    fn every_audit_entry_has_a_page() {
        sample_entries().iter().for_each(|audit_entry| {
            assert!(
                [
                    AuditTopic::EngineChanges,
                    AuditTopic::OnAccessChanges,
                    AuditTopic::TrustChanges
                ]
                .into_iter()
                .any(|audit_topic| audit_entry_concerns_topic(audit_entry, audit_topic)),
                "{}",
                audit_entry.action_subject
            );
        });
    }

    #[test]
    fn each_view_names_its_placeholder() {
        assert_eq!(
            SystemChangesView::SystemChangesLoading.placeholder_page_name(),
            LOADING_PAGE_NAME
        );
        assert_eq!(
            SystemChangesView::SystemChangesLoaded.placeholder_page_name(),
            LOADED_PAGE_NAME
        );
    }
}

use crate::{
    host_services::settings_helper::helper_audit_records::{
        HelperAuditEntry, newest_helper_audit_entries,
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

pub fn audit_entry_concerns_settings(
    audit_entry: &HelperAuditEntry,
    setting_group: ReducedSettingGroup,
) -> bool {
    audit_entry
        .changed_setting_keys()
        .into_iter()
        .any(|setting_key| setting_group.includes_setting(setting_key))
}

pub fn audit_entries_for_settings(
    audit_entries: Vec<HelperAuditEntry>,
    setting_group: ReducedSettingGroup,
) -> Vec<HelperAuditEntry> {
    audit_entries
        .into_iter()
        .filter(|audit_entry| audit_entry_concerns_settings(audit_entry, setting_group))
        .collect()
}

#[cfg(test)]
mod system_changes_state_tests {
    use jiff::Timestamp;

    use super::*;
    use crate::host_services::settings_helper::helper_audit_records::{
        AuditedAction, AuditedOutcome, RecordedReduction, Requester,
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
        ]
    }

    fn kept_subjects(setting_group: ReducedSettingGroup) -> Vec<String> {
        audit_entries_for_settings(sample_entries(), setting_group)
            .into_iter()
            .map(|audit_entry| audit_entry.action_subject)
            .collect()
    }

    #[test]
    fn engine_changes_keep_only_entries_with_an_engine_key() {
        assert_eq!(
            kept_subjects(ReducedSettingGroup::EngineSettings),
            vec!["DetectPUA no", "MaxThreads 4, OnAccessMaxFileSize 5M"]
        );
    }

    #[test]
    fn on_access_changes_keep_only_entries_with_an_on_access_key() {
        assert_eq!(
            kept_subjects(ReducedSettingGroup::OnAccessSettings),
            vec![
                "OnAccessPrevention no",
                "MaxThreads 4, OnAccessMaxFileSize 5M"
            ]
        );
    }

    #[test]
    fn trust_changes_belong_to_no_settings_page() {
        assert!(
            kept_subjects(ReducedSettingGroup::AllSettings)
                .iter()
                .all(|kept_subject| !kept_subject.starts_with("ignore"))
        );
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

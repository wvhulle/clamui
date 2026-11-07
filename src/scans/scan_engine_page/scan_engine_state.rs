use crate::{
    scans::scan_engine_page::clamd_socket_ownership::ClamdSocketOwnership,
    shared_widgets::engine_settings::engine_settings_sections::EngineSettingsNotice,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanEnginePageOutput {
    EvidenceRefreshRequested,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClamdSocketView {
    SocketInspecting,
    SocketInspected(ClamdSocketOwnership),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingsChangeFollowUp {
    ReloadChangesAndEvidence,
    NothingToReload,
}

pub const fn settings_change_follow_up(
    settings_notice: &EngineSettingsNotice,
) -> SettingsChangeFollowUp {
    match settings_notice {
        EngineSettingsNotice::LiveChangeReported(_) => {
            SettingsChangeFollowUp::ReloadChangesAndEvidence
        }
        EngineSettingsNotice::ChangeSnippetCopied
        | EngineSettingsNotice::StaleConfirmationDropped => SettingsChangeFollowUp::NothingToReload,
    }
}

#[cfg(test)]
mod scan_engine_state_tests {
    use super::*;
    use crate::host_services::settings_helper::live_settings_client::LiveChangeOutcome;

    #[test]
    fn a_live_change_reloads_the_audit_and_the_evidence() {
        assert_eq!(
            settings_change_follow_up(&EngineSettingsNotice::LiveChangeReported(
                LiveChangeOutcome::SettingsApplied
            )),
            SettingsChangeFollowUp::ReloadChangesAndEvidence
        );
        assert_eq!(
            settings_change_follow_up(&EngineSettingsNotice::LiveChangeReported(
                LiveChangeOutcome::PreviousRestored
            )),
            SettingsChangeFollowUp::ReloadChangesAndEvidence
        );
    }

    #[test]
    fn copying_a_snippet_reloads_nothing() {
        assert_eq!(
            settings_change_follow_up(&EngineSettingsNotice::ChangeSnippetCopied),
            SettingsChangeFollowUp::NothingToReload
        );
        assert_eq!(
            settings_change_follow_up(&EngineSettingsNotice::StaleConfirmationDropped),
            SettingsChangeFollowUp::NothingToReload
        );
    }
}

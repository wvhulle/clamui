use crate::application_window::{
    application_pages::ApplicationPage,
    sidebar_area_status::{SidebarAreaSummary, first_area_needing_attention},
};

pub const PAGE_BEFORE_FIRST_EVIDENCE: ApplicationPage = ApplicationPage::Detections;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartPageRequest {
    RequestedPage(ApplicationPage),
    FirstAreaNeedingAttention,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartPageState {
    AwaitingFirstEvidence,
    StartPageSettled,
    UserNavigated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartPageTransition {
    pub shown_page: ApplicationPage,
    pub next_state: StartPageState,
}

pub const fn initial_start_page(start_page_request: StartPageRequest) -> StartPageTransition {
    match start_page_request {
        StartPageRequest::RequestedPage(requested_page) => StartPageTransition {
            shown_page: requested_page,
            next_state: StartPageState::StartPageSettled,
        },
        StartPageRequest::FirstAreaNeedingAttention => StartPageTransition {
            shown_page: PAGE_BEFORE_FIRST_EVIDENCE,
            next_state: StartPageState::AwaitingFirstEvidence,
        },
    }
}

pub fn start_page_after_evidence(
    start_page_state: StartPageState,
    visible_page: ApplicationPage,
    area_summaries: &[SidebarAreaSummary],
) -> StartPageTransition {
    match start_page_state {
        StartPageState::AwaitingFirstEvidence => StartPageTransition {
            shown_page: first_area_needing_attention(area_summaries),
            next_state: StartPageState::StartPageSettled,
        },
        StartPageState::StartPageSettled | StartPageState::UserNavigated => StartPageTransition {
            shown_page: visible_page,
            next_state: start_page_state,
        },
    }
}

#[cfg(test)]
mod start_page_choice_tests {
    use super::*;
    use crate::application_window::sidebar_area_status::{AreaStatus, AreaSummary};

    fn summaries_with_failing_engine() -> Vec<SidebarAreaSummary> {
        [
            (ApplicationPage::SignatureSources, AreaStatus::AreaHealthy),
            (ApplicationPage::ScanEngine, AreaStatus::AreaFailing),
            (ApplicationPage::Detections, AreaStatus::AreaHealthy),
        ]
        .into_iter()
        .map(|(application_page, area_status)| SidebarAreaSummary {
            application_page,
            area_summary: AreaSummary {
                area_status,
                live_state_text: String::new(),
            },
        })
        .collect()
    }

    #[test]
    fn without_a_requested_page_detections_show_until_the_first_evidence() {
        assert_eq!(
            initial_start_page(StartPageRequest::FirstAreaNeedingAttention),
            StartPageTransition {
                shown_page: ApplicationPage::Detections,
                next_state: StartPageState::AwaitingFirstEvidence,
            }
        );
    }

    #[test]
    fn the_first_evidence_moves_to_the_first_area_needing_attention_once() {
        let first_move = start_page_after_evidence(
            StartPageState::AwaitingFirstEvidence,
            ApplicationPage::Detections,
            &summaries_with_failing_engine(),
        );
        assert_eq!(
            first_move,
            StartPageTransition {
                shown_page: ApplicationPage::ScanEngine,
                next_state: StartPageState::StartPageSettled,
            }
        );
        assert_eq!(
            start_page_after_evidence(
                first_move.next_state,
                ApplicationPage::Quarantine,
                &summaries_with_failing_engine(),
            )
            .shown_page,
            ApplicationPage::Quarantine
        );
    }

    #[test]
    fn a_healthy_host_stays_on_detections() {
        assert_eq!(
            start_page_after_evidence(
                StartPageState::AwaitingFirstEvidence,
                ApplicationPage::Detections,
                &[],
            )
            .shown_page,
            ApplicationPage::Detections
        );
    }

    #[test]
    fn a_user_who_already_navigated_is_never_moved() {
        assert_eq!(
            start_page_after_evidence(
                StartPageState::UserNavigated,
                ApplicationPage::Submissions,
                &summaries_with_failing_engine(),
            ),
            StartPageTransition {
                shown_page: ApplicationPage::Submissions,
                next_state: StartPageState::UserNavigated,
            }
        );
    }

    #[test]
    fn a_requested_page_is_kept_when_the_evidence_arrives() {
        let requested = initial_start_page(StartPageRequest::RequestedPage(
            ApplicationPage::OnlineLookups,
        ));
        assert_eq!(
            start_page_after_evidence(
                requested.next_state,
                requested.shown_page,
                &summaries_with_failing_engine(),
            )
            .shown_page,
            ApplicationPage::OnlineLookups
        );
    }
}

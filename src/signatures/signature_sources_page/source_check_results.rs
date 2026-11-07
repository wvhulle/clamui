use gettextrs::gettext;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditStatus {
    CheckPassed,
    NeedsReview,
    CheckFailed,
    StatusUnknown,
    CheckSkipped,
    CheckInProgress,
}

const STATUS_SEVERITY_ORDER: [AuditStatus; 6] = [
    AuditStatus::CheckFailed,
    AuditStatus::NeedsReview,
    AuditStatus::StatusUnknown,
    AuditStatus::CheckPassed,
    AuditStatus::CheckSkipped,
    AuditStatus::CheckInProgress,
];

impl AuditStatus {
    pub fn status_label(self) -> String {
        match self {
            Self::CheckPassed => gettext("Pass"),
            Self::NeedsReview => gettext("Warning"),
            Self::CheckFailed => gettext("Fail"),
            Self::StatusUnknown => gettext("Unknown"),
            Self::CheckSkipped => gettext("Skipped"),
            Self::CheckInProgress => gettext("Checking"),
        }
    }

    pub fn status_icon_name(self) -> &'static str {
        match self {
            Self::CheckPassed => "object-select-symbolic",
            Self::NeedsReview => "dialog-warning-symbolic",
            Self::CheckFailed => "dialog-error-symbolic",
            Self::StatusUnknown => "dialog-question-symbolic",
            Self::CheckSkipped => "list-remove-symbolic",
            Self::CheckInProgress => "view-refresh-symbolic",
        }
    }

    pub fn status_style_class(self) -> &'static str {
        match self {
            Self::CheckPassed => "success",
            Self::NeedsReview => "warning",
            Self::CheckFailed => "error",
            Self::StatusUnknown | Self::CheckSkipped | Self::CheckInProgress => "dim-label",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckGuidance {
    RecommendationText(String),
    SuggestedCommand(&'static str),
    DocumentationLink(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditCheck {
    pub check_name: String,
    pub check_status: AuditStatus,
    pub status_detail: String,
    pub check_guidance: Vec<CheckGuidance>,
    pub starts_collapsed: bool,
}

impl AuditCheck {
    pub fn new(check_name: String, check_status: AuditStatus, status_detail: String) -> Self {
        Self {
            check_name,
            check_status,
            status_detail,
            check_guidance: Vec::new(),
            starts_collapsed: false,
        }
    }

    pub const fn starting_collapsed(mut self) -> Self {
        self.starts_collapsed = true;
        self
    }

    pub fn with_recommendation(mut self, recommendation_text: String) -> Self {
        self.check_guidance
            .push(CheckGuidance::RecommendationText(recommendation_text));
        self
    }

    pub fn with_suggested_commands(
        mut self,
        suggested_commands: impl IntoIterator<Item = &'static str>,
    ) -> Self {
        self.check_guidance.extend(
            suggested_commands
                .into_iter()
                .map(CheckGuidance::SuggestedCommand),
        );
        self
    }

    pub fn with_documentation(mut self, documentation_url: &'static str) -> Self {
        self.check_guidance
            .push(CheckGuidance::DocumentationLink(documentation_url));
        self
    }

    pub fn expanded_by_default(&self) -> bool {
        !self.starts_collapsed
            && self.check_status != AuditStatus::CheckPassed
            && self.check_guidance.iter().any(|check_guidance| {
                !matches!(check_guidance, CheckGuidance::DocumentationLink(_))
            })
    }
}

pub fn overall_check_status(audit_checks: &[AuditCheck]) -> AuditStatus {
    STATUS_SEVERITY_ORDER
        .into_iter()
        .find(|candidate_status| {
            audit_checks
                .iter()
                .any(|audit_check| audit_check.check_status == *candidate_status)
        })
        .unwrap_or(AuditStatus::StatusUnknown)
}

#[cfg(test)]
mod source_check_results_tests {
    use super::*;

    fn check_with_status(check_status: AuditStatus) -> AuditCheck {
        AuditCheck::new(String::new(), check_status, String::new())
    }

    #[test]
    fn the_most_severe_status_decides_the_section_icon() {
        assert_eq!(
            overall_check_status(&[
                check_with_status(AuditStatus::CheckPassed),
                check_with_status(AuditStatus::StatusUnknown),
                check_with_status(AuditStatus::CheckFailed),
            ]),
            AuditStatus::CheckFailed
        );
        assert_eq!(
            overall_check_status(&[
                check_with_status(AuditStatus::CheckSkipped),
                check_with_status(AuditStatus::CheckPassed),
            ]),
            AuditStatus::CheckPassed
        );
        assert_eq!(overall_check_status(&[]), AuditStatus::StatusUnknown);
    }

    #[test]
    fn only_actionable_unpassed_checks_start_expanded() {
        let documentation_url = "https://docs.clamav.net/";
        assert!(
            check_with_status(AuditStatus::NeedsReview)
                .with_recommendation("Review it".to_owned())
                .expanded_by_default()
        );
        assert!(
            check_with_status(AuditStatus::CheckSkipped)
                .with_suggested_commands(["sudo systemctl start fail2ban"])
                .expanded_by_default()
        );
        assert!(
            !check_with_status(AuditStatus::CheckSkipped)
                .with_documentation(documentation_url)
                .expanded_by_default()
        );
        assert!(
            !check_with_status(AuditStatus::CheckPassed)
                .with_recommendation("Review it".to_owned())
                .expanded_by_default()
        );
    }
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditCategory {
    ClamavHealth,
    FirewallProtection,
    AccessControl,
    AutomaticUpdates,
    IntrusionDetection,
    SshSecurity,
    PortmasterService,
    DeepScans,
}

pub const ALL_AUDIT_CATEGORIES: [AuditCategory; 8] = [
    AuditCategory::ClamavHealth,
    AuditCategory::FirewallProtection,
    AuditCategory::AccessControl,
    AuditCategory::AutomaticUpdates,
    AuditCategory::IntrusionDetection,
    AuditCategory::SshSecurity,
    AuditCategory::PortmasterService,
    AuditCategory::DeepScans,
];

impl AuditCategory {
    pub fn section_title(self) -> String {
        match self {
            Self::ClamavHealth => gettext("ClamAV Health"),
            Self::FirewallProtection => gettext("Firewall"),
            Self::AccessControl => gettext("Access Control"),
            Self::AutomaticUpdates => gettext("Automatic Updates"),
            Self::IntrusionDetection => gettext("Intrusion Detection"),
            Self::SshSecurity => gettext("SSH Security"),
            Self::PortmasterService => gettext("Portmaster"),
            Self::DeepScans => gettext("Deep scans"),
        }
    }

    pub fn section_position(self) -> usize {
        ALL_AUDIT_CATEGORIES
            .iter()
            .position(|audit_category| *audit_category == self)
            .unwrap_or_default()
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
}

impl AuditCheck {
    pub fn new(check_name: String, check_status: AuditStatus, status_detail: String) -> Self {
        Self {
            check_name,
            check_status,
            status_detail,
            check_guidance: Vec::new(),
        }
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
        self.check_status != AuditStatus::CheckPassed
            && self.check_guidance.iter().any(|check_guidance| {
                !matches!(check_guidance, CheckGuidance::DocumentationLink(_))
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditSection {
    pub audit_category: AuditCategory,
    pub section_checks: Vec<AuditCheck>,
}

impl AuditSection {
    pub fn awaiting_checks(audit_category: AuditCategory) -> Self {
        Self {
            audit_category,
            section_checks: Vec::new(),
        }
    }

    pub fn overall_status(&self) -> AuditStatus {
        if self.section_checks.is_empty() {
            AuditStatus::CheckInProgress
        } else {
            overall_check_status(&self.section_checks)
        }
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuditStatusCounts {
    pub failed_count: u32,
    pub review_count: u32,
    pub passed_count: u32,
    pub unverified_count: u32,
}

impl AuditStatusCounts {
    pub fn including_section(self, audit_section: &AuditSection) -> Self {
        audit_section
            .section_checks
            .iter()
            .fold(self, |status_counts, audit_check| {
                status_counts.including_status(audit_check.check_status)
            })
    }

    fn including_status(self, check_status: AuditStatus) -> Self {
        match check_status {
            AuditStatus::CheckFailed => Self {
                failed_count: self.failed_count + 1,
                ..self
            },
            AuditStatus::NeedsReview => Self {
                review_count: self.review_count + 1,
                ..self
            },
            AuditStatus::CheckPassed => Self {
                passed_count: self.passed_count + 1,
                ..self
            },
            AuditStatus::StatusUnknown
            | AuditStatus::CheckSkipped
            | AuditStatus::CheckInProgress => Self {
                unverified_count: self.unverified_count + 1,
                ..self
            },
        }
    }
}

#[cfg(test)]
mod audit_report_model_tests {
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
                .with_suggested_commands(["sudo lynis audit system"])
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

    #[test]
    fn a_section_without_results_is_still_in_progress() {
        assert_eq!(
            AuditSection::awaiting_checks(AuditCategory::SshSecurity).overall_status(),
            AuditStatus::CheckInProgress
        );
    }

    #[test]
    fn counts_group_unknown_and_skipped_checks_together() {
        let audit_section = AuditSection {
            audit_category: AuditCategory::FirewallProtection,
            section_checks: vec![
                check_with_status(AuditStatus::CheckFailed),
                check_with_status(AuditStatus::NeedsReview),
                check_with_status(AuditStatus::NeedsReview),
                check_with_status(AuditStatus::CheckPassed),
                check_with_status(AuditStatus::StatusUnknown),
                check_with_status(AuditStatus::CheckSkipped),
            ],
        };
        assert_eq!(
            AuditStatusCounts::default().including_section(&audit_section),
            AuditStatusCounts {
                failed_count: 1,
                review_count: 2,
                passed_count: 1,
                unverified_count: 2,
            }
        );
    }

    #[test]
    fn category_positions_follow_the_display_order() {
        ALL_AUDIT_CATEGORIES
            .into_iter()
            .enumerate()
            .for_each(|positioned_category| {
                assert_eq!(
                    positioned_category.1.section_position(),
                    positioned_category.0
                );
            });
    }
}

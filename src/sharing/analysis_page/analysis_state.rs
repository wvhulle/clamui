use crate::{
    host_services::threat_intel::service_key_storage::ThreatIntelService,
    sharing::analysis_page::analysis_presentation::ServiceKeyStatus,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisPageOutput {
    EvidenceRefreshRequested,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LookupKeyStatuses {
    pub abuse_ch_key: ServiceKeyStatus,
    pub virustotal_key: ServiceKeyStatus,
}

impl LookupKeyStatuses {
    pub const fn while_checking() -> Self {
        Self {
            abuse_ch_key: ServiceKeyStatus::KeyChecking,
            virustotal_key: ServiceKeyStatus::KeyChecking,
        }
    }

    pub fn with_service_status(
        self,
        threat_intel_service: ThreatIntelService,
        key_status: ServiceKeyStatus,
    ) -> Self {
        match threat_intel_service {
            ThreatIntelService::AbuseChService => Self {
                abuse_ch_key: key_status,
                ..self
            },
            ThreatIntelService::VirusTotalService => Self {
                virustotal_key: key_status,
                ..self
            },
        }
    }
}

#[cfg(test)]
mod analysis_state_tests {
    use super::*;

    #[test]
    fn each_key_reading_updates_only_its_own_service() {
        let key_statuses = LookupKeyStatuses::while_checking()
            .with_service_status(
                ThreatIntelService::VirusTotalService,
                ServiceKeyStatus::KeyMissing,
            )
            .with_service_status(
                ThreatIntelService::AbuseChService,
                ServiceKeyStatus::KeyConfigured,
            );
        assert_eq!(
            key_statuses,
            LookupKeyStatuses {
                abuse_ch_key: ServiceKeyStatus::KeyConfigured,
                virustotal_key: ServiceKeyStatus::KeyMissing,
            }
        );
    }
}

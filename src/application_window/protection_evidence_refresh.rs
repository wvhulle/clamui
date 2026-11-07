use jiff::Timestamp;

use crate::host_services::protection_evidence::host_protection_evidence::ProtectionEvidence;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceRefresh {
    NothingRunning,
    GatheringOnce,
    GatheringThenAgain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceRefreshTrigger {
    RefreshRequested,
    WatchedUnitChanged,
    GatheringFinished,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatheringStart {
    StartGathering,
    KeepWaiting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceRefreshTransition {
    pub next_refresh: EvidenceRefresh,
    pub gathering_start: GatheringStart,
}

#[derive(Clone, Debug)]
pub enum GatheredEvidence {
    NotGatheredYet,
    Gathered {
        protection_evidence: Box<ProtectionEvidence>,
        gathered_at: Timestamp,
    },
}

impl EvidenceRefresh {
    pub const fn is_running(self) -> bool {
        match self {
            Self::NothingRunning => false,
            Self::GatheringOnce | Self::GatheringThenAgain => true,
        }
    }

    pub const fn after_trigger(
        self,
        refresh_trigger: EvidenceRefreshTrigger,
    ) -> EvidenceRefreshTransition {
        match (refresh_trigger, self) {
            (
                EvidenceRefreshTrigger::RefreshRequested
                | EvidenceRefreshTrigger::WatchedUnitChanged,
                Self::NothingRunning,
            )
            | (EvidenceRefreshTrigger::GatheringFinished, Self::GatheringThenAgain) => {
                EvidenceRefreshTransition {
                    next_refresh: Self::GatheringOnce,
                    gathering_start: GatheringStart::StartGathering,
                }
            }
            (
                EvidenceRefreshTrigger::RefreshRequested
                | EvidenceRefreshTrigger::WatchedUnitChanged,
                Self::GatheringOnce | Self::GatheringThenAgain,
            ) => EvidenceRefreshTransition {
                next_refresh: Self::GatheringThenAgain,
                gathering_start: GatheringStart::KeepWaiting,
            },
            (
                EvidenceRefreshTrigger::GatheringFinished,
                Self::GatheringOnce | Self::NothingRunning,
            ) => EvidenceRefreshTransition {
                next_refresh: Self::NothingRunning,
                gathering_start: GatheringStart::KeepWaiting,
            },
        }
    }
}

#[cfg(test)]
mod protection_evidence_refresh_tests {
    use super::*;

    #[test]
    fn a_unit_change_while_idle_starts_gathering() {
        assert_eq!(
            EvidenceRefresh::NothingRunning
                .after_trigger(EvidenceRefreshTrigger::WatchedUnitChanged),
            EvidenceRefreshTransition {
                next_refresh: EvidenceRefresh::GatheringOnce,
                gathering_start: GatheringStart::StartGathering,
            }
        );
    }

    #[test]
    fn a_unit_change_while_gathering_gathers_once_more_afterwards() {
        let queued_transition = EvidenceRefresh::GatheringOnce
            .after_trigger(EvidenceRefreshTrigger::WatchedUnitChanged);
        assert_eq!(
            queued_transition,
            EvidenceRefreshTransition {
                next_refresh: EvidenceRefresh::GatheringThenAgain,
                gathering_start: GatheringStart::KeepWaiting,
            }
        );
        assert_eq!(
            queued_transition
                .next_refresh
                .after_trigger(EvidenceRefreshTrigger::RefreshRequested)
                .next_refresh,
            EvidenceRefresh::GatheringThenAgain
        );
        assert_eq!(
            queued_transition
                .next_refresh
                .after_trigger(EvidenceRefreshTrigger::GatheringFinished),
            EvidenceRefreshTransition {
                next_refresh: EvidenceRefresh::GatheringOnce,
                gathering_start: GatheringStart::StartGathering,
            }
        );
    }

    #[test]
    fn finishing_a_single_gathering_goes_idle() {
        let finished_transition =
            EvidenceRefresh::GatheringOnce.after_trigger(EvidenceRefreshTrigger::GatheringFinished);
        assert_eq!(
            finished_transition,
            EvidenceRefreshTransition {
                next_refresh: EvidenceRefresh::NothingRunning,
                gathering_start: GatheringStart::KeepWaiting,
            }
        );
        assert!(!finished_transition.next_refresh.is_running());
    }
}

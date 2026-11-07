#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanSlot {
    SlotFree,
    HeldByManualScan,
    HeldByDeviceScan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanSlotEvent {
    ManualScanStarted,
    ManualScanEnded,
    DeviceScanRequested,
    DeviceScanEnded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanSlotReply {
    NoReplyNeeded,
    DeviceScanGranted,
    DeviceScanRefused,
    DeviceScanRevoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanSlotTransition {
    pub next_slot: ScanSlot,
    pub slot_reply: ScanSlotReply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceScanActivity {
    DeviceScanIdle,
    DeviceScanHoldsSlot,
}

const fn transition_to(next_slot: ScanSlot, slot_reply: ScanSlotReply) -> ScanSlotTransition {
    ScanSlotTransition {
        next_slot,
        slot_reply,
    }
}

impl ScanSlot {
    pub const fn after_event(self, slot_event: ScanSlotEvent) -> ScanSlotTransition {
        match (self, slot_event) {
            (Self::SlotFree, ScanSlotEvent::DeviceScanRequested) => {
                transition_to(Self::HeldByDeviceScan, ScanSlotReply::DeviceScanGranted)
            }
            (
                Self::HeldByManualScan | Self::HeldByDeviceScan,
                ScanSlotEvent::DeviceScanRequested,
            ) => transition_to(self, ScanSlotReply::DeviceScanRefused),
            (Self::SlotFree | Self::HeldByManualScan, ScanSlotEvent::ManualScanStarted) => {
                transition_to(Self::HeldByManualScan, ScanSlotReply::NoReplyNeeded)
            }
            (Self::HeldByDeviceScan, ScanSlotEvent::ManualScanStarted) => {
                transition_to(Self::HeldByManualScan, ScanSlotReply::DeviceScanRevoked)
            }
            (Self::HeldByManualScan, ScanSlotEvent::ManualScanEnded)
            | (Self::HeldByDeviceScan, ScanSlotEvent::DeviceScanEnded) => {
                transition_to(Self::SlotFree, ScanSlotReply::NoReplyNeeded)
            }
            (Self::SlotFree | Self::HeldByDeviceScan, ScanSlotEvent::ManualScanEnded)
            | (Self::SlotFree | Self::HeldByManualScan, ScanSlotEvent::DeviceScanEnded) => {
                transition_to(self, ScanSlotReply::NoReplyNeeded)
            }
        }
    }

    pub const fn device_scan_activity(self) -> DeviceScanActivity {
        match self {
            Self::HeldByDeviceScan => DeviceScanActivity::DeviceScanHoldsSlot,
            Self::SlotFree | Self::HeldByManualScan => DeviceScanActivity::DeviceScanIdle,
        }
    }
}

#[cfg(test)]
mod scan_slot_arbiter_tests {
    use super::*;

    fn replayed(slot_events: &[ScanSlotEvent]) -> (ScanSlot, Vec<ScanSlotReply>) {
        slot_events.iter().fold(
            (ScanSlot::SlotFree, Vec::new()),
            |(current_slot, mut slot_replies), slot_event| {
                let slot_transition = current_slot.after_event(*slot_event);
                slot_replies.push(slot_transition.slot_reply);
                (slot_transition.next_slot, slot_replies)
            },
        )
    }

    #[test]
    fn a_device_scan_is_refused_while_a_manual_scan_runs() {
        let (final_slot, slot_replies) = replayed(&[
            ScanSlotEvent::ManualScanStarted,
            ScanSlotEvent::DeviceScanRequested,
        ]);
        assert_eq!(final_slot, ScanSlot::HeldByManualScan);
        assert_eq!(slot_replies[1], ScanSlotReply::DeviceScanRefused);
        assert_eq!(
            final_slot.device_scan_activity(),
            DeviceScanActivity::DeviceScanIdle
        );
    }

    #[test]
    fn a_second_device_scan_is_refused_while_one_runs() {
        let (final_slot, slot_replies) = replayed(&[
            ScanSlotEvent::DeviceScanRequested,
            ScanSlotEvent::DeviceScanRequested,
        ]);
        assert_eq!(final_slot, ScanSlot::HeldByDeviceScan);
        assert_eq!(
            slot_replies,
            vec![
                ScanSlotReply::DeviceScanGranted,
                ScanSlotReply::DeviceScanRefused
            ]
        );
        assert_eq!(
            final_slot.device_scan_activity(),
            DeviceScanActivity::DeviceScanHoldsSlot
        );
    }

    #[test]
    fn the_slot_is_free_again_once_the_holder_ends() {
        let (final_slot, slot_replies) = replayed(&[
            ScanSlotEvent::ManualScanStarted,
            ScanSlotEvent::ManualScanEnded,
            ScanSlotEvent::DeviceScanRequested,
            ScanSlotEvent::DeviceScanEnded,
            ScanSlotEvent::DeviceScanRequested,
        ]);
        assert_eq!(final_slot, ScanSlot::HeldByDeviceScan);
        assert_eq!(slot_replies[2], ScanSlotReply::DeviceScanGranted);
        assert_eq!(slot_replies[4], ScanSlotReply::DeviceScanGranted);
    }

    #[test]
    fn a_manual_scan_that_raced_a_granted_device_scan_revokes_it() {
        let (final_slot, slot_replies) = replayed(&[
            ScanSlotEvent::DeviceScanRequested,
            ScanSlotEvent::ManualScanStarted,
            ScanSlotEvent::DeviceScanEnded,
        ]);
        assert_eq!(final_slot, ScanSlot::HeldByManualScan);
        assert_eq!(slot_replies[1], ScanSlotReply::DeviceScanRevoked);
        assert_eq!(slot_replies[2], ScanSlotReply::NoReplyNeeded);
    }

    #[test]
    fn an_end_from_a_page_that_does_not_hold_the_slot_changes_nothing() {
        let (final_slot, _slot_replies) = replayed(&[
            ScanSlotEvent::DeviceScanRequested,
            ScanSlotEvent::ManualScanEnded,
        ]);
        assert_eq!(final_slot, ScanSlot::HeldByDeviceScan);
    }
}

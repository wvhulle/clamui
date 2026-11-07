use gettextrs::gettext;
use relm4::{
    FactorySender,
    actions::{RelmAction, RelmActionGroup},
    adw,
    adw::prelude::*,
    gtk,
    gtk::gio,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::{
    host_services::{
        clamav_programs::false_positive_submission::SubmittedContent,
        clamav_scanner::scanner_output_parser::{
            DetectedThreat, ThreatIdentity, ThreatSeverity, displayed_threat_name,
            sanitize_scanner_line,
        },
        quarantine_vault::quarantine_file_moves::QuarantineMoveFailure,
        settings_helper::trust_requests::{
            TrustChoice, signature_can_be_ignored, signature_of_detection,
        },
    },
    shared_widgets::{
        false_positive_report_dialog::ReportedDetection,
        quarantine_failure_text::describe_quarantine_failure,
    },
};

relm4::new_action_group!(ThreatRowActions, "threat-row");
relm4::new_stateless_action!(TrustFileAction, ThreatRowActions, "trust-file");
relm4::new_stateless_action!(IgnoreSignatureAction, ThreatRowActions, "ignore-signature");
relm4::new_stateless_action!(ExcludeFromScansAction, ThreatRowActions, "exclude");
relm4::new_stateless_action!(CopyPathAction, ThreatRowActions, "copy-path");
relm4::new_stateless_action!(
    ReportFalsePositiveAction,
    ThreatRowActions,
    "report-false-positive"
);

pub fn ignore_signature_choice(threat_identity: &ThreatIdentity) -> Option<TrustChoice> {
    threat_identity
        .matched_signature_name()
        .filter(|signature_name| signature_can_be_ignored(signature_name))
        .map(|signature_name| TrustChoice::IgnoreSignature {
            signature_name: signature_of_detection(signature_name),
        })
}

pub fn false_positive_detection(detected_threat: &DetectedThreat) -> Option<ReportedDetection> {
    detected_threat
        .threat_identity
        .matched_signature_name()
        .map(|signature_name| ReportedDetection {
            detection_name: signature_name.to_owned(),
            submitted_content: SubmittedContent::DetectedFile {
                file_path: detected_threat.file_path.clone(),
            },
            shown_path: sanitize_scanner_line(&detected_threat.file_path.to_string_lossy()),
        })
}

fn threat_actions_menu(detected_threat: &DetectedThreat) -> gio::Menu {
    let trust_section = gio::Menu::new();
    trust_section.append(
        Some(&gettext("Trust This File…")),
        Some("threat-row.trust-file"),
    );
    if ignore_signature_choice(&detected_threat.threat_identity).is_some() {
        trust_section.append(
            Some(&gettext("Ignore This Detection Everywhere…")),
            Some("threat-row.ignore-signature"),
        );
    }
    if false_positive_detection(detected_threat).is_some() {
        trust_section.append(
            Some(&gettext("Report False Positive…")),
            Some("threat-row.report-false-positive"),
        );
    }
    let scan_section = gio::Menu::new();
    scan_section.append(
        Some(&gettext("Skip This Path in Lazaret Scans")),
        Some("threat-row.exclude"),
    );
    scan_section.append(Some(&gettext("Copy Path")), Some("threat-row.copy-path"));
    let actions_menu = gio::Menu::new();
    actions_menu.append_section(None, &trust_section);
    actions_menu.append_section(None, &scan_section);
    actions_menu
}

fn row_action<
    Action: relm4::actions::ActionName<Group = ThreatRowActions, Target = (), State = ()>,
>(
    sender: &FactorySender<DetectedThreatRow>,
    row_index: &DynamicIndex,
    requested_output: fn(DynamicIndex) -> DetectedThreatRowOutput,
) -> RelmAction<Action> {
    let action_sender = sender.clone();
    let action_index = row_index.clone();
    RelmAction::new_stateless(move |_activated_action| {
        let _parent_gone = action_sender.output(requested_output(action_index.clone()));
    })
}

fn signature_action<
    Action: relm4::actions::ActionName<Group = ThreatRowActions, Target = (), State = ()>,
>(
    sender: &FactorySender<DetectedThreatRow>,
    requested_output: DetectedThreatRowOutput,
) -> RelmAction<Action> {
    let action_sender = sender.clone();
    RelmAction::new_stateless(move |_activated_action| {
        let _parent_gone = action_sender.output(requested_output.clone());
    })
}

#[derive(Debug)]
pub enum ThreatQuarantineState {
    AwaitingDecision,
    MovingToQuarantine,
    MovedToQuarantine,
    QuarantineFailed(QuarantineMoveFailure),
}

pub struct DetectedThreatRow {
    pub detected_threat: DetectedThreat,
    pub row_index: DynamicIndex,
    quarantine_state: ThreatQuarantineState,
}

#[derive(Debug)]
pub enum DetectedThreatRowInput {
    QuarantineStateChanged(ThreatQuarantineState),
}

#[derive(Clone, Debug)]
pub enum DetectedThreatRowOutput {
    QuarantineRequested(DynamicIndex),
    PathCopyRequested(DynamicIndex),
    ExclusionRequested(DynamicIndex),
    TrustFileRequested(DynamicIndex),
    IgnoreSignatureRequested(TrustChoice),
    FalsePositiveReportRequested(ReportedDetection),
}

fn severity_badge_text(threat_severity: ThreatSeverity) -> String {
    match threat_severity {
        ThreatSeverity::Critical => gettext("Critical"),
        ThreatSeverity::High => gettext("High"),
        ThreatSeverity::Medium => gettext("Medium"),
        ThreatSeverity::Low => gettext("Low"),
    }
}

fn severity_badge_class(threat_severity: ThreatSeverity) -> &'static str {
    match threat_severity {
        ThreatSeverity::Critical | ThreatSeverity::High => "error",
        ThreatSeverity::Medium | ThreatSeverity::Low => "warning",
    }
}

impl DetectedThreatRow {
    fn row_subtitle(&self) -> String {
        let displayed_path =
            sanitize_scanner_line(&self.detected_threat.file_path.to_string_lossy());
        match &self.quarantine_state {
            ThreatQuarantineState::AwaitingDecision | ThreatQuarantineState::MovingToQuarantine => {
                displayed_path
            }
            ThreatQuarantineState::MovedToQuarantine => {
                gettext("Moved to quarantine: {path}. Check its reputation on the Quarantine page.")
                    .replace("{path}", &displayed_path)
            }
            ThreatQuarantineState::QuarantineFailed(move_failure) => {
                format!(
                    "{displayed_path}\n{}",
                    describe_quarantine_failure(move_failure)
                )
            }
        }
    }

    pub fn can_request_quarantine(&self) -> bool {
        matches!(
            self.quarantine_state,
            ThreatQuarantineState::AwaitingDecision | ThreatQuarantineState::QuarantineFailed(_)
        )
    }

    fn threat_severity(&self) -> ThreatSeverity {
        self.detected_threat.threat_identity.threat_severity()
    }
}

#[relm4::factory(pub)]
impl FactoryComponent for DetectedThreatRow {
    type Init = DetectedThreat;
    type Input = DetectedThreatRowInput;
    type Output = DetectedThreatRowOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        #[name = "threat_action_row"]
        adw::ActionRow {
            set_use_markup: false,
            set_title: &displayed_threat_name(&self.detected_threat.threat_identity),
            #[watch]
            set_subtitle: &self.row_subtitle(),
            set_subtitle_lines: 0,

            add_suffix = &gtk::Label {
                set_label: &severity_badge_text(self.threat_severity()),
                set_tooltip_text: Some(self.detected_threat.threat_identity.threat_category()),
                add_css_class: "caption-heading",
                add_css_class: severity_badge_class(self.threat_severity()),
            },

            add_suffix = &gtk::Button {
                set_label: &gettext("Quarantine"),
                set_valign: gtk::Align::Center,
                #[watch]
                set_sensitive: self.can_request_quarantine(),
                connect_clicked[sender, index] => move |_clicked_button| {
                    let _parent_gone = sender.output(DetectedThreatRowOutput::QuarantineRequested(index.clone()));
                },
            },

            add_suffix = &gtk::MenuButton {
                set_icon_name: "view-more-symbolic",
                set_tooltip_text: Some(&gettext("More Actions")),
                set_valign: gtk::Align::Center,
                add_css_class: "flat",
                set_menu_model: Some(&threat_actions_menu(&self.detected_threat)),
            },
        }
    }

    fn init_model(
        detected_threat: DetectedThreat,
        row_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self {
            detected_threat,
            row_index: row_index.clone(),
            quarantine_state: ThreatQuarantineState::AwaitingDecision,
        }
    }

    fn init_widgets(
        &mut self,
        index: &DynamicIndex,
        root: Self::Root,
        _returned_widget: &<Self::ParentWidget as relm4::factory::FactoryView>::ReturnedWidget,
        sender: FactorySender<Self>,
    ) -> Self::Widgets {
        let widgets = view_output!();
        let mut row_actions = RelmActionGroup::<ThreatRowActions>::new();
        row_actions.add_action(row_action::<TrustFileAction>(
            &sender,
            index,
            DetectedThreatRowOutput::TrustFileRequested,
        ));
        if let Some(trust_choice) = ignore_signature_choice(&self.detected_threat.threat_identity) {
            row_actions.add_action(signature_action::<IgnoreSignatureAction>(
                &sender,
                DetectedThreatRowOutput::IgnoreSignatureRequested(trust_choice),
            ));
        }
        if let Some(reported_detection) = false_positive_detection(&self.detected_threat) {
            row_actions.add_action(signature_action::<ReportFalsePositiveAction>(
                &sender,
                DetectedThreatRowOutput::FalsePositiveReportRequested(reported_detection),
            ));
        }
        row_actions.add_action(row_action::<ExcludeFromScansAction>(
            &sender,
            index,
            DetectedThreatRowOutput::ExclusionRequested,
        ));
        row_actions.add_action(row_action::<CopyPathAction>(
            &sender,
            index,
            DetectedThreatRowOutput::PathCopyRequested,
        ));
        row_actions.register_for_widget(&widgets.threat_action_row);
        widgets
    }

    fn update(&mut self, row_input: DetectedThreatRowInput, _sender: FactorySender<Self>) {
        match row_input {
            DetectedThreatRowInput::QuarantineStateChanged(quarantine_state) => {
                self.quarantine_state = quarantine_state;
            }
        }
    }
}

#[cfg(test)]
mod detected_threat_row_tests {
    use std::path::PathBuf;

    use super::*;

    fn detected_signature(signature_name: &str) -> DetectedThreat {
        DetectedThreat {
            file_path: PathBuf::from("/scan/detected.bin"),
            threat_identity: ThreatIdentity::Signature {
                signature_name: signature_name.to_owned(),
            },
        }
    }

    #[test]
    fn an_on_access_block_offers_no_signature_actions() {
        let blocked_threat = DetectedThreat {
            file_path: PathBuf::from("/scan/blocked.bin"),
            threat_identity: ThreatIdentity::BlockedByOnAccess,
        };
        assert_eq!(
            ignore_signature_choice(&blocked_threat.threat_identity),
            None
        );
        assert_eq!(false_positive_detection(&blocked_threat), None);
    }

    #[test]
    fn a_signature_offers_ignoring_its_official_name_and_a_report() {
        let detected_threat = detected_signature("Sanesecurity.Foo.UNOFFICIAL");
        assert_eq!(
            ignore_signature_choice(&detected_threat.threat_identity),
            Some(TrustChoice::IgnoreSignature {
                signature_name: "Sanesecurity.Foo".to_owned(),
            })
        );
        assert_eq!(
            false_positive_detection(&detected_threat)
                .map(|reported_detection| reported_detection.detection_name),
            Some("Sanesecurity.Foo.UNOFFICIAL".to_owned())
        );
    }

    #[test]
    fn heuristic_signatures_can_be_reported_but_not_ignored() {
        let detected_threat = detected_signature("Heuristics.Encrypted.Zip");
        assert_eq!(
            ignore_signature_choice(&detected_threat.threat_identity),
            None
        );
        assert!(false_positive_detection(&detected_threat).is_some());
    }
}

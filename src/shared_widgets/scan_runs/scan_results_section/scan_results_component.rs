use futures::{StreamExt, stream};
use gettextrs::{gettext, ngettext};
use relm4::{
    Component, ComponentParts, ComponentSender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryVecDeque},
};

use crate::{
    host_services::{
        activity_history::activity_history_database::ActivityHistory,
        clamav_programs::clamav_report_submission::ClamavReportRequest,
        clamav_scanner::{
            scan_exclusion_rules::exclusion_entry_for_threat,
            scanner_output_parser::{DetectedThreat, sanitize_scanner_line},
        },
        desktop::stored_settings::{add_exclusion_entry, application_settings},
        quarantine_vault::{
            quarantine_entry_database::{QuarantineEntryRecord, QuarantineVault},
            quarantine_file_moves::QuarantineMoveFailure,
        },
        sample_submissions::clamav_report_flow::{ClamavReportAttempt, send_clamav_report},
        settings_helper::trust_requests::{
            FileFingerprint, TrustChoice, TrustOutcome, fingerprint_file, request_trust_change,
            trust_outcome_text,
        },
    },
    shared_widgets::{
        awaited_dialogs::{
            AlertChoice, TextExportOutcome, add_alert_choice, add_dismissing_choice, alert_choice,
            deliver_local_outcome, describe_export_failure, exported_text,
        },
        component_streams::run_stream_to_completion,
        scan_runs::scan_results_section::{
            detected_threat_row::{
                DetectedThreatRow, DetectedThreatRowInput, DetectedThreatRowOutput,
                ThreatQuarantineState,
            },
            scan_problem_row::{ScanProblemRow, problem_rows_of},
            scan_results_state::{
                ScanResultsView, fingerprint_failure_text, format_scan_report, status_icon,
                status_style_class,
            },
        },
        submission_confirm_dialog::{ClamavReportProposal, present_clamav_report_confirmation},
        submission_outcome_text::clamav_report_attempt_text,
        trust_confirmation_dialog::present_trust_confirmation,
    },
};

const EXPORT_FILE_NAME: &str = "lazaret_scan_results.txt";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuarantineDialogChoice {
    QuarantineChosen,
    QuarantineCancelled,
}

impl AlertChoice for QuarantineDialogChoice {
    const ANSWERING_CHOICES: &'static [Self] = &[Self::QuarantineChosen];
    const DISMISSING_CHOICE: Self = Self::QuarantineCancelled;

    fn response_id(self) -> &'static str {
        match self {
            Self::QuarantineChosen => "quarantine",
            Self::QuarantineCancelled => "cancel",
        }
    }
}

pub struct ScanResultsSectionInit {
    pub quarantine_vault: QuarantineVault,
    pub activity_history: ActivityHistory,
    pub dismiss_label: String,
}

pub struct ScanResultsSection {
    dismiss_label: String,
    results_view: ScanResultsView,
    results_generation: u64,
    quarantine_vault: QuarantineVault,
    activity_history: ActivityHistory,
    threat_rows: FactoryVecDeque<DetectedThreatRow>,
    problem_rows: FactoryVecDeque<ScanProblemRow>,
}

#[derive(Debug)]
pub enum ScanResultsSectionInput {
    ResultsShown(ScanResultsView),
    QuarantineThreatRequested(DynamicIndex),
    QuarantineAllRequested,
    QuarantineConfirmed(Vec<DynamicIndex>),
    CopyPathRequested(DynamicIndex),
    ExcludeThreatRequested(DynamicIndex),
    TrustFileRequested(DynamicIndex),
    IgnoreSignatureRequested(TrustChoice),
    TrustChangeConfirmed(TrustChoice),
    FalsePositiveReportRequested(ClamavReportProposal),
    FalsePositiveReportConfirmed(ClamavReportRequest),
    CopyReportRequested,
    ExportReportRequested,
    ResultsDismissRequested,
}

#[derive(Debug)]
pub enum ScanResultsSectionOutput {
    QuarantineEntriesChanged,
    ResultsDismissRequested,
    ToastRequested(String),
}

#[derive(Debug)]
pub enum ScanResultsSectionCommand {
    ThreatQuarantineFinished {
        results_generation: u64,
        row_index: DynamicIndex,
        move_outcome: Result<QuarantineEntryRecord, QuarantineMoveFailure>,
    },
    ReportExportFinished(TextExportOutcome),
    ThreatFileFingerprinted {
        shown_path: String,
        fingerprint_outcome: std::io::Result<FileFingerprint>,
    },
    TrustChangeFinished(TrustOutcome),
    FalsePositiveReportFinished(ClamavReportAttempt),
}

struct PendingThreatMove {
    row_index: DynamicIndex,
    detected_threat: DetectedThreat,
}

fn forwarded_threat_output(row_output: DetectedThreatRowOutput) -> ScanResultsSectionInput {
    match row_output {
        DetectedThreatRowOutput::QuarantineRequested(row_index) => {
            ScanResultsSectionInput::QuarantineThreatRequested(row_index)
        }
        DetectedThreatRowOutput::PathCopyRequested(row_index) => {
            ScanResultsSectionInput::CopyPathRequested(row_index)
        }
        DetectedThreatRowOutput::ExclusionRequested(row_index) => {
            ScanResultsSectionInput::ExcludeThreatRequested(row_index)
        }
        DetectedThreatRowOutput::TrustFileRequested(row_index) => {
            ScanResultsSectionInput::TrustFileRequested(row_index)
        }
        DetectedThreatRowOutput::IgnoreSignatureRequested(trust_choice) => {
            ScanResultsSectionInput::IgnoreSignatureRequested(trust_choice)
        }
        DetectedThreatRowOutput::FalsePositiveReportRequested(reported_detection) => {
            ScanResultsSectionInput::FalsePositiveReportRequested(reported_detection)
        }
    }
}

impl ScanResultsSection {
    fn remaining_threat_count(&self) -> usize {
        self.threat_rows
            .iter()
            .filter(|threat_row| threat_row.can_request_quarantine())
            .count()
    }

    fn quarantine_all_label(&self) -> String {
        let remaining_threats = self.remaining_threat_count();
        ngettext(
            "Quarantine {count} Threat",
            "Quarantine {count} Threats",
            u32::try_from(remaining_threats).unwrap_or(u32::MAX),
        )
        .replace("{count}", &remaining_threats.to_string())
    }

    fn confirm_quarantine(
        &self,
        confirmed_rows: Vec<DynamicIndex>,
        confirmation_body: String,
        root: &gtk::Box,
        sender: &ComponentSender<Self>,
    ) {
        let confirmation_dialog = adw::AlertDialog::new(
            Some(&gettext("Move to Quarantine?")),
            Some(&format!(
                "{confirmation_body}\n{}",
                gettext("This removes each original file from its current location.")
            )),
        );
        add_dismissing_choice::<QuarantineDialogChoice>(&confirmation_dialog, &gettext("Cancel"));
        add_alert_choice(
            &confirmation_dialog,
            QuarantineDialogChoice::QuarantineChosen,
            &gettext("Quarantine"),
        );
        confirmation_dialog.set_response_appearance(
            QuarantineDialogChoice::QuarantineChosen.response_id(),
            adw::ResponseAppearance::Destructive,
        );
        deliver_local_outcome(
            sender.input_sender().clone(),
            alert_choice(confirmation_dialog, root.clone().upcast()),
            move |quarantine_choice| match quarantine_choice {
                QuarantineDialogChoice::QuarantineChosen => {
                    Some(ScanResultsSectionInput::QuarantineConfirmed(confirmed_rows))
                }
                QuarantineDialogChoice::QuarantineCancelled => None,
            },
        );
    }

    fn start_threat_moves(
        &self,
        confirmed_rows: Vec<DynamicIndex>,
        sender: &ComponentSender<Self>,
    ) {
        let pending_moves = confirmed_rows
            .into_iter()
            .filter_map(|row_index| {
                let current_position = row_index.current_index();
                let detected_threat = self
                    .threat_rows
                    .get(current_position)?
                    .detected_threat
                    .clone();
                self.threat_rows.send(
                    current_position,
                    DetectedThreatRowInput::QuarantineStateChanged(
                        ThreatQuarantineState::MovingToQuarantine,
                    ),
                );
                Some(PendingThreatMove {
                    row_index,
                    detected_threat,
                })
            })
            .collect::<Vec<_>>();
        let quarantine_vault = self.quarantine_vault.clone();
        let results_generation = self.results_generation;
        run_stream_to_completion(
            sender,
            stream::iter(pending_moves).then(move |pending_move| {
                let quarantine_vault = quarantine_vault.clone();
                async move {
                    ScanResultsSectionCommand::ThreatQuarantineFinished {
                        results_generation,
                        move_outcome: quarantine_vault
                            .move_file_into_quarantine(
                                &pending_move.detected_threat.file_path,
                                &pending_move.detected_threat.threat_identity,
                            )
                            .await,
                        row_index: pending_move.row_index,
                    }
                }
            }),
        );
    }

    fn show_results(&mut self, results_view: ScanResultsView) {
        self.results_generation += 1;
        let mut threat_guard = self.threat_rows.guard();
        threat_guard.clear();
        results_view
            .detected_threats
            .iter()
            .cloned()
            .for_each(|detected_threat| {
                threat_guard.push_back(detected_threat);
            });
        drop(threat_guard);
        let mut problem_guard = self.problem_rows.guard();
        problem_guard.clear();
        problem_rows_of(&results_view)
            .into_iter()
            .for_each(|problem_row| {
                problem_guard.push_back(problem_row);
            });
        drop(problem_guard);
        self.results_view = results_view;
    }
}

#[relm4::component(pub)]
impl Component for ScanResultsSection {
    type Init = ScanResultsSectionInit;
    type Input = ScanResultsSectionInput;
    type Output = ScanResultsSectionOutput;
    type CommandOutput = ScanResultsSectionCommand;

    view! {
        gtk::Box {
            set_orientation: gtk::Orientation::Vertical,
            set_spacing: 18,

            gtk::Box {
                set_orientation: gtk::Orientation::Vertical,
                set_spacing: 6,
                set_margin_top: 12,

                gtk::Image {
                    #[watch]
                    set_icon_name: Some(status_icon(model.results_view.results_status)),
                    set_pixel_size: 64,
                    #[watch]
                    set_css_classes: &[status_style_class(model.results_view.results_status)],
                },

                gtk::Label {
                    add_css_class: "title-1",
                    set_wrap: true,
                    set_justify: gtk::Justification::Center,
                    #[watch]
                    set_label: &model.results_view.headline_text(),
                },

                gtk::Label {
                    add_css_class: "dim-label",
                    set_wrap: true,
                    set_justify: gtk::Justification::Center,
                    #[watch]
                    set_label: &model.results_view.summary_text(),
                },
            },

            gtk::Box {
                set_spacing: 6,
                set_halign: gtk::Align::Center,

                gtk::Button {
                    add_css_class: "suggested-action",
                    #[watch]
                    set_label: &model.quarantine_all_label(),
                    #[watch]
                    set_visible: model.remaining_threat_count() > 0,
                    connect_clicked => ScanResultsSectionInput::QuarantineAllRequested,
                },

                gtk::Button {
                    set_label: &model.dismiss_label,
                    connect_clicked => ScanResultsSectionInput::ResultsDismissRequested,
                },


            },

            adw::PreferencesGroup {
                set_title: &gettext("Detected Threats"),
                #[watch]
                set_visible: !model.threat_rows.is_empty(),

                #[local_ref]
                threat_list -> gtk::ListBox {
                    add_css_class: "boxed-list",
                    set_selection_mode: gtk::SelectionMode::None,
                },
            },

            adw::PreferencesGroup {
                set_title: &gettext("Problems"),
                #[watch]
                set_visible: model.results_view.has_problems(),

                #[local_ref]
                problem_list -> gtk::ListBox {
                    add_css_class: "boxed-list",
                    set_selection_mode: gtk::SelectionMode::None,
                },
            },
        }
    }

    fn init(
        section_init: ScanResultsSectionInit,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let ScanResultsSectionInit {
            quarantine_vault,
            activity_history,
            dismiss_label,
        } = section_init;
        let model = Self {
            dismiss_label,
            results_view: ScanResultsView::empty_results(),
            results_generation: 0,
            quarantine_vault,
            activity_history,
            threat_rows: FactoryVecDeque::builder()
                .launch(gtk::ListBox::default())
                .forward(sender.input_sender(), forwarded_threat_output),
            problem_rows: FactoryVecDeque::builder()
                .launch(gtk::ListBox::default())
                .detach(),
        };
        let threat_list = model.threat_rows.widget();
        let problem_list = model.problem_rows.widget();
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        panel_input: ScanResultsSectionInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match panel_input {
            ScanResultsSectionInput::ResultsShown(results_view) => self.show_results(results_view),
            ScanResultsSectionInput::QuarantineThreatRequested(row_index) => {
                if let Some(threat_row) = self.threat_rows.get(row_index.current_index()) {
                    let confirmation_body = gettext("Move '{path}' to quarantine?").replace(
                        "{path}",
                        &sanitize_scanner_line(
                            &threat_row.detected_threat.file_path.to_string_lossy(),
                        ),
                    );
                    self.confirm_quarantine(vec![row_index], confirmation_body, root, &sender);
                }
            }
            ScanResultsSectionInput::QuarantineAllRequested => {
                let remaining_threats = self.remaining_threat_count();
                let confirmed_rows = self
                    .threat_rows
                    .iter()
                    .filter(|threat_row| threat_row.can_request_quarantine())
                    .map(|threat_row| threat_row.row_index.clone())
                    .collect();
                let confirmation_body = ngettext(
                    "Move {count} detected file to quarantine?",
                    "Move {count} detected files to quarantine?",
                    u32::try_from(remaining_threats).unwrap_or(u32::MAX),
                )
                .replace("{count}", &remaining_threats.to_string());
                self.confirm_quarantine(confirmed_rows, confirmation_body, root, &sender);
            }
            ScanResultsSectionInput::QuarantineConfirmed(confirmed_rows) => {
                self.start_threat_moves(confirmed_rows, &sender);
            }
            ScanResultsSectionInput::CopyPathRequested(row_index) => {
                if let Some(threat_row) = self.threat_rows.get(row_index.current_index()) {
                    root.clipboard()
                        .set_text(&threat_row.detected_threat.file_path.to_string_lossy());
                    let _page_closed = sender.output(ScanResultsSectionOutput::ToastRequested(
                        gettext("Path copied to clipboard"),
                    ));
                }
            }
            ScanResultsSectionInput::ExcludeThreatRequested(row_index) => {
                if let Some(threat_row) = self.threat_rows.get(row_index.current_index()) {
                    let newly_excluded = add_exclusion_entry(
                        &application_settings(),
                        exclusion_entry_for_threat(&threat_row.detected_threat.file_path),
                    );
                    let exclusion_message = if newly_excluded {
                        gettext("This file will be skipped in future scans")
                    } else {
                        gettext("This exclusion already exists")
                    };
                    let _page_closed =
                        sender.output(ScanResultsSectionOutput::ToastRequested(exclusion_message));
                }
            }
            ScanResultsSectionInput::TrustFileRequested(row_index) => {
                if let Some(threat_row) = self.threat_rows.get(row_index.current_index()) {
                    let threat_path = threat_row.detected_threat.file_path.clone();
                    sender.oneshot_command(async move {
                        let shown_path = sanitize_scanner_line(&threat_path.to_string_lossy());
                        let fingerprint_outcome =
                            tokio::task::spawn_blocking(move || fingerprint_file(&threat_path))
                                .await
                                .unwrap_or_else(|interrupted_hashing| {
                                    Err(std::io::Error::other(interrupted_hashing))
                                });
                        ScanResultsSectionCommand::ThreatFileFingerprinted {
                            shown_path,
                            fingerprint_outcome,
                        }
                    });
                }
            }
            ScanResultsSectionInput::IgnoreSignatureRequested(trust_choice) => {
                present_trust_confirmation(
                    root,
                    trust_choice,
                    sender.input_sender().clone(),
                    ScanResultsSectionInput::TrustChangeConfirmed,
                );
            }
            ScanResultsSectionInput::TrustChangeConfirmed(confirmed_choice) => {
                sender.oneshot_command(async move {
                    ScanResultsSectionCommand::TrustChangeFinished(
                        request_trust_change(confirmed_choice).await,
                    )
                });
            }
            ScanResultsSectionInput::FalsePositiveReportRequested(report_proposal) => {
                present_clamav_report_confirmation(
                    root,
                    report_proposal,
                    sender.input_sender().clone(),
                    ScanResultsSectionInput::FalsePositiveReportConfirmed,
                );
            }
            ScanResultsSectionInput::FalsePositiveReportConfirmed(report_request) => {
                let activity_history = self.activity_history.clone();
                let quarantine_vault = self.quarantine_vault.clone();
                sender.oneshot_command(async move {
                    ScanResultsSectionCommand::FalsePositiveReportFinished(
                        send_clamav_report(&activity_history, &quarantine_vault, report_request)
                            .await,
                    )
                });
            }
            ScanResultsSectionInput::CopyReportRequested => {
                root.clipboard()
                    .set_text(&format_scan_report(&self.results_view));
                let _page_closed = sender.output(ScanResultsSectionOutput::ToastRequested(
                    gettext("Results copied to clipboard"),
                ));
            }
            ScanResultsSectionInput::ResultsDismissRequested => {
                let _page_closed = sender.output(ScanResultsSectionOutput::ResultsDismissRequested);
            }
            ScanResultsSectionInput::ExportReportRequested => {
                let exported_report = format_scan_report(&self.results_view);
                deliver_local_outcome(
                    sender.command_sender().clone(),
                    exported_text(EXPORT_FILE_NAME.to_owned(), exported_report),
                    |export_outcome| {
                        Some(ScanResultsSectionCommand::ReportExportFinished(
                            export_outcome,
                        ))
                    },
                );
            }
        }
    }

    fn update_cmd(
        &mut self,
        panel_command: ScanResultsSectionCommand,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match panel_command {
            ScanResultsSectionCommand::ThreatFileFingerprinted {
                shown_path,
                fingerprint_outcome: Ok(file_fingerprint),
            } => {
                present_trust_confirmation(
                    root,
                    TrustChoice::TrustFile {
                        file_fingerprint,
                        shown_path,
                    },
                    sender.input_sender().clone(),
                    ScanResultsSectionInput::TrustChangeConfirmed,
                );
            }
            ScanResultsSectionCommand::ThreatFileFingerprinted {
                fingerprint_outcome: Err(fingerprint_failure),
                ..
            } => {
                let _page_closed = sender.output(ScanResultsSectionOutput::ToastRequested(
                    fingerprint_failure_text(&fingerprint_failure),
                ));
            }
            ScanResultsSectionCommand::FalsePositiveReportFinished(report_attempt) => {
                let _page_closed = sender.output(ScanResultsSectionOutput::ToastRequested(
                    clamav_report_attempt_text(&report_attempt),
                ));
            }
            ScanResultsSectionCommand::TrustChangeFinished(trust_outcome) => {
                let _page_closed = sender.output(ScanResultsSectionOutput::ToastRequested(
                    trust_outcome_text(&trust_outcome),
                ));
            }
            ScanResultsSectionCommand::ThreatQuarantineFinished {
                results_generation,
                row_index,
                move_outcome,
            } => {
                let quarantine_state = match move_outcome {
                    Ok(_entry_record) => {
                        let _page_closed =
                            sender.output(ScanResultsSectionOutput::QuarantineEntriesChanged);
                        ThreatQuarantineState::MovedToQuarantine
                    }
                    Err(move_failure) => ThreatQuarantineState::QuarantineFailed(move_failure),
                };
                if results_generation == self.results_generation {
                    self.threat_rows.send(
                        row_index.current_index(),
                        DetectedThreatRowInput::QuarantineStateChanged(quarantine_state),
                    );
                }
            }
            ScanResultsSectionCommand::ReportExportFinished(TextExportOutcome::TextSaved) => {
                let _page_closed = sender.output(ScanResultsSectionOutput::ToastRequested(
                    gettext("Results exported"),
                ));
            }
            ScanResultsSectionCommand::ReportExportFinished(TextExportOutcome::ExportCancelled) => {
            }
            ScanResultsSectionCommand::ReportExportFinished(TextExportOutcome::ExportFailed(
                export_failure,
            )) => {
                let _page_closed = sender.output(ScanResultsSectionOutput::ToastRequested(
                    describe_export_failure(&export_failure),
                ));
            }
        }
    }
}

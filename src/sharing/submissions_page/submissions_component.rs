use std::path::PathBuf;

use futures::stream;
use gettextrs::gettext;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller,
    abstractions::Toaster, adw, adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    host_services::{
        activity_history::{
            activity_history_database::{ActivityHistory, ActivityHistoryFailure},
            submission_history_store::{SubmissionRecord, SubmissionTarget},
        },
        clamav_programs::clamav_report_submission::{
            ClamavReport, ClamavReportKind, ClamavReportRequest, SubmittedContent,
        },
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        desktop::locale_formatting::host_moment_formatters,
        quarantine_vault::{
            quarantine_entry_database::{QuarantineEntryRecord, QuarantineVault},
            quarantine_file_moves::QuarantineMoveFailure,
        },
        sample_submissions::{
            bazaar_sample_upload::{
                BazaarEligibility, BazaarUploadAttempt, bazaar_eligibility,
                upload_to_malware_bazaar,
            },
            clamav_report_flow::{
                ClamavReportAttempt, clamav_report_target, read_clamav_report_sample,
                send_read_clamav_report,
            },
            remote_status_refresh::{RemoteRefreshSummary, refresh_remote_statuses},
            submission_samples::{SampleReadFailure, SubmissionSample, shown_file_name},
            virustotal_sample_upload::{VirusTotalUploadAttempt, upload_to_virustotal},
        },
        threat_intel::service_key_storage::ThreatIntelService,
    },
    shared_widgets::{
        awaited_dialogs::{ChosenSubmissionFile, chosen_file_to_submit, deliver_local_outcome},
        component_streams::{RunningStream, run_stream},
        loading_indicators::{BUSY_PAGE_NAME, IDLE_PAGE_NAME, busy_page_name},
        submission_confirm_dialog::{
            ClamavReportProposal, SampleUploadProposal, UploadService,
            present_clamav_report_confirmation, present_sample_upload_confirmation,
        },
        submission_outcome_text::{
            bazaar_upload_attempt_text, clamav_report_attempt_text, virustotal_upload_attempt_text,
        },
    },
    sharing::submissions_page::{
        quarantined_candidate_row::{QuarantinedCandidateRow, QuarantinedCandidateRowOutput},
        service_key_section::{ServiceKeySection, ServiceKeySectionOutput},
        submission_target_dialog::{ChosenTarget, TargetChoiceRequest, present_target_choice},
        submissions_presentation::{
            candidate_row_view, empty_candidates_text, empty_submissions_text,
            progress_filter_label, refresh_summary_text, service_filter_label, submitted_row_view,
        },
        submissions_state::{
            CandidateListing, PROGRESS_FILTER_CHOICES, SERVICE_FILTER_CHOICES, SubmissionFilters,
            SubmissionListing, SubmissionsPageOutput, choice_at, choice_position, entry_upload_key,
            offered_target_activities,
        },
        submitted_entry_row::{SubmittedEntryRow, SubmittedEntryRowOutput},
        uploads_in_flight::{UploadKey, UploadsInFlight, upload_refusal_text},
    },
};

pub struct SubmissionsPageInit {
    pub activity_history: ActivityHistory,
    pub quarantine_vault: QuarantineVault,
}

enum RemoteRefreshRun {
    RefreshIdle,
    RefreshRunning { _refresh_stream: RunningStream },
}

pub struct SubmissionsPage {
    activity_history: ActivityHistory,
    quarantine_vault: QuarantineVault,
    toaster: Toaster,
    submission_listing: SubmissionListing,
    candidate_listing: CandidateListing,
    submission_filters: SubmissionFilters,
    remote_refresh: RemoteRefreshRun,
    uploads_in_flight: UploadsInFlight,
    submitted_rows: FactoryVecDeque<SubmittedEntryRow>,
    candidate_rows: FactoryVecDeque<QuarantinedCandidateRow>,
    abuse_ch_section: Controller<ServiceKeySection>,
    virustotal_section: Controller<ServiceKeySection>,
}

#[derive(Debug)]
pub enum SubmissionsPageInput {
    PageShown,
    SubmissionsChanged,
    QuarantineEntriesChanged,
    ServiceFilterChosen(u32),
    ProgressFilterChosen(u32),
    RemoteRefreshRequested,
    EntrySubmissionRequested { entry_id: i64 },
    QuarantinedFileSubmissionRequested { original_path: PathBuf },
    TargetChosen(ChosenTarget),
    ClamavReportConfirmed(ClamavReportRequest),
    SampleUploadConfirmed(SampleUploadProposal),
    MissedMalwareReportRequested,
    MissedMalwareFileChosen(PathBuf),
    RemoteEntryRequested(String),
    StoredKeyChanged,
}

const fn page_input_for_key_output(key_output: ServiceKeySectionOutput) -> SubmissionsPageInput {
    match key_output {
        ServiceKeySectionOutput::StoredKeyChanged => SubmissionsPageInput::StoredKeyChanged,
    }
}

#[derive(Debug)]
pub enum SubmissionsPageCommand {
    SubmissionsLoaded(Result<Vec<SubmissionRecord>, ActivityHistoryFailure>),
    CandidatesLoaded(Result<Vec<QuarantineEntryRecord>, QuarantineMoveFailure>),
    ClamavSampleRead {
        clamav_report: ClamavReport,
        read_outcome: Result<SubmissionSample, SampleReadFailure>,
    },
    ClamavReportFinished {
        upload_key: UploadKey,
        report_attempt: ClamavReportAttempt,
    },
    BazaarUploadFinished {
        upload_key: UploadKey,
        upload_attempt: BazaarUploadAttempt,
    },
    VirusTotalUploadFinished {
        upload_key: UploadKey,
        upload_attempt: VirusTotalUploadAttempt,
    },
    RemoteRefreshFinished(RemoteRefreshSummary),
}

fn plain_text_toast(toast_text: &str) -> adw::Toast {
    adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build()
}

fn choice_labels(choice_labels: Vec<String>) -> gtk::StringList {
    gtk::StringList::new(&choice_labels.iter().map(String::as_str).collect::<Vec<_>>())
}

fn shown_path(entry_record: &QuarantineEntryRecord) -> String {
    sanitize_scanner_line(&entry_record.original_path.to_string_lossy())
}

impl SubmissionsPage {
    fn reload_submissions(&self, sender: &ComponentSender<Self>) {
        let activity_history = self.activity_history.clone();
        sender.oneshot_command(async move {
            SubmissionsPageCommand::SubmissionsLoaded(activity_history.list_submissions().await)
        });
    }

    fn reload_candidates(&self, sender: &ComponentSender<Self>) {
        let quarantine_vault = self.quarantine_vault.clone();
        sender.oneshot_command(async move {
            SubmissionsPageCommand::CandidatesLoaded(
                quarantine_vault.list_quarantine_entries().await,
            )
        });
    }

    fn show_submitted_rows(&mut self) {
        let moment_formatters = host_moment_formatters();
        let mut row_guard = self.submitted_rows.guard();
        row_guard.clear();
        self.submission_listing
            .listed_submissions()
            .iter()
            .filter(|listed_submission| {
                self.submission_filters.admits_submission(listed_submission)
            })
            .for_each(|listed_submission| {
                row_guard.push_back(submitted_row_view(listed_submission, moment_formatters));
            });
    }

    fn show_candidate_rows(&mut self) {
        let mut row_guard = self.candidate_rows.guard();
        row_guard.clear();
        self.candidate_listing
            .listed_candidates()
            .iter()
            .for_each(|listed_candidate| {
                row_guard.push_back(candidate_row_view(
                    listed_candidate,
                    &self.uploads_in_flight,
                ));
            });
    }

    fn submitted_rows_shown(&self) -> bool {
        !self.submitted_rows.is_empty()
    }

    fn candidate_rows_shown(&self) -> bool {
        !self.candidate_rows.is_empty()
    }

    const fn remote_refresh_running(&self) -> bool {
        matches!(self.remote_refresh, RemoteRefreshRun::RefreshRunning { .. })
    }

    fn report_tally(&self, sender: &ComponentSender<Self>) {
        let _shell_closed = sender.output(SubmissionsPageOutput::TallyChanged(
            self.submission_listing.submission_tally(),
        ));
    }

    fn offer_targets_for(
        &self,
        entry_record: &QuarantineEntryRecord,
        root: &adw::ToastOverlay,
        sender: &ComponentSender<Self>,
    ) {
        let entry_targets = offered_target_activities(entry_record, &self.uploads_in_flight);
        if entry_targets.is_empty() {
            self.toaster.add_toast(plain_text_toast(&gettext(
                "This quarantine record has no usable hash, so Lazaret doesn't send it anywhere",
            )));
            return;
        }
        present_target_choice(
            root,
            TargetChoiceRequest {
                entry_id: entry_record.entry_id,
                file_name: shown_file_name(&entry_record.original_path),
                offered_targets: entry_targets,
            },
            sender.input_sender().clone(),
            SubmissionsPageInput::TargetChosen,
        );
    }

    fn confirm_chosen_target(
        &self,
        chosen_target: ChosenTarget,
        root: &adw::ToastOverlay,
        sender: &ComponentSender<Self>,
    ) {
        let Some(entry_record) = self
            .candidate_listing
            .candidate_with_id(chosen_target.entry_id)
        else {
            self.toaster.add_toast(plain_text_toast(&gettext(
                "This file is no longer in quarantine",
            )));
            return;
        };
        let unsendable_toast = || {
            self.toaster.add_toast(plain_text_toast(&gettext(
                "This service doesn't take this detection",
            )));
        };
        let clamav_report_proposal = |report_kind| ClamavReportProposal {
            report_kind,
            submitted_content: SubmittedContent::QuarantinedEntry {
                entry_id: entry_record.entry_id,
            },
            shown_path: shown_path(entry_record),
        };
        let sample_upload_proposal = |upload_service| SampleUploadProposal {
            upload_service,
            entry_id: entry_record.entry_id,
            shown_path: shown_path(entry_record),
        };
        match chosen_target.submission_target {
            SubmissionTarget::ClamavFalsePositive => {
                match entry_record.threat_identity.matched_signature_name() {
                    Some(signature_name) => present_clamav_report_confirmation(
                        root,
                        clamav_report_proposal(ClamavReportKind::FalsePositive {
                            detection_name: signature_name.to_owned(),
                        }),
                        sender.input_sender().clone(),
                        SubmissionsPageInput::ClamavReportConfirmed,
                    ),
                    None => unsendable_toast(),
                }
            }
            SubmissionTarget::ClamavMissedMalware => present_clamav_report_confirmation(
                root,
                clamav_report_proposal(ClamavReportKind::MissedMalware),
                sender.input_sender().clone(),
                SubmissionsPageInput::ClamavReportConfirmed,
            ),
            SubmissionTarget::MalwareBazaarSample => {
                match bazaar_eligibility(&entry_record.threat_identity) {
                    BazaarEligibility::EligibleSignature { signature_name } => {
                        present_sample_upload_confirmation(
                            root,
                            sample_upload_proposal(UploadService::MalwareBazaarUpload {
                                signature_name,
                            }),
                            sender.input_sender().clone(),
                            SubmissionsPageInput::SampleUploadConfirmed,
                        );
                    }
                    BazaarEligibility::NotDetectedByClamav
                    | BazaarEligibility::UnwantedProgramOnly => unsendable_toast(),
                }
            }
            SubmissionTarget::VirusTotalSample => present_sample_upload_confirmation(
                root,
                sample_upload_proposal(UploadService::VirusTotalUpload),
                sender.input_sender().clone(),
                SubmissionsPageInput::SampleUploadConfirmed,
            ),
        }
    }

    fn report_upload_notice(sender: &ComponentSender<Self>, notice_text: String) {
        let _shell_closed = sender.output(SubmissionsPageOutput::UploadNoticeReady(notice_text));
    }

    fn finish_sending(&self, outcome_text: &str, sender: &ComponentSender<Self>) {
        self.toaster.add_toast(plain_text_toast(outcome_text));
        self.reload_submissions(sender);
    }

    fn finish_upload(
        &mut self,
        upload_key: &UploadKey,
        outcome_text: String,
        sender: &ComponentSender<Self>,
    ) {
        self.uploads_in_flight.finish_upload(upload_key);
        self.show_candidate_rows();
        Self::report_upload_notice(sender, outcome_text);
        self.reload_submissions(sender);
    }

    fn admit_upload(
        &mut self,
        upload_key: UploadKey,
        sender: &ComponentSender<Self>,
    ) -> Option<UploadKey> {
        match self.uploads_in_flight.start_upload(upload_key) {
            Ok(admitted_key) => {
                self.show_candidate_rows();
                Some(admitted_key)
            }
            Err(upload_refusal) => {
                Self::report_upload_notice(sender, upload_refusal_text(&upload_refusal));
                None
            }
        }
    }

    fn start_sample_upload(
        &mut self,
        upload_proposal: &SampleUploadProposal,
        sender: &ComponentSender<Self>,
    ) {
        let entry_id = upload_proposal.entry_id;
        let upload_target = match upload_proposal.upload_service {
            UploadService::MalwareBazaarUpload { .. } => SubmissionTarget::MalwareBazaarSample,
            UploadService::VirusTotalUpload => SubmissionTarget::VirusTotalSample,
        };
        let Some(upload_key) = self
            .candidate_listing
            .candidate_with_id(entry_id)
            .and_then(|entry_record| entry_upload_key(entry_record, upload_target))
        else {
            Self::report_upload_notice(
                sender,
                gettext("This file is no longer in quarantine with a usable hash"),
            );
            return;
        };
        let Some(upload_key) = self.admit_upload(upload_key, sender) else {
            return;
        };
        let activity_history = self.activity_history.clone();
        let quarantine_vault = self.quarantine_vault.clone();
        match upload_proposal.upload_service {
            UploadService::MalwareBazaarUpload { .. } => {
                sender.oneshot_command(async move {
                    SubmissionsPageCommand::BazaarUploadFinished {
                        upload_attempt: upload_to_malware_bazaar(
                            &activity_history,
                            &quarantine_vault,
                            entry_id,
                        )
                        .await,
                        upload_key,
                    }
                });
            }
            UploadService::VirusTotalUpload => {
                sender.oneshot_command(async move {
                    SubmissionsPageCommand::VirusTotalUploadFinished {
                        upload_attempt: upload_to_virustotal(
                            &activity_history,
                            &quarantine_vault,
                            entry_id,
                        )
                        .await,
                        upload_key,
                    }
                });
            }
        }
    }

    fn start_read_clamav_report(
        &mut self,
        clamav_report: ClamavReport,
        submission_sample: SubmissionSample,
        sender: &ComponentSender<Self>,
    ) {
        let upload_key = UploadKey::for_target(
            &submission_sample.submitted_file.content_sha256,
            clamav_report_target(&clamav_report.report_kind),
        );
        let Some(upload_key) = self.admit_upload(upload_key, sender) else {
            return;
        };
        let activity_history = self.activity_history.clone();
        sender.oneshot_command(async move {
            SubmissionsPageCommand::ClamavReportFinished {
                report_attempt: send_read_clamav_report(
                    &activity_history,
                    &clamav_report,
                    submission_sample,
                )
                .await,
                upload_key,
            }
        });
    }
}

#[relm4::component(pub)]
impl Component for SubmissionsPage {
    type Init = SubmissionsPageInit;
    type Input = SubmissionsPageInput;
    type Output = SubmissionsPageOutput;
    type CommandOutput = SubmissionsPageCommand;

    view! {
        adw::ToastOverlay {
            connect_map => SubmissionsPageInput::PageShown,

            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    pack_end = &gtk::Stack {
                        add_named[Some(IDLE_PAGE_NAME)] = &gtk::Button {
                            set_icon_name: "view-refresh-symbolic",
                            set_tooltip_text: Some(&gettext("Check MalwareBazaar and VirusTotal for news")),
                            connect_clicked => SubmissionsPageInput::RemoteRefreshRequested,
                        },
                        add_named[Some(BUSY_PAGE_NAME)] = &adw::Spinner {
                            set_tooltip_text: Some(&gettext("Checking")),
                        },
                        #[watch]
                        set_visible_child_name: busy_page_name(model.remote_refresh_running()),
                    },
                },

                #[wrap(Some)]
                set_content = &adw::PreferencesPage {
                    add = &adw::PreferencesGroup {
                        set_title: &gettext("Submitted"),
                        set_description: Some(&gettext(
                            "Everything Lazaret sent to ClamAV, MalwareBazaar or VirusTotal, and \
                             what became of it. ClamAV reports settle after signature updates; \
                             refresh asks the other services on request.",
                        )),

                        adw::ComboRow {
                            set_title: &gettext("Service"),
                            set_model: Some(&choice_labels(
                                SERVICE_FILTER_CHOICES.map(service_filter_label).to_vec(),
                            )),
                            #[watch]
                            #[block_signal(service_filter_handler)]
                            set_selected: choice_position(
                                &SERVICE_FILTER_CHOICES,
                                &model.submission_filters.service_filter,
                            ),
                            connect_selected_notify[sender] => move |changed_row| {
                                sender.input(SubmissionsPageInput::ServiceFilterChosen(changed_row.selected()));
                            } @service_filter_handler,
                        },

                        adw::ComboRow {
                            set_title: &gettext("Status"),
                            set_model: Some(&choice_labels(
                                PROGRESS_FILTER_CHOICES.map(progress_filter_label).to_vec(),
                            )),
                            #[watch]
                            #[block_signal(progress_filter_handler)]
                            set_selected: choice_position(
                                &PROGRESS_FILTER_CHOICES,
                                &model.submission_filters.progress_filter,
                            ),
                            connect_selected_notify[sender] => move |changed_row| {
                                sender.input(SubmissionsPageInput::ProgressFilterChosen(changed_row.selected()));
                            } @progress_filter_handler,
                        },
                    },

                    add = &adw::PreferencesGroup {
                        adw::StatusPage {
                            add_css_class: "compact",
                            set_icon_name: Some("document-send-symbolic"),
                            #[watch]
                            set_visible: !model.submitted_rows_shown(),
                            #[watch]
                            set_title: &empty_submissions_text(&model.submission_listing),
                        },

                        #[local_ref]
                        submitted_list -> gtk::ListBox {
                            add_css_class: "boxed-list",
                            set_selection_mode: gtk::SelectionMode::None,
                            #[watch]
                            set_visible: model.submitted_rows_shown(),
                        },
                    },

                    add = &adw::PreferencesGroup {
                        set_title: &gettext("New Submission"),
                        set_description: Some(&gettext(
                            "Send a quarantined file, or report a file ClamAV misses. Every \
                             submission shows exactly what is sent before anything leaves this \
                             computer.",
                        )),

                        adw::ActionRow {
                            set_title: &gettext("Report Missed Malware"),
                            set_subtitle: &gettext(
                                "Pick a malicious file ClamAV doesn't detect. Lazaret reads it \
                                 without following links and sends it to ClamAV with clamsubmit.",
                            ),
                            set_subtitle_lines: 0,
                            add_suffix = &gtk::Button {
                                set_label: &gettext("Choose File…"),
                                set_valign: gtk::Align::Center,
                                connect_clicked => SubmissionsPageInput::MissedMalwareReportRequested,
                            },
                        },
                    },

                    add = &adw::PreferencesGroup {
                        set_title: &gettext("Quarantined Files"),

                        adw::StatusPage {
                            add_css_class: "compact",
                            set_icon_name: Some("folder-symbolic"),
                            #[watch]
                            set_visible: !model.candidate_rows_shown(),
                            #[watch]
                            set_title: &empty_candidates_text(&model.candidate_listing),
                        },

                        #[local_ref]
                        candidate_list -> gtk::ListBox {
                            add_css_class: "boxed-list",
                            set_selection_mode: gtk::SelectionMode::None,
                            #[watch]
                            set_visible: model.candidate_rows_shown(),
                        },
                    },

                    add = &adw::PreferencesGroup {
                        set_title: &gettext("Services & Keys"),
                        set_description: Some(&gettext(
                            "What each service receives. Lookups send only a hash or a signature \
                             name; files leave this computer only when you confirm an upload.",
                        )),

                        adw::ActionRow {
                            set_title: "ClamAV (Cisco Talos)",
                            set_subtitle: &gettext(
                                "Reports send the file, the detection name for a false positive, \
                                 and your name and email address. Talos processes samples by \
                                 automation, never makes them public and doesn't share them with \
                                 other companies. A review takes at least 48 hours. No key \
                                 needed.",
                            ),
                            set_subtitle_lines: 0,
                        },

                        adw::ActionRow {
                            set_title: "CIRCL hashlookup",
                            set_subtitle: &gettext(
                                "Reputation checks send only a file's SHA-256 hash. No key needed.",
                            ),
                            set_subtitle_lines: 0,
                        },
                    },

                    add: model.abuse_ch_section.widget(),
                    add: model.virustotal_section.widget(),
                },
            },
        }
    }

    fn init(
        page_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = Self {
            activity_history: page_init.activity_history,
            quarantine_vault: page_init.quarantine_vault,
            toaster: Toaster::new(&root),
            submission_listing: SubmissionListing::ListingLoading,
            candidate_listing: CandidateListing::CandidatesLoading,
            submission_filters: SubmissionFilters::SHOW_EVERYTHING,
            remote_refresh: RemoteRefreshRun::RefreshIdle,
            uploads_in_flight: UploadsInFlight::default(),
            submitted_rows: FactoryVecDeque::builder()
                .launch(gtk::ListBox::default())
                .forward(sender.input_sender(), |row_output| match row_output {
                    SubmittedEntryRowOutput::RemoteEntryRequested(entry_url) => {
                        SubmissionsPageInput::RemoteEntryRequested(entry_url)
                    }
                }),
            candidate_rows: FactoryVecDeque::builder()
                .launch(gtk::ListBox::default())
                .forward(sender.input_sender(), |row_output| match row_output {
                    QuarantinedCandidateRowOutput::SubmissionRequested { entry_id } => {
                        SubmissionsPageInput::EntrySubmissionRequested { entry_id }
                    }
                }),
            abuse_ch_section: ServiceKeySection::builder()
                .launch(ThreatIntelService::AbuseChService)
                .forward(sender.input_sender(), page_input_for_key_output),
            virustotal_section: ServiceKeySection::builder()
                .launch(ThreatIntelService::VirusTotalService)
                .forward(sender.input_sender(), page_input_for_key_output),
        };
        model.reload_submissions(&sender);
        model.reload_candidates(&sender);
        let submitted_list = model.submitted_rows.widget();
        let candidate_list = model.candidate_rows.widget();
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: SubmissionsPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            SubmissionsPageInput::PageShown => {
                self.reload_submissions(&sender);
                self.reload_candidates(&sender);
            }
            SubmissionsPageInput::SubmissionsChanged => self.reload_submissions(&sender),
            SubmissionsPageInput::QuarantineEntriesChanged => self.reload_candidates(&sender),
            SubmissionsPageInput::ServiceFilterChosen(chosen_position) => {
                if let Some(service_filter) = choice_at(&SERVICE_FILTER_CHOICES, chosen_position) {
                    self.submission_filters.service_filter = service_filter;
                    self.show_submitted_rows();
                }
            }
            SubmissionsPageInput::ProgressFilterChosen(chosen_position) => {
                if let Some(progress_filter) = choice_at(&PROGRESS_FILTER_CHOICES, chosen_position)
                {
                    self.submission_filters.progress_filter = progress_filter;
                    self.show_submitted_rows();
                }
            }
            SubmissionsPageInput::RemoteRefreshRequested => {
                if self.remote_refresh_running() {
                    return;
                }
                let activity_history = self.activity_history.clone();
                self.remote_refresh = RemoteRefreshRun::RefreshRunning {
                    _refresh_stream: run_stream(
                        &sender,
                        stream::once(async move {
                            SubmissionsPageCommand::RemoteRefreshFinished(
                                refresh_remote_statuses(&activity_history).await,
                            )
                        }),
                    ),
                };
            }
            SubmissionsPageInput::EntrySubmissionRequested { entry_id } => {
                match self.candidate_listing.candidate_with_id(entry_id) {
                    Some(entry_record) => self.offer_targets_for(entry_record, root, &sender),
                    None => self.toaster.add_toast(plain_text_toast(&gettext(
                        "This file is no longer in quarantine",
                    ))),
                }
            }
            SubmissionsPageInput::QuarantinedFileSubmissionRequested { original_path } => {
                match self.candidate_listing.newest_candidate_from(&original_path) {
                    Some(entry_record) => self.offer_targets_for(entry_record, root, &sender),
                    None => self.toaster.add_toast(plain_text_toast(&gettext(
                        "This file is no longer in quarantine",
                    ))),
                }
            }
            SubmissionsPageInput::TargetChosen(chosen_target) => {
                self.confirm_chosen_target(chosen_target, root, &sender);
            }
            SubmissionsPageInput::ClamavReportConfirmed(report_request) => {
                let quarantine_vault = self.quarantine_vault.clone();
                sender.oneshot_command(async move {
                    let read_outcome =
                        read_clamav_report_sample(&quarantine_vault, &report_request).await;
                    SubmissionsPageCommand::ClamavSampleRead {
                        clamav_report: report_request.clamav_report,
                        read_outcome,
                    }
                });
            }
            SubmissionsPageInput::SampleUploadConfirmed(upload_proposal) => {
                self.start_sample_upload(&upload_proposal, &sender);
            }
            SubmissionsPageInput::MissedMalwareReportRequested => {
                deliver_local_outcome(
                    sender.input_sender().clone(),
                    chosen_file_to_submit(gettext("Choose the File ClamAV Misses")),
                    |chosen_file| match chosen_file {
                        ChosenSubmissionFile::FileChosen(chosen_path) => {
                            Some(SubmissionsPageInput::MissedMalwareFileChosen(chosen_path))
                        }
                        ChosenSubmissionFile::ChoiceCancelled => None,
                    },
                );
            }
            SubmissionsPageInput::MissedMalwareFileChosen(chosen_path) => {
                present_clamav_report_confirmation(
                    root,
                    ClamavReportProposal {
                        report_kind: ClamavReportKind::MissedMalware,
                        shown_path: sanitize_scanner_line(&chosen_path.to_string_lossy()),
                        submitted_content: SubmittedContent::FileOnDisk {
                            file_path: chosen_path,
                        },
                    },
                    sender.input_sender().clone(),
                    SubmissionsPageInput::ClamavReportConfirmed,
                );
            }
            SubmissionsPageInput::RemoteEntryRequested(entry_url) => {
                gtk::UriLauncher::new(&entry_url).launch(
                    root.root().and_downcast::<gtk::Window>().as_ref(),
                    gtk::gio::Cancellable::NONE,
                    |_launch_outcome| {},
                );
            }
            SubmissionsPageInput::StoredKeyChanged => {
                let _shell_closed = sender.output(SubmissionsPageOutput::StoredKeyChanged);
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: SubmissionsPageCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            SubmissionsPageCommand::SubmissionsLoaded(load_outcome) => {
                self.submission_listing = match load_outcome {
                    Ok(listed_submissions) => SubmissionListing::ListingLoaded(listed_submissions),
                    Err(history_failure) => SubmissionListing::ListingFailed(history_failure),
                };
                self.show_submitted_rows();
                self.report_tally(&sender);
            }
            SubmissionsPageCommand::CandidatesLoaded(load_outcome) => {
                self.candidate_listing = match load_outcome {
                    Ok(listed_candidates) => CandidateListing::CandidatesLoaded(listed_candidates),
                    Err(quarantine_failure) => {
                        CandidateListing::CandidatesFailed(quarantine_failure)
                    }
                };
                self.show_candidate_rows();
            }
            SubmissionsPageCommand::ClamavSampleRead {
                clamav_report,
                read_outcome,
            } => match read_outcome {
                Ok(submission_sample) => {
                    self.start_read_clamav_report(clamav_report, submission_sample, &sender);
                }
                Err(read_failure) => Self::report_upload_notice(
                    &sender,
                    clamav_report_attempt_text(&ClamavReportAttempt::SampleUnreadable(
                        read_failure,
                    )),
                ),
            },
            SubmissionsPageCommand::ClamavReportFinished {
                upload_key,
                report_attempt,
            } => {
                self.finish_upload(
                    &upload_key,
                    clamav_report_attempt_text(&report_attempt),
                    &sender,
                );
            }
            SubmissionsPageCommand::BazaarUploadFinished {
                upload_key,
                upload_attempt,
            } => {
                self.finish_upload(
                    &upload_key,
                    bazaar_upload_attempt_text(&upload_attempt),
                    &sender,
                );
            }
            SubmissionsPageCommand::VirusTotalUploadFinished {
                upload_key,
                upload_attempt,
            } => {
                self.finish_upload(
                    &upload_key,
                    virustotal_upload_attempt_text(&upload_attempt),
                    &sender,
                );
            }
            SubmissionsPageCommand::RemoteRefreshFinished(refresh_summary) => {
                self.remote_refresh = RemoteRefreshRun::RefreshIdle;
                self.finish_sending(&refresh_summary_text(&refresh_summary), &sender);
            }
        }
    }
}

use futures::StreamExt;
use gettextrs::gettext;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller,
    abstractions::Toaster, adw, adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    application_window::protection_evidence_refresh::{EvidenceRefresh, GatheredEvidence},
    host_services::{
        activity_history::activity_history_database::{
            ActivityEntryRecord, ActivityHistory, ActivityHistoryFailure,
        },
        clamav_programs::distribution_install_guides::{
            DistributionFamily, detect_distribution_family,
        },
        desktop::{
            desktop_notifications::notify_outside_the_window,
            locale_formatting::host_moment_formatters,
        },
    },
    shared_widgets::{
        activity_entries::{
            activity_entry_row::ActivityEntryRow,
            activity_transcript_dialog::ActivityTranscriptDialog,
        },
        component_streams::run_stream_then,
        engine_settings::engine_settings_sections::{
            EngineSettingsLayout, EngineSettingsNotice, EngineSettingsSection,
            EngineSettingsSections, EngineSettingsSectionsInput, EngineSettingsSectionsOutput,
            engine_settings_notice_toast,
        },
        loading_indicators::{
            BUSY_PAGE_NAME, FirstLoad, IDLE_PAGE_NAME, LOAD_FAILED_PAGE_NAME, LOADED_PAGE_NAME,
            LOADING_PAGE_NAME, busy_page_name, loading_placeholder_stack, loading_status_page,
        },
        step_timeline::{
            step_evidence_builders::MomentContext,
            timeline_step_contents::TimelineStepRowOutput,
            timeline_step_row::{TimelineStepRow, show_timeline_steps},
        },
    },
    signatures::database_updates_page::{
        database_updates_presentation::{DatabaseUpdateAction, database_update_steps},
        database_updates_state::{
            DatabaseUpdatesPageOutput, SignatureUpdateControl, UpdateFinishEffects,
            UpdateHistoryView, UpdateStartDecision,
        },
        signature_update_run::{
            database_update_events::{DatabaseUpdateEvent, database_update_events},
            signature_update_session::{DatabaseHostStatus, load_host_status},
        },
    },
};

const UPDATE_BATCH_SIZE: usize = 64;

enum TranscriptDialogView {
    DialogClosed,
    DialogOpen {
        _transcript_dialog: Controller<ActivityTranscriptDialog>,
    },
}

pub struct DatabaseUpdatesPage {
    toaster: Toaster,
    status_rows: FactoryVecDeque<TimelineStepRow<DatabaseUpdateAction>>,
    history_rows: FactoryVecDeque<ActivityEntryRow>,
    update_history: UpdateHistoryView,
    activity_history: ActivityHistory,
    update_control: SignatureUpdateControl,
    distribution_family: DistributionFamily,
    evidence_refresh: EvidenceRefresh,
    gathered_evidence: GatheredEvidence,
    transcript_dialog: TranscriptDialogView,
    update_settings_sections: Controller<EngineSettingsSections>,
}

#[derive(Debug)]
pub enum DatabaseUpdatesPageInput {
    RefreshRequested,
    EvidenceRefreshChanged(EvidenceRefresh),
    EvidenceGathered(GatheredEvidence),
    SignatureUpdateRequested,
    SettingsRevealRequested,
    SettingsNoticeReceived(EngineSettingsNotice),
    StepRequested(TimelineStepRowOutput<DatabaseUpdateAction>),
    HistoryEntryActivated { row_position: usize },
}

#[derive(Debug)]
pub enum DatabaseUpdatesPageCommand {
    HostStatusLoaded(DatabaseHostStatus),
    UpdateBatchArrived(Vec<DatabaseUpdateEvent>),
    UpdateStreamFinished,
    ActivityRecordingFinished(Result<(), ActivityHistoryFailure>),
    HistoryLoaded(Result<Vec<ActivityEntryRecord>, ActivityHistoryFailure>),
}

fn plain_text_toast(toast_text: &str) -> adw::Toast {
    adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build()
}

pub fn page_input_for_settings_output(
    settings_output: EngineSettingsSectionsOutput,
) -> DatabaseUpdatesPageInput {
    match settings_output {
        EngineSettingsSectionsOutput::ToastRequested(settings_notice) => {
            DatabaseUpdatesPageInput::SettingsNoticeReceived(settings_notice)
        }
    }
}

impl DatabaseUpdatesPage {
    const fn first_load(&self) -> FirstLoad {
        match self.gathered_evidence {
            GatheredEvidence::NotGatheredYet => FirstLoad::StillLoading,
            GatheredEvidence::Gathered { .. } => FirstLoad::LoadFinished,
        }
    }

    fn report_output(sender: &ComponentSender<Self>, page_output: DatabaseUpdatesPageOutput) {
        let _shell_closed = sender.output(page_output);
    }

    fn history_failure_text(&self) -> String {
        match &self.update_history {
            UpdateHistoryView::HistoryLoadFailed(load_failure) => {
                gettext("Failed to load historical logs: {error}")
                    .replace("{error}", &load_failure.to_string())
            }
            UpdateHistoryView::HistoryLoading | UpdateHistoryView::HistoryLoaded(_) => {
                String::new()
            }
        }
    }

    fn show_status_steps(&mut self) {
        let GatheredEvidence::Gathered {
            protection_evidence,
            gathered_at,
        } = &self.gathered_evidence
        else {
            return;
        };
        show_timeline_steps(
            &mut self.status_rows,
            database_update_steps(
                protection_evidence,
                &self.update_control.update_view(),
                MomentContext {
                    moment_formatters: host_moment_formatters(),
                    reference_moment: *gathered_at,
                },
                self.distribution_family,
            ),
        );
    }

    fn reload_history(&self, sender: &ComponentSender<Self>) {
        let activity_history = self.activity_history.clone();
        sender.oneshot_command(async move {
            DatabaseUpdatesPageCommand::HistoryLoaded(activity_history.list_recent_entries().await)
        });
    }

    fn refresh_host_status(sender: &ComponentSender<Self>) {
        sender.oneshot_command(async {
            DatabaseUpdatesPageCommand::HostStatusLoaded(load_host_status().await)
        });
    }

    fn follow_start_decision(
        &mut self,
        start_decision: UpdateStartDecision,
        sender: &ComponentSender<Self>,
    ) {
        match start_decision {
            UpdateStartDecision::StartUpdateNow(update_plan) => {
                let update_stream = run_stream_then(
                    sender,
                    database_update_events(update_plan)
                        .ready_chunks(UPDATE_BATCH_SIZE)
                        .map(DatabaseUpdatesPageCommand::UpdateBatchArrived),
                    DatabaseUpdatesPageCommand::UpdateStreamFinished,
                );
                self.update_control
                    .update_started(update_plan, update_stream);
            }
            UpdateStartDecision::UpdateQueued | UpdateStartDecision::NothingToStart => {}
        }
        self.show_status_steps();
    }

    fn finish_update(&mut self, sender: &ComponentSender<Self>) {
        let finished_effects = match self.update_control.update_stream_ended() {
            UpdateFinishEffects::UpdateFinished(finished_effects) => finished_effects,
            UpdateFinishEffects::StaleStreamEnding => return,
        };
        notify_outside_the_window(
            "update-finished",
            &gettext("Database update finished"),
            &finished_effects.summary_line,
        );
        self.toaster
            .add_toast(plain_text_toast(&finished_effects.summary_line));
        let activity_history = self.activity_history.clone();
        let activity_entry = finished_effects.activity_entry;
        sender.oneshot_command(async move {
            DatabaseUpdatesPageCommand::ActivityRecordingFinished(
                activity_history.record_activity(activity_entry).await,
            )
        });
        Self::refresh_host_status(sender);
        self.show_status_steps();
        finished_effects
            .page_outputs
            .into_iter()
            .for_each(|page_output| Self::report_output(sender, page_output));
    }

    fn open_transcript(&mut self, row_position: usize, root: &adw::ToastOverlay) {
        let Some(activity_entry) = self.update_history.listed_entries().get(row_position) else {
            return;
        };
        let transcript_dialog = ActivityTranscriptDialog::builder()
            .launch(activity_entry.clone())
            .detach();
        transcript_dialog.widget().present(Some(root));
        self.transcript_dialog = TranscriptDialogView::DialogOpen {
            _transcript_dialog: transcript_dialog,
        };
    }
}

#[relm4::component(pub)]
impl Component for DatabaseUpdatesPage {
    type Init = ActivityHistory;
    type Input = DatabaseUpdatesPageInput;
    type Output = DatabaseUpdatesPageOutput;
    type CommandOutput = DatabaseUpdatesPageCommand;

    view! {
        adw::ToastOverlay {
            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    pack_end = &gtk::Stack {
                        add_named[Some(IDLE_PAGE_NAME)] = &gtk::Button {
                            set_icon_name: "view-refresh-symbolic",
                            set_tooltip_text: Some(&gettext("Check again")),
                            connect_clicked => DatabaseUpdatesPageInput::RefreshRequested,
                        },
                        add_named[Some(BUSY_PAGE_NAME)] = &adw::Spinner {
                            set_tooltip_text: Some(&gettext("Checking")),
                        },
                        #[watch]
                        set_visible_child_name: busy_page_name(model.evidence_refresh.is_running()),
                    },
                },

                #[wrap(Some)]
                set_content = &gtk::Stack {
                    #[local_ref]
                    add_named[Some(LOADING_PAGE_NAME)] = status_loading_page -> adw::StatusPage {},
                    add_named[Some(LOADED_PAGE_NAME)] = &adw::PreferencesPage {
                        add: status_group,
                        add: model.update_settings_sections.widget(),

                        add = &adw::PreferencesGroup {
                            set_title: &gettext("Update history"),
                            set_description: Some(&gettext("Updates started from Lazaret, newest first. Select one to read its transcript.")),

                            #[local_ref]
                            history_list -> gtk::ListBox {
                                add_css_class: "boxed-list",
                                set_selection_mode: gtk::SelectionMode::None,
                                #[wrap(Some)]
                                #[local_ref]
                                set_placeholder = history_placeholder -> gtk::Stack {
                                    add_named[Some(LOAD_FAILED_PAGE_NAME)] = &adw::StatusPage {
                                        add_css_class: "compact",
                                        set_icon_name: Some("dialog-error-symbolic"),
                                        set_title: &gettext("Historical logs can't be read"),
                                        #[watch]
                                        set_description: Some(&gtk::glib::markup_escape_text(&model.history_failure_text())),
                                    },
                                    #[watch]
                                    set_visible_child_name: model.update_history.placeholder_page_name(),
                                },
                                connect_row_activated[sender] => move |_history_list, activated_row| {
                                    sender.input(DatabaseUpdatesPageInput::HistoryEntryActivated {
                                        row_position: usize::try_from(activated_row.index()).unwrap_or_default(),
                                    });
                                },
                            },
                        },
                    },
                    #[watch]
                    set_visible_child_name: model.first_load().shown_page_name(),
                },
            },
        }
    }

    fn init(
        activity_history: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = Self {
            toaster: Toaster::new(&root),
            status_rows: FactoryVecDeque::builder()
                .launch(
                    adw::PreferencesGroup::builder()
                        .title(gettext("Status"))
                        .build(),
                )
                .forward(
                    sender.input_sender(),
                    DatabaseUpdatesPageInput::StepRequested,
                ),
            history_rows: FactoryVecDeque::builder()
                .launch(gtk::ListBox::default())
                .detach(),
            update_history: UpdateHistoryView::HistoryLoading,
            activity_history,
            update_control: SignatureUpdateControl::new(),
            distribution_family: detect_distribution_family(),
            evidence_refresh: EvidenceRefresh::NothingRunning,
            gathered_evidence: GatheredEvidence::NotGatheredYet,
            transcript_dialog: TranscriptDialogView::DialogClosed,
            update_settings_sections: EngineSettingsSections::builder()
                .launch(EngineSettingsLayout::SingleSection(
                    EngineSettingsSection::SignatureUpdates,
                ))
                .forward(sender.input_sender(), page_input_for_settings_output),
        };
        let status_group = &model.status_rows.widget().clone();
        let history_list = model.history_rows.widget();
        let history_placeholder = &loading_placeholder_stack(
            &gettext("Loading history…"),
            &adw::StatusPage::builder()
                .css_classes(["compact"])
                .icon_name("software-update-available-symbolic")
                .title(gettext("No updates were started from Lazaret yet"))
                .build(),
        );
        let status_loading_page = &loading_status_page(&gettext("Checking the signatures…"));
        let widgets = view_output!();
        Self::refresh_host_status(&sender);
        model.reload_history(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: DatabaseUpdatesPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            DatabaseUpdatesPageInput::RefreshRequested => {
                Self::report_output(&sender, DatabaseUpdatesPageOutput::EvidenceRefreshRequested);
            }
            DatabaseUpdatesPageInput::SettingsRevealRequested => {
                self.update_settings_sections
                    .emit(EngineSettingsSectionsInput::RevealRequested(
                        EngineSettingsSection::SignatureUpdates,
                    ));
            }
            DatabaseUpdatesPageInput::EvidenceRefreshChanged(evidence_refresh) => {
                self.evidence_refresh = evidence_refresh;
            }
            DatabaseUpdatesPageInput::EvidenceGathered(gathered_evidence) => {
                self.gathered_evidence = gathered_evidence;
                self.show_status_steps();
            }
            DatabaseUpdatesPageInput::SignatureUpdateRequested => {
                let start_decision = self.update_control.update_requested();
                self.follow_start_decision(start_decision, &sender);
            }
            DatabaseUpdatesPageInput::SettingsNoticeReceived(settings_notice) => {
                self.toaster
                    .add_toast(engine_settings_notice_toast(&settings_notice));
            }
            DatabaseUpdatesPageInput::StepRequested(TimelineStepRowOutput::ActionChosen(
                DatabaseUpdateAction::UpdateSignatures,
            )) => {
                let start_decision = self.update_control.update_requested();
                self.follow_start_decision(start_decision, &sender);
            }
            DatabaseUpdatesPageInput::StepRequested(TimelineStepRowOutput::ActionChosen(
                DatabaseUpdateAction::CancelSignatureUpdate,
            )) => {
                self.update_control.cancel_requested();
                self.show_status_steps();
            }
            DatabaseUpdatesPageInput::StepRequested(TimelineStepRowOutput::CopyRequested(
                copied_command,
            )) => {
                root.clipboard().set_text(&copied_command);
                self.toaster
                    .add_toast(adw::Toast::new(&gettext("Command copied to clipboard")));
            }
            DatabaseUpdatesPageInput::HistoryEntryActivated { row_position } => {
                self.open_transcript(row_position, root);
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: DatabaseUpdatesPageCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            DatabaseUpdatesPageCommand::HostStatusLoaded(host_status) => {
                let start_decision = self.update_control.host_status_loaded(host_status);
                self.follow_start_decision(start_decision, &sender);
            }
            DatabaseUpdatesPageCommand::UpdateBatchArrived(update_batch) => {
                self.update_control.absorb_update_batch(update_batch);
                self.show_status_steps();
            }
            DatabaseUpdatesPageCommand::UpdateStreamFinished => self.finish_update(&sender),
            DatabaseUpdatesPageCommand::ActivityRecordingFinished(Ok(())) => {
                self.reload_history(&sender);
                Self::report_output(&sender, DatabaseUpdatesPageOutput::ActivityRecorded);
            }
            DatabaseUpdatesPageCommand::ActivityRecordingFinished(Err(recording_failure)) => {
                self.toaster.add_toast(plain_text_toast(
                    &gettext("The update could not be added to the history: {error}")
                        .replace("{error}", &recording_failure.to_string()),
                ));
            }
            DatabaseUpdatesPageCommand::HistoryLoaded(load_outcome) => {
                self.update_history = UpdateHistoryView::from_load_outcome(load_outcome);
                let mut history_guard = self.history_rows.guard();
                history_guard.clear();
                self.update_history
                    .listed_entries()
                    .iter()
                    .cloned()
                    .for_each(|activity_entry| {
                        history_guard.push_back(activity_entry);
                    });
            }
        }
    }
}

#[cfg(test)]
mod database_updates_component_tests {
    use super::*;
    use crate::host_services::settings_helper::live_settings_client::LiveChangeOutcome;

    #[test]
    fn a_settings_toast_request_becomes_a_page_notice() {
        assert!(matches!(
            page_input_for_settings_output(EngineSettingsSectionsOutput::ToastRequested(
                EngineSettingsNotice::LiveChangeReported(LiveChangeOutcome::PreviousRestored)
            )),
            DatabaseUpdatesPageInput::SettingsNoticeReceived(
                EngineSettingsNotice::LiveChangeReported(LiveChangeOutcome::PreviousRestored)
            )
        ));
        assert!(matches!(
            page_input_for_settings_output(EngineSettingsSectionsOutput::ToastRequested(
                EngineSettingsNotice::ChangeSnippetCopied
            )),
            DatabaseUpdatesPageInput::SettingsNoticeReceived(
                EngineSettingsNotice::ChangeSnippetCopied
            )
        ));
    }
}

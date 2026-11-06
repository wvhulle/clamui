use std::{collections::HashMap, fs, path::PathBuf};

use futures::{Stream, StreamExt, stream};
use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, abstractions::Toaster, adw, adw::prelude::*, gtk,
    prelude::FactoryVecDeque,
};
use tokio::task::spawn_blocking;

use crate::{
    detections_page::{
        detected_file_state::{
            DetectedFileState, inspect_detected_file, inspect_file_without_opening,
        },
        detection_alerts::{
            JournalReplay, plan_detection_alerts, send_detection_alerts, withdraw_detection_alert,
        },
        detection_list_row::{DetectionListRow, DetectionListRowOutput},
        detections_view_state::{
            AwaitedIncident, JournalBatch, OpenedIncident, current_unix_seconds,
            detection_for_file, detections_needing_attention_first, file_state_for_detection,
            file_states_to_keep, split_journal_batch, unresolved_detection_count,
        },
        incident_timeline_presentation::{
            DeletionPrompt, DisplayedDetection, SignatureLookupState, displayed_file_name,
            incident_timeline,
        },
    },
    host_services::{
        activity_history::activity_history_database::ActivityHistory,
        clamav_programs::distribution_install_guides::{
            DistributionFamily, detect_distribution_family,
        },
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        detection_journal::{
            detection_history_store::DetectionResolution,
            detection_journal_follower::{
                JournalAccess, JournalStartPosition, detection_journal_events,
            },
            detection_journal_records::JournalDetectionRecord,
        },
        quarantine_vault::quarantine_entry_database::QuarantineVault,
        threat_intel::{
            malware_bazaar_client::look_up_signature,
            service_key_storage::{
                ResolvedApiKey, ThreatIntelService, describe_key_failure, read_api_key,
            },
        },
    },
    quarantine_page::quarantine_entries_page::describe_quarantine_failure,
    shared_widgets::{
        component_streams::{RunningStream, run_stream},
        loading_indicators::FirstLoad,
        step_timeline::{
            timeline_step_contents::{TimelineStepAction, TimelineStepRowOutput},
            timeline_step_row::{TimelineStepRow, TimelineStepRowInput},
        },
    },
};

const JOURNAL_BATCH_SIZE: usize = 256;
const LIST_VIEW_NAME: &str = "list";
const INCIDENT_VIEW_NAME: &str = "incident";

pub struct BackgroundDetectionsPage {
    activity_history: ActivityHistory,
    quarantine_vault: QuarantineVault,
    distribution_family: DistributionFamily,
    displayed_detections: Vec<DisplayedDetection>,
    journal_access: JournalAccess,
    opened_incident: OpenedIncident,
    awaited_incident: AwaitedIncident,
    application_started_unix: i64,
    deletion_prompt: DeletionPrompt,
    lookup_state: SignatureLookupState,
    first_load: FirstLoad,
    detection_list_rows: FactoryVecDeque<DetectionListRow>,
    incident_rows: FactoryVecDeque<TimelineStepRow>,
    toaster: Toaster,
    _journal_follow: RunningStream,
}

pub struct BackgroundDetectionsPageInit {
    pub activity_history: ActivityHistory,
    pub quarantine_vault: QuarantineVault,
}

#[derive(Debug)]
pub enum BackgroundDetectionsPageInput {
    ReloadRequested,
    IncidentOpened(i64),
    IncidentRequestedForFile(PathBuf),
    BackToListRequested,
    StepRequested(TimelineStepRowOutput),
}

#[derive(Debug)]
pub enum BackgroundDetectionsPageOutput {
    UnresolvedCountChanged(usize),
    QuarantineReloadNeeded,
    JournalAccessChanged(JournalAccess),
}

#[derive(Debug)]
pub enum BackgroundDetectionsPageCommand {
    DetectionsRecorded {
        newly_opened: Vec<JournalDetectionRecord>,
        journal_replay: JournalReplay,
    },
    JournalAccessChanged(JournalAccess),
    DetectionsLoaded(Vec<DisplayedDetection>),
    LoadingFailed(String),
    IncidentActionFinished {
        file_path: PathBuf,
        action_outcome: Result<IncidentActionEffect, String>,
    },
    SignatureLookupFinished(SignatureLookupState),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncidentActionEffect {
    QuarantineChanged,
    OnlyHistoryChanged,
}

fn plain_text_toast(toast_text: &str) -> adw::Toast {
    adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build()
}

async fn journal_start_point(
    activity_history: &ActivityHistory,
) -> (JournalStartPosition, JournalReplay) {
    match activity_history.saved_journal_cursor().await {
        Ok(Some(journal_cursor)) => (
            JournalStartPosition::AfterCursor { journal_cursor },
            JournalReplay::AfterSavedCursor,
        ),
        Ok(None) | Err(_) => (
            JournalStartPosition::FromOldestEntry,
            JournalReplay::FirstImport,
        ),
    }
}

async fn recorded_batch_commands(
    activity_history: ActivityHistory,
    journal_batch: JournalBatch,
    journal_replay: JournalReplay,
) -> Vec<BackgroundDetectionsPageCommand> {
    let access_commands = journal_batch
        .access_changes
        .into_iter()
        .map(BackgroundDetectionsPageCommand::JournalAccessChanged);
    let recording_command = if journal_batch.detection_records.is_empty() {
        None
    } else {
        Some(
            match activity_history
                .record_detection_batch(
                    &journal_batch.detection_records,
                    &journal_batch.last_cursor,
                )
                .await
            {
                Ok(newly_opened) => BackgroundDetectionsPageCommand::DetectionsRecorded {
                    newly_opened,
                    journal_replay,
                },
                Err(recording_failure) => {
                    BackgroundDetectionsPageCommand::LoadingFailed(recording_failure.to_string())
                }
            },
        )
    };
    access_commands.chain(recording_command).collect()
}

fn recorded_detection_updates(
    activity_history: ActivityHistory,
) -> impl Stream<Item = BackgroundDetectionsPageCommand> + Send + 'static {
    let start_history = activity_history.clone();
    stream::once(async move { journal_start_point(&start_history).await }).flat_map(
        move |(start_position, journal_replay)| {
            let recording_history = activity_history.clone();
            detection_journal_events(start_position)
                .ready_chunks(JOURNAL_BATCH_SIZE)
                .then(move |journal_events| {
                    recorded_batch_commands(
                        recording_history.clone(),
                        split_journal_batch(journal_events),
                        journal_replay,
                    )
                })
                .flat_map(stream::iter)
        },
    )
}

pub async fn load_displayed_detections(
    activity_history: ActivityHistory,
    known_file_states: HashMap<i64, DetectedFileState>,
) -> BackgroundDetectionsPageCommand {
    let stored_detections = match activity_history.list_detections().await {
        Ok(stored_detections) => stored_detections,
        Err(listing_failure) => {
            return BackgroundDetectionsPageCommand::LoadingFailed(listing_failure.to_string());
        }
    };
    let displayed_detections = spawn_blocking(move || {
        stored_detections
            .into_iter()
            .map(|stored_detection| DisplayedDetection {
                file_state: file_state_for_detection(
                    &stored_detection,
                    &known_file_states,
                    inspect_detected_file,
                    inspect_file_without_opening,
                ),
                stored_detection,
            })
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();
    BackgroundDetectionsPageCommand::DetectionsLoaded(displayed_detections)
}

async fn signature_lookup_state(signature_name: &str) -> SignatureLookupState {
    match read_api_key(ThreatIntelService::AbuseChService).await {
        Ok(ResolvedApiKey::NotConfigured) => SignatureLookupState::KeyMissing,
        Err(key_failure) => SignatureLookupState::LookupFailed {
            failure_text: describe_key_failure(&key_failure),
        },
        Ok(ResolvedApiKey::FromKeyFile(auth_key) | ResolvedApiKey::FromKeyring(auth_key)) => {
            match look_up_signature(&auth_key, signature_name).await {
                Ok(signature_lookup) => SignatureLookupState::LookupFinished(signature_lookup),
                Err(lookup_failure) => SignatureLookupState::LookupFailed {
                    failure_text: lookup_failure.to_string(),
                },
            }
        }
    }
}

async fn delete_detected_file(file_path: PathBuf) -> Result<(), String> {
    spawn_blocking(move || match inspect_detected_file(&file_path) {
        DetectedFileState::NoLongerThere => Ok(()),
        DetectedFileState::OwnedByOtherUser | DetectedFileState::StateUnknown => {
            Err(gettext("This file can't be deleted from here"))
        }
        DetectedFileState::BlockedInPlace | DetectedFileState::ReadableInPlace => {
            fs::remove_file(&file_path).map_err(|removal_failure| removal_failure.to_string())
        }
    })
    .await
    .map_err(|join_failure| join_failure.to_string())?
}

impl BackgroundDetectionsPage {
    fn start_reload(&self, sender: &ComponentSender<Self>) {
        let activity_history = self.activity_history.clone();
        sender.oneshot_command(load_displayed_detections(activity_history, HashMap::new()));
    }

    fn refresh_after_sightings(
        &self,
        newly_opened: &[JournalDetectionRecord],
        sender: &ComponentSender<Self>,
    ) {
        let activity_history = self.activity_history.clone();
        let known_file_states = file_states_to_keep(&self.displayed_detections, newly_opened);
        sender.oneshot_command(load_displayed_detections(
            activity_history,
            known_file_states,
        ));
    }

    fn shown_view_name(&self) -> &'static str {
        if self.opened_detection().is_some() {
            INCIDENT_VIEW_NAME
        } else {
            LIST_VIEW_NAME
        }
    }

    fn opened_file_name(&self) -> String {
        self.opened_detection()
            .map_or_else(String::new, |displayed_detection| {
                displayed_file_name(&displayed_detection.stored_detection)
            })
    }

    fn opened_detection(&self) -> Option<&DisplayedDetection> {
        let OpenedIncident::IncidentOpen { detection_id } = self.opened_incident else {
            return None;
        };
        self.displayed_detections
            .iter()
            .find(|displayed_detection| {
                displayed_detection.stored_detection.detection_id == detection_id
            })
    }

    fn list_description(&self) -> String {
        match &self.journal_access {
            JournalAccess::JournalUnreadable => gettext(
                "Lazaret can't read the system journal, so new background detections won't appear \
                 here. This does not mean nothing was found. Add your user to the systemd-journal \
                 group.",
            ),
            JournalAccess::FollowingFailed { failure_text } => {
                gettext("Reading the system journal stopped: {error}")
                    .replace("{error}", &sanitize_scanner_line(failure_text))
            }
            JournalAccess::FollowingJournal if self.first_load == FirstLoad::StillLoading => {
                gettext("Loading detections…")
            }
            JournalAccess::FollowingJournal if self.displayed_detections.is_empty() => {
                gettext("Nothing has been detected in the background.")
            }
            JournalAccess::FollowingJournal => {
                gettext("What on-access scanning and scheduled scans have found.")
            }
        }
    }

    fn show_detection_list(&mut self) {
        let mut row_guard = self.detection_list_rows.guard();
        row_guard.clear();
        detections_needing_attention_first(&self.displayed_detections)
            .into_iter()
            .for_each(|displayed_detection| {
                row_guard.push_back(displayed_detection);
            });
    }

    fn show_opened_incident(&mut self) {
        let Some(displayed_detection) = self.opened_detection().cloned() else {
            self.opened_incident = OpenedIncident::NoIncidentOpen;
            self.incident_rows.guard().clear();
            return;
        };
        let incident_steps = incident_timeline(
            &displayed_detection,
            self.deletion_prompt,
            &self.lookup_state,
            self.distribution_family,
        );
        if self.incident_rows.len() == incident_steps.len() {
            incident_steps
                .into_iter()
                .enumerate()
                .for_each(|positioned_step| {
                    self.incident_rows.send(
                        positioned_step.0,
                        TimelineStepRowInput::StepChanged(Box::new(positioned_step.1)),
                    );
                });
        } else {
            let mut row_guard = self.incident_rows.guard();
            row_guard.clear();
            incident_steps.into_iter().for_each(|timeline_step| {
                row_guard.push_back(timeline_step);
            });
        }
    }

    fn open_awaited_incident(&mut self) {
        let AwaitedIncident::FileAwaited { file_path } = &self.awaited_incident else {
            return;
        };
        if let Some(displayed_detection) = detection_for_file(&self.displayed_detections, file_path)
        {
            self.opened_incident = OpenedIncident::IncidentOpen {
                detection_id: displayed_detection.stored_detection.detection_id,
            };
            self.deletion_prompt = DeletionPrompt::NotAsked;
        }
        self.awaited_incident = AwaitedIncident::NothingAwaited;
    }

    fn resolve_in_background(
        &self,
        sender: &ComponentSender<Self>,
        displayed_detection: &DisplayedDetection,
        chosen_action: TimelineStepAction,
    ) {
        let activity_history = self.activity_history.clone();
        let quarantine_vault = self.quarantine_vault.clone();
        let stored_detection = displayed_detection.stored_detection.clone();
        sender.oneshot_command(async move {
            let action_outcome = async {
                let (resolution, action_effect) = match chosen_action {
                    TimelineStepAction::QuarantineIncident => {
                        quarantine_vault
                            .move_file_into_quarantine(
                                &stored_detection.file_path,
                                &stored_detection.signature_name,
                            )
                            .await
                            .map_err(|move_failure| describe_quarantine_failure(&move_failure))?;
                        (
                            DetectionResolution::MovedToQuarantine,
                            IncidentActionEffect::QuarantineChanged,
                        )
                    }
                    TimelineStepAction::DeleteIncidentFile => {
                        delete_detected_file(stored_detection.file_path.clone()).await?;
                        (
                            DetectionResolution::DeletedByUser,
                            IncidentActionEffect::OnlyHistoryChanged,
                        )
                    }
                    _dismissed => (
                        DetectionResolution::DismissedByUser,
                        IncidentActionEffect::OnlyHistoryChanged,
                    ),
                };
                activity_history
                    .resolve_detection(
                        stored_detection.detection_id,
                        resolution,
                        current_unix_seconds(),
                    )
                    .await
                    .map_err(|resolving_failure| resolving_failure.to_string())?;
                Ok(action_effect)
            }
            .await;
            BackgroundDetectionsPageCommand::IncidentActionFinished {
                file_path: stored_detection.file_path,
                action_outcome,
            }
        });
    }

    fn start_signature_lookup(&mut self, sender: &ComponentSender<Self>) {
        let Some(signature_name) = self
            .opened_detection()
            .map(|displayed_detection| displayed_detection.stored_detection.signature_name.clone())
        else {
            return;
        };
        self.lookup_state = SignatureLookupState::LookingUp;
        self.show_opened_incident();
        sender.oneshot_command(async move {
            BackgroundDetectionsPageCommand::SignatureLookupFinished(
                signature_lookup_state(&signature_name).await,
            )
        });
    }

    fn run_incident_action(
        &mut self,
        chosen_action: TimelineStepAction,
        sender: &ComponentSender<Self>,
    ) {
        match chosen_action {
            TimelineStepAction::LookUpIncidentSignature => self.start_signature_lookup(sender),
            TimelineStepAction::AskIncidentDeletion => {
                self.deletion_prompt = DeletionPrompt::AwaitingAnswer;
                self.show_opened_incident();
            }
            TimelineStepAction::CancelIncidentDeletion => {
                self.deletion_prompt = DeletionPrompt::NotAsked;
                self.show_opened_incident();
            }
            TimelineStepAction::QuarantineIncident
            | TimelineStepAction::DeleteIncidentFile
            | TimelineStepAction::DismissIncident => {
                self.deletion_prompt = DeletionPrompt::NotAsked;
                if let Some(displayed_detection) = self.opened_detection().cloned() {
                    self.resolve_in_background(sender, &displayed_detection, chosen_action);
                }
            }
            TimelineStepAction::UpdateSignatures
            | TimelineStepAction::RunScheduledScan { .. }
            | TimelineStepAction::OpenSettingsSubpage(_) => {}
        }
    }
}

#[relm4::component(pub)]
impl Component for BackgroundDetectionsPage {
    type Init = BackgroundDetectionsPageInit;
    type Input = BackgroundDetectionsPageInput;
    type Output = BackgroundDetectionsPageOutput;
    type CommandOutput = BackgroundDetectionsPageCommand;

    view! {
        adw::ToastOverlay {
            connect_map => BackgroundDetectionsPageInput::ReloadRequested,

            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    #[wrap(Some)]
                    set_title_widget = &adw::WindowTitle {
                        set_title: &gettext("Detections"),
                        #[watch]
                        set_subtitle: &model.opened_file_name(),
                    },

                    pack_start = &gtk::Button {
                        set_icon_name: "go-previous-symbolic",
                        set_tooltip_text: Some(&gettext("Back to detections")),
                        #[watch]
                        set_visible: model.opened_detection().is_some(),
                        connect_clicked => BackgroundDetectionsPageInput::BackToListRequested,
                    },
                },

                #[wrap(Some)]
                set_content = &gtk::Stack {
                    set_transition_type: gtk::StackTransitionType::Crossfade,

                    add_named[Some(LIST_VIEW_NAME)] = &adw::PreferencesPage {
                        set_title: &gettext("Detections"),

                        #[local_ref]
                        add = detection_list_group -> adw::PreferencesGroup {
                            set_title: &gettext("Detections"),
                            #[watch]
                            set_description: Some(&gtk::glib::markup_escape_text(&model.list_description())),
                            #[wrap(Some)]
                            set_header_suffix = &adw::Spinner {
                                #[watch]
                                set_visible: model.first_load == FirstLoad::StillLoading,
                            },
                        },
                    },

                    add_named[Some(INCIDENT_VIEW_NAME)] = &adw::PreferencesPage {
                        set_title: &gettext("Detection"),

                        #[local_ref]
                        add = incident_group -> adw::PreferencesGroup {},
                    },

                    #[watch]
                    set_visible_child_name: model.shown_view_name(),
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
            activity_history: page_init.activity_history.clone(),
            quarantine_vault: page_init.quarantine_vault,
            distribution_family: detect_distribution_family(),
            displayed_detections: Vec::new(),
            journal_access: JournalAccess::FollowingJournal,
            opened_incident: OpenedIncident::NoIncidentOpen,
            awaited_incident: AwaitedIncident::NothingAwaited,
            application_started_unix: current_unix_seconds(),
            deletion_prompt: DeletionPrompt::NotAsked,
            lookup_state: SignatureLookupState::NotLookedUp,
            first_load: FirstLoad::StillLoading,
            detection_list_rows: FactoryVecDeque::builder()
                .launch(adw::PreferencesGroup::default())
                .forward(sender.input_sender(), |row_output| match row_output {
                    DetectionListRowOutput::IncidentOpened(detection_id) => {
                        BackgroundDetectionsPageInput::IncidentOpened(detection_id)
                    }
                }),
            incident_rows: FactoryVecDeque::builder()
                .launch(adw::PreferencesGroup::default())
                .forward(
                    sender.input_sender(),
                    BackgroundDetectionsPageInput::StepRequested,
                ),
            toaster: Toaster::new(&root),
            _journal_follow: run_stream(
                &sender,
                recorded_detection_updates(page_init.activity_history),
            ),
        };
        let detection_list_group = model.detection_list_rows.widget();
        let incident_group = model.incident_rows.widget();
        let widgets = view_output!();
        model.start_reload(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: BackgroundDetectionsPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            BackgroundDetectionsPageInput::ReloadRequested => self.start_reload(&sender),
            BackgroundDetectionsPageInput::IncidentOpened(detection_id) => {
                self.lookup_state = SignatureLookupState::NotLookedUp;
                self.opened_incident = OpenedIncident::IncidentOpen { detection_id };
                self.deletion_prompt = DeletionPrompt::NotAsked;
                self.show_opened_incident();
            }
            BackgroundDetectionsPageInput::IncidentRequestedForFile(file_path) => {
                self.awaited_incident = AwaitedIncident::FileAwaited { file_path };
                self.start_reload(&sender);
            }
            BackgroundDetectionsPageInput::BackToListRequested => {
                self.opened_incident = OpenedIncident::NoIncidentOpen;
                self.deletion_prompt = DeletionPrompt::NotAsked;
                self.incident_rows.guard().clear();
            }
            BackgroundDetectionsPageInput::StepRequested(TimelineStepRowOutput::CopyRequested(
                copied_text,
            )) => {
                root.clipboard().set_text(&copied_text);
                self.toaster.toast(&gettext("Copied to clipboard"));
            }
            BackgroundDetectionsPageInput::StepRequested(TimelineStepRowOutput::ActionChosen(
                chosen_action,
            )) => self.run_incident_action(chosen_action, &sender),
        }
    }

    fn update_cmd(
        &mut self,
        page_command: BackgroundDetectionsPageCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            BackgroundDetectionsPageCommand::DetectionsRecorded {
                newly_opened,
                journal_replay,
            } => {
                send_detection_alerts(&plan_detection_alerts(
                    &newly_opened,
                    journal_replay,
                    self.application_started_unix,
                ));
                self.refresh_after_sightings(&newly_opened, &sender);
            }
            BackgroundDetectionsPageCommand::JournalAccessChanged(journal_access) => {
                self.journal_access = journal_access.clone();
                let _shell_closed = sender.output(
                    BackgroundDetectionsPageOutput::JournalAccessChanged(journal_access),
                );
            }
            BackgroundDetectionsPageCommand::DetectionsLoaded(displayed_detections) => {
                self.first_load = FirstLoad::LoadFinished;
                self.displayed_detections = displayed_detections;
                self.show_detection_list();
                self.open_awaited_incident();
                if self.opened_incident != OpenedIncident::NoIncidentOpen {
                    self.show_opened_incident();
                }
                let _shell_closed =
                    sender.output(BackgroundDetectionsPageOutput::UnresolvedCountChanged(
                        unresolved_detection_count(&self.displayed_detections),
                    ));
            }
            BackgroundDetectionsPageCommand::LoadingFailed(failure_text) => {
                self.toaster.add_toast(plain_text_toast(
                    &gettext("Detections could not be read: {error}")
                        .replace("{error}", &sanitize_scanner_line(&failure_text)),
                ));
            }
            BackgroundDetectionsPageCommand::SignatureLookupFinished(lookup_state) => {
                self.lookup_state = lookup_state;
                self.show_opened_incident();
            }
            BackgroundDetectionsPageCommand::IncidentActionFinished {
                file_path,
                action_outcome,
            } => {
                if action_outcome.is_ok() {
                    withdraw_detection_alert(&file_path);
                }
                match action_outcome {
                    Ok(IncidentActionEffect::QuarantineChanged) => {
                        let _shell_closed =
                            sender.output(BackgroundDetectionsPageOutput::QuarantineReloadNeeded);
                    }
                    Ok(IncidentActionEffect::OnlyHistoryChanged) => {}
                    Err(failure_text) => {
                        self.toaster
                            .add_toast(plain_text_toast(&sanitize_scanner_line(&failure_text)));
                    }
                }
                self.start_reload(&sender);
            }
        }
    }
}

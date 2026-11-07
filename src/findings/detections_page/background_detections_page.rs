use std::{collections::HashMap, fs, path::PathBuf};

use futures::{Stream, StreamExt, stream};
use gettextrs::gettext;
use jiff::Timestamp;
use relm4::{
    Component, ComponentParts, ComponentSender, abstractions::Toaster, adw, adw::prelude::*, gtk,
    prelude::FactoryVecDeque,
};
use tokio::task::spawn_blocking;

use crate::{
    findings::detections_page::{
        detected_file_state::{DetectedFileState, FileOwner, OpeningCheck, inspect_detected_file},
        detection_alerts::{
            DetectionAlert, JournalReplay, JournalResume, plan_detection_alerts,
            send_detection_alerts, withdraw_detection_alert,
        },
        detection_list_row::{DetectionListRow, DetectionListRowOutput},
        detections_view_state::{
            IncidentRequest, IncidentView, JournalBatch, detections_needing_attention_first,
            file_state_for_detection, file_states_to_keep, split_journal_batch,
            unresolved_detection_count,
        },
        incident_timeline_presentation::{
            DeletionPrompt, DisplayedDetection, IncidentStep, IncidentStepAction,
            SignatureLookupState, displayed_file_name, incident_timeline,
        },
    },
    host_services::{
        activity_history::activity_history_database::{ActivityHistory, ActivityHistoryFailure},
        clamav_programs::distribution_install_guides::{
            DistributionFamily, detect_distribution_family,
        },
        clamav_scanner::scanner_output_parser::ThreatIdentity,
        detection_journal::{
            detection_history_store::ResolutionKind,
            detection_journal_follower::{JournalAccess, detection_journal_events},
            detection_journal_records::JournalDetectionRecord,
        },
        quarantine_vault::{
            quarantine_entry_database::QuarantineVault,
            quarantine_file_moves::QuarantineMoveFailure,
        },
        threat_intel::{
            malware_bazaar_client::look_up_signature,
            service_key_storage::{ResolvedApiKey, ThreatIntelService, read_api_key},
        },
    },
    shared_widgets::{
        component_streams::{RunningStream, run_stream},
        journal_follow_failure_text::journal_follow_failure_text,
        loading_indicators::FirstLoad,
        quarantine_failure_text::describe_quarantine_failure,
        step_timeline::{
            timeline_step_contents::TimelineStepRowOutput,
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
    incident_view: IncidentView,
    application_started: Timestamp,
    first_load: FirstLoad,
    detection_list_rows: FactoryVecDeque<DetectionListRow>,
    incident_rows: FactoryVecDeque<TimelineStepRow<IncidentStepAction>>,
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
    StepRequested(TimelineStepRowOutput<IncidentStepAction>),
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
    JournalCursorUnreadable(ActivityHistoryFailure),
    DetectionsLoaded {
        displayed_detections: Vec<DisplayedDetection>,
        incident_request: IncidentRequest,
    },
    LoadingFailed(ActivityHistoryFailure),
    IncidentActionFinished {
        file_path: PathBuf,
        action_outcome: Result<IncidentActionEffect, IncidentActionFailure>,
    },
    SignatureLookupFinished {
        detection_id: i64,
        lookup_state: SignatureLookupState,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncidentActionEffect {
    QuarantineChanged,
    OnlyHistoryChanged,
}

#[derive(Debug, thiserror::Error)]
pub enum IncidentActionFailure {
    #[error("the file belongs to another user")]
    FileOwnedByOtherUser,
    #[error("the file could not be checked")]
    FileNotCheckable,
    #[error("the file could not be removed: {0}")]
    RemovalFailed(#[from] std::io::Error),
    #[error("the file check stopped unexpectedly: {0}")]
    FileCheckInterrupted(#[from] tokio::task::JoinError),
    #[error("the file could not be quarantined: {0}")]
    QuarantineFailed(#[from] QuarantineMoveFailure),
    #[error("the decision could not be saved: {0}")]
    HistoryNotUpdated(#[from] ActivityHistoryFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResolvingIncidentAction {
    QuarantineFile,
    DeleteFile,
    KeepFile,
}

impl ResolvingIncidentAction {
    const fn resolution_kind(self) -> ResolutionKind {
        match self {
            Self::QuarantineFile => ResolutionKind::MovedToQuarantine,
            Self::DeleteFile => ResolutionKind::DeletedByUser,
            Self::KeepFile => ResolutionKind::DismissedByUser,
        }
    }

    const fn action_effect(self) -> IncidentActionEffect {
        match self {
            Self::QuarantineFile => IncidentActionEffect::QuarantineChanged,
            Self::DeleteFile | Self::KeepFile => IncidentActionEffect::OnlyHistoryChanged,
        }
    }
}

fn describe_incident_action_failure(action_failure: &IncidentActionFailure) -> String {
    match action_failure {
        IncidentActionFailure::FileOwnedByOtherUser => {
            gettext("This file belongs to another user, so it can't be moved or deleted from here")
        }
        IncidentActionFailure::FileNotCheckable => {
            gettext("This file couldn't be checked, so it can't be moved or deleted from here")
        }
        IncidentActionFailure::RemovalFailed(removal_failure) => {
            gettext("The file could not be deleted: {error}")
                .replace("{error}", &removal_failure.to_string())
        }
        IncidentActionFailure::FileCheckInterrupted(_) => {
            gettext("Checking the file stopped unexpectedly")
        }
        IncidentActionFailure::QuarantineFailed(move_failure) => {
            describe_quarantine_failure(move_failure)
        }
        IncidentActionFailure::HistoryNotUpdated(history_failure) => {
            gettext("Your decision could not be saved: {error}")
                .replace("{error}", &history_failure.to_string())
        }
    }
}

fn plain_text_toast(toast_text: &str) -> adw::Toast {
    adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build()
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
                    BackgroundDetectionsPageCommand::LoadingFailed(recording_failure)
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
    stream::once(async move {
        JournalResume::from_saved_cursor(start_history.saved_journal_cursor().await)
    })
    .flat_map(move |journal_resume| {
        let recording_history = activity_history.clone();
        let start_position = journal_resume.start_position();
        let journal_replay = journal_resume.journal_replay();
        let cursor_warning = journal_resume
            .into_cursor_failure()
            .map(BackgroundDetectionsPageCommand::JournalCursorUnreadable);
        stream::iter(cursor_warning).chain(
            detection_journal_events(start_position)
                .ready_chunks(JOURNAL_BATCH_SIZE)
                .then(move |journal_events| {
                    recorded_batch_commands(
                        recording_history.clone(),
                        split_journal_batch(journal_events),
                        journal_replay,
                    )
                })
                .flat_map(stream::iter),
        )
    })
}

pub async fn load_displayed_detections(
    activity_history: ActivityHistory,
    known_file_states: HashMap<i64, DetectedFileState>,
) -> Result<Vec<DisplayedDetection>, ActivityHistoryFailure> {
    let stored_detections = activity_history.list_detections().await?;
    let displayed_detections = spawn_blocking(move || {
        stored_detections
            .into_iter()
            .map(|stored_detection| DisplayedDetection {
                file_state: file_state_for_detection(
                    &stored_detection,
                    &known_file_states,
                    inspect_detected_file,
                ),
                stored_detection,
            })
            .collect::<Vec<_>>()
    })
    .await
    .map_err(ActivityHistoryFailure::DetectedFileCheckInterrupted)?;
    Ok(displayed_detections)
}

async fn loaded_detections_command(
    activity_history: ActivityHistory,
    known_file_states: HashMap<i64, DetectedFileState>,
    incident_request: IncidentRequest,
) -> BackgroundDetectionsPageCommand {
    match load_displayed_detections(activity_history, known_file_states).await {
        Ok(displayed_detections) => BackgroundDetectionsPageCommand::DetectionsLoaded {
            displayed_detections,
            incident_request,
        },
        Err(listing_failure) => BackgroundDetectionsPageCommand::LoadingFailed(listing_failure),
    }
}

async fn signature_lookup_state(signature_name: &str) -> SignatureLookupState {
    match read_api_key(ThreatIntelService::AbuseChService).await {
        Ok(ResolvedApiKey::NotConfigured) => SignatureLookupState::KeyMissing,
        Err(key_failure) => SignatureLookupState::KeyUnreadable(key_failure),
        Ok(ResolvedApiKey::FromKeyFile(auth_key) | ResolvedApiKey::FromKeyring(auth_key)) => {
            match look_up_signature(&auth_key, signature_name).await {
                Ok(signature_lookup) => SignatureLookupState::LookupFinished(signature_lookup),
                Err(lookup_failure) => SignatureLookupState::BazaarLookupFailed(lookup_failure),
            }
        }
    }
}

async fn file_state_of_own_file(
    file_path: PathBuf,
) -> Result<DetectedFileState, IncidentActionFailure> {
    let file_state = spawn_blocking(move || {
        inspect_detected_file(&file_path, OpeningCheck::InspectWithoutOpening)
    })
    .await?;
    match file_state {
        DetectedFileState::Present {
            owner: FileOwner::OtherUser,
            ..
        } => Err(IncidentActionFailure::FileOwnedByOtherUser),
        DetectedFileState::StateUnknown => Err(IncidentActionFailure::FileNotCheckable),
        DetectedFileState::Present {
            owner: FileOwner::CurrentUser,
            ..
        }
        | DetectedFileState::NoLongerThere => Ok(file_state),
    }
}

async fn delete_detected_file(file_path: PathBuf) -> Result<(), IncidentActionFailure> {
    if file_state_of_own_file(file_path.clone()).await? == DetectedFileState::NoLongerThere {
        return Ok(());
    }
    spawn_blocking(move || fs::remove_file(&file_path)).await??;
    Ok(())
}

impl BackgroundDetectionsPage {
    fn start_reload(&self, sender: &ComponentSender<Self>, incident_request: IncidentRequest) {
        let activity_history = self.activity_history.clone();
        sender.oneshot_command(loaded_detections_command(
            activity_history,
            HashMap::new(),
            incident_request,
        ));
    }

    fn refresh_after_sightings(
        &self,
        newly_opened: &[JournalDetectionRecord],
        sender: &ComponentSender<Self>,
    ) {
        let activity_history = self.activity_history.clone();
        let known_file_states = file_states_to_keep(&self.displayed_detections, newly_opened);
        sender.oneshot_command(loaded_detections_command(
            activity_history,
            known_file_states,
            IncidentRequest::KeepShownIncident,
        ));
    }

    const fn shown_view_name(&self) -> &'static str {
        match self.incident_view {
            IncidentView::DetectionList => LIST_VIEW_NAME,
            IncidentView::IncidentOpen { .. } => INCIDENT_VIEW_NAME,
        }
    }

    fn opened_file_name(&self) -> String {
        self.opened_detection()
            .map_or_else(String::new, |displayed_detection| {
                displayed_file_name(&displayed_detection.stored_detection)
            })
    }

    fn opened_detection(&self) -> Option<&DisplayedDetection> {
        let detection_id = self.incident_view.opened_detection_id()?;
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
            JournalAccess::FollowingFailed(follow_failure) => {
                journal_follow_failure_text(follow_failure)
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

    fn opened_incident_steps(&self) -> Vec<IncidentStep> {
        let IncidentView::IncidentOpen {
            deletion_prompt,
            signature_lookup,
            ..
        } = &self.incident_view
        else {
            return Vec::new();
        };
        self.opened_detection()
            .map(|displayed_detection| {
                incident_timeline(
                    displayed_detection,
                    *deletion_prompt,
                    signature_lookup,
                    self.distribution_family,
                )
            })
            .unwrap_or_default()
    }

    fn show_incident_view(&mut self) {
        let incident_steps = self.opened_incident_steps();
        if self.incident_rows.len() == incident_steps.len() {
            (0..)
                .zip(incident_steps)
                .for_each(|(row_position, timeline_step)| {
                    self.incident_rows.send(
                        row_position,
                        TimelineStepRowInput::StepChanged(Box::new(timeline_step)),
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

    fn taken_incident_view(&mut self) -> IncidentView {
        std::mem::take(&mut self.incident_view)
    }

    fn replace_incident_view(&mut self, next_view: IncidentView) {
        self.incident_view = next_view.still_listed_in(&self.displayed_detections);
        self.show_incident_view();
    }

    fn resolve_in_background(
        &self,
        sender: &ComponentSender<Self>,
        displayed_detection: &DisplayedDetection,
        resolving_action: ResolvingIncidentAction,
    ) {
        let activity_history = self.activity_history.clone();
        let quarantine_vault = self.quarantine_vault.clone();
        let stored_detection = displayed_detection.stored_detection.clone();
        sender.oneshot_command(async move {
            let action_outcome = async {
                match resolving_action {
                    ResolvingIncidentAction::QuarantineFile => {
                        file_state_of_own_file(stored_detection.file_path.clone()).await?;
                        quarantine_vault
                            .move_file_into_quarantine(
                                &stored_detection.file_path,
                                &ThreatIdentity::Signature {
                                    signature_name: stored_detection.signature_name.clone(),
                                },
                            )
                            .await?;
                    }
                    ResolvingIncidentAction::DeleteFile => {
                        delete_detected_file(stored_detection.file_path.clone()).await?;
                    }
                    ResolvingIncidentAction::KeepFile => {}
                }
                activity_history
                    .resolve_detection(
                        stored_detection.detection_id,
                        resolving_action.resolution_kind(),
                        Timestamp::now(),
                    )
                    .await?;
                Ok(resolving_action.action_effect())
            }
            .await;
            BackgroundDetectionsPageCommand::IncidentActionFinished {
                file_path: stored_detection.file_path,
                action_outcome,
            }
        });
    }

    fn resolve_opened_incident(
        &mut self,
        sender: &ComponentSender<Self>,
        resolving_action: ResolvingIncidentAction,
    ) {
        let next_view = self
            .taken_incident_view()
            .with_deletion_prompt(DeletionPrompt::NotAsked);
        self.replace_incident_view(next_view);
        if let Some(displayed_detection) = self.opened_detection().cloned() {
            self.resolve_in_background(sender, &displayed_detection, resolving_action);
        }
    }

    fn start_signature_lookup(&mut self, sender: &ComponentSender<Self>) {
        let Some(stored_detection) = self
            .opened_detection()
            .map(|displayed_detection| displayed_detection.stored_detection.clone())
        else {
            return;
        };
        let detection_id = stored_detection.detection_id;
        let next_view = self
            .taken_incident_view()
            .with_signature_lookup(detection_id, SignatureLookupState::LookingUp);
        self.replace_incident_view(next_view);
        sender.oneshot_command(async move {
            BackgroundDetectionsPageCommand::SignatureLookupFinished {
                detection_id,
                lookup_state: signature_lookup_state(&stored_detection.signature_name).await,
            }
        });
    }

    fn run_incident_action(
        &mut self,
        chosen_action: IncidentStepAction,
        sender: &ComponentSender<Self>,
    ) {
        match chosen_action {
            IncidentStepAction::LookUpIncidentSignature => self.start_signature_lookup(sender),
            IncidentStepAction::AskIncidentDeletion => {
                let next_view = self
                    .taken_incident_view()
                    .with_deletion_prompt(DeletionPrompt::AwaitingAnswer);
                self.replace_incident_view(next_view);
            }
            IncidentStepAction::CancelIncidentDeletion => {
                let next_view = self
                    .taken_incident_view()
                    .with_deletion_prompt(DeletionPrompt::NotAsked);
                self.replace_incident_view(next_view);
            }
            IncidentStepAction::QuarantineIncident => {
                self.resolve_opened_incident(sender, ResolvingIncidentAction::QuarantineFile);
            }
            IncidentStepAction::DeleteIncidentFile => {
                self.resolve_opened_incident(sender, ResolvingIncidentAction::DeleteFile);
            }
            IncidentStepAction::DismissIncident => {
                self.resolve_opened_incident(sender, ResolvingIncidentAction::KeepFile);
            }
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
            incident_view: IncidentView::DetectionList,
            application_started: Timestamp::now(),
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
        model.start_reload(&sender, IncidentRequest::KeepShownIncident);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: BackgroundDetectionsPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            BackgroundDetectionsPageInput::ReloadRequested => {
                self.start_reload(&sender, IncidentRequest::KeepShownIncident);
            }
            BackgroundDetectionsPageInput::IncidentOpened(detection_id) => {
                self.replace_incident_view(IncidentView::freshly_opened(detection_id));
            }
            BackgroundDetectionsPageInput::IncidentRequestedForFile(file_path) => {
                self.start_reload(&sender, IncidentRequest::OpenIncidentForFile { file_path });
            }
            BackgroundDetectionsPageInput::BackToListRequested => {
                self.replace_incident_view(IncidentView::DetectionList);
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
                    self.application_started,
                ));
                self.refresh_after_sightings(&newly_opened, &sender);
            }
            BackgroundDetectionsPageCommand::JournalAccessChanged(journal_access) => {
                self.journal_access = journal_access.clone();
                let _shell_closed = sender.output(
                    BackgroundDetectionsPageOutput::JournalAccessChanged(journal_access),
                );
            }
            BackgroundDetectionsPageCommand::JournalCursorUnreadable(cursor_failure) => {
                send_detection_alerts(&[DetectionAlert::MissedDetectionsUncountable]);
                self.toaster.add_toast(plain_text_toast(
                    &gettext(
                        "Detections while Lazaret wasn't running can't be counted, because where \
                         it stopped reading the system journal could not be read: {error}",
                    )
                    .replace("{error}", &cursor_failure.to_string()),
                ));
            }
            BackgroundDetectionsPageCommand::DetectionsLoaded {
                displayed_detections,
                incident_request,
            } => {
                self.first_load = FirstLoad::LoadFinished;
                self.displayed_detections = displayed_detections;
                self.show_detection_list();
                let next_view = self
                    .taken_incident_view()
                    .with_requested_incident(&self.displayed_detections, &incident_request);
                self.replace_incident_view(next_view);
                let _shell_closed =
                    sender.output(BackgroundDetectionsPageOutput::UnresolvedCountChanged(
                        unresolved_detection_count(&self.displayed_detections),
                    ));
            }
            BackgroundDetectionsPageCommand::LoadingFailed(history_failure) => {
                self.toaster.add_toast(plain_text_toast(
                    &gettext("Detections could not be read: {error}")
                        .replace("{error}", &history_failure.to_string()),
                ));
            }
            BackgroundDetectionsPageCommand::SignatureLookupFinished {
                detection_id,
                lookup_state,
            } => {
                let next_view = self
                    .taken_incident_view()
                    .with_signature_lookup(detection_id, lookup_state);
                self.replace_incident_view(next_view);
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
                    Err(action_failure) => {
                        self.toaster.add_toast(plain_text_toast(
                            &describe_incident_action_failure(&action_failure),
                        ));
                    }
                }
                self.start_reload(&sender, IncidentRequest::KeepShownIncident);
            }
        }
    }
}

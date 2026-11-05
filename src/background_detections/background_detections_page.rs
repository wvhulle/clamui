use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use futures::StreamExt;
use gettextrs::gettext;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller, adw,
    adw::prelude::*, gtk, prelude::FactoryVecDeque,
};
use tokio::task::spawn_blocking;

use crate::{
    activity_history::activity_history_database::ActivityHistory,
    background_detections::{
        detected_file_state::{
            DetectedFileState, inspect_detected_file, inspect_file_without_opening,
        },
        detection_alerts::{
            JournalReplay, plan_detection_alerts, send_detection_alerts, withdraw_detection_alert,
        },
        detection_history_store::{DetectionResolution, StoredDetection},
        detection_journal_follower::{
            DetectionJournalEvent, JournalAccess, JournalStartPosition, detection_journal_events,
        },
        detection_journal_records::JournalDetectionRecord,
        incident_timeline_presentation::{
            DeletionPrompt, DisplayedDetection, SignatureLookupState, detection_needs_attention,
            detection_summary_text, displayed_file_name, displayed_file_path, incident_timeline,
        },
    },
    clamav_components::distribution_install_guides::{
        DistributionFamily, detect_distribution_family,
    },
    file_quarantine::{
        quarantine_entries_page::describe_quarantine_failure,
        quarantine_entry_database::QuarantineVault,
    },
    malware_scan::scanner_output_parser::sanitize_scanner_line,
    step_timeline::{
        timeline_step_model::{TimelineStepAction, TimelineStepRequest},
        timeline_step_row::{TimelineStepRow, TimelineStepRowInput},
    },
    threat_intel_lookup::{
        malware_bazaar_client::look_up_signature,
        service_key_storage::{ThreatIntelService, read_stored_api_key},
        virustotal_lookup_dialog::VirusTotalLookupDialog,
    },
};

const JOURNAL_BATCH_SIZE: usize = 256;
const LIST_VIEW_NAME: &str = "list";
const INCIDENT_VIEW_NAME: &str = "incident";

enum VirusTotalDialogHolder {
    NoDialogOpened,
    DialogOpened {
        _lookup_dialog: Controller<VirusTotalLookupDialog>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenedIncident {
    NoIncidentOpen,
    IncidentOpen { detection_id: i64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AwaitedIncident {
    NothingAwaited,
    FileAwaited { file_path: PathBuf },
}

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
    virustotal_dialog: VirusTotalDialogHolder,
    list_rows: Vec<adw::ActionRow>,
    incident_rows: FactoryVecDeque<TimelineStepRow>,
    list_group: adw::PreferencesGroup,
    view_stack: gtk::Stack,
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
    StepRequested(TimelineStepRequest),
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

fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed_time| {
            i64::try_from(elapsed_time.as_secs()).unwrap_or_default()
        })
}

fn plain_text_toast(toast_text: &str) -> adw::Toast {
    adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build()
}

fn split_journal_batch(
    journal_events: Vec<DetectionJournalEvent>,
) -> (Vec<JournalDetectionRecord>, String, Vec<JournalAccess>) {
    journal_events.into_iter().fold(
        (Vec::new(), String::new(), Vec::new()),
        |(mut detection_records, mut last_cursor, mut access_changes), journal_event| {
            match journal_event {
                DetectionJournalEvent::DetectionObserved {
                    detection_record,
                    journal_cursor,
                } => {
                    detection_records.push(detection_record);
                    last_cursor = journal_cursor;
                }
                DetectionJournalEvent::JournalUnreadable => {
                    access_changes.push(JournalAccess::JournalUnreadable);
                }
                DetectionJournalEvent::FollowingStopped { failure_text } => {
                    access_changes.push(JournalAccess::FollowingFailed { failure_text });
                }
            }
            (detection_records, last_cursor, access_changes)
        },
    )
}

async fn follow_detection_journal(
    activity_history: ActivityHistory,
    command_sender: relm4::Sender<BackgroundDetectionsPageCommand>,
) {
    let (start_position, journal_replay) = match activity_history.saved_journal_cursor().await {
        Ok(Some(journal_cursor)) => (
            JournalStartPosition::AfterCursor { journal_cursor },
            JournalReplay::AfterSavedCursor,
        ),
        Ok(None) | Err(_) => (
            JournalStartPosition::FromOldestEntry,
            JournalReplay::FirstImport,
        ),
    };
    let mut event_batches =
        Box::pin(detection_journal_events(start_position).ready_chunks(JOURNAL_BATCH_SIZE));
    while let Some(journal_events) = event_batches.next().await {
        let (detection_records, last_cursor, access_changes) = split_journal_batch(journal_events);
        access_changes.into_iter().for_each(|access_change| {
            command_sender.emit(BackgroundDetectionsPageCommand::JournalAccessChanged(
                access_change,
            ));
        });
        if detection_records.is_empty() {
            continue;
        }
        match activity_history
            .record_detection_batch(&detection_records, &last_cursor)
            .await
        {
            Ok(newly_opened) => {
                command_sender.emit(BackgroundDetectionsPageCommand::DetectionsRecorded {
                    newly_opened,
                    journal_replay,
                });
            }
            Err(recording_failure) => {
                command_sender.emit(BackgroundDetectionsPageCommand::LoadingFailed(
                    recording_failure.to_string(),
                ));
            }
        }
    }
}

pub fn file_state_for_detection(
    stored_detection: &StoredDetection,
    known_file_states: &HashMap<i64, DetectedFileState>,
    open_to_check_blocking: impl Fn(&Path) -> DetectedFileState,
    check_without_opening: impl Fn(&Path) -> DetectedFileState,
) -> DetectedFileState {
    if let Some(known_state) = known_file_states.get(&stored_detection.detection_id) {
        return *known_state;
    }
    if stored_detection.resolution == DetectionResolution::Unresolved {
        open_to_check_blocking(&stored_detection.file_path)
    } else {
        check_without_opening(&stored_detection.file_path)
    }
}

pub fn file_states_to_keep(
    displayed_detections: &[DisplayedDetection],
    newly_opened: &[JournalDetectionRecord],
) -> HashMap<i64, DetectedFileState> {
    displayed_detections
        .iter()
        .filter(|displayed_detection| {
            !newly_opened.iter().any(|detection_record| {
                detection_record.file_path == displayed_detection.stored_detection.file_path
            })
        })
        .map(|displayed_detection| {
            (
                displayed_detection.stored_detection.detection_id,
                displayed_detection.file_state,
            )
        })
        .collect()
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
    match read_stored_api_key(ThreatIntelService::AbuseChService).await {
        Ok(None) => SignatureLookupState::KeyMissing,
        Err(key_failure) => SignatureLookupState::LookupFailed {
            failure_text: key_failure.to_string(),
        },
        Ok(Some(auth_key)) => match look_up_signature(&auth_key, signature_name).await {
            Ok(signature_lookup) => SignatureLookupState::LookupFinished(signature_lookup),
            Err(lookup_failure) => SignatureLookupState::LookupFailed {
                failure_text: lookup_failure.to_string(),
            },
        },
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
                "ClamUI can't read the system journal, so new background detections won't appear \
                 here. This does not mean nothing was found. Add your user to the systemd-journal \
                 group.",
            ),
            JournalAccess::FollowingFailed { failure_text } => {
                gettext("Reading the system journal stopped: {error}")
                    .replace("{error}", &sanitize_scanner_line(failure_text))
            }
            JournalAccess::FollowingJournal if self.displayed_detections.is_empty() => {
                gettext("Nothing has been detected in the background.")
            }
            JournalAccess::FollowingJournal => {
                gettext("What on-access scanning and scheduled scans have found.")
            }
        }
    }

    fn rebuild_list_rows(&mut self, sender: &ComponentSender<Self>) {
        self.list_rows
            .drain(..)
            .for_each(|list_row| self.list_group.remove(&list_row));
        let mut sorted_detections = self.displayed_detections.iter().collect::<Vec<_>>();
        sorted_detections
            .sort_by_key(|displayed_detection| !detection_needs_attention(displayed_detection));
        self.list_rows = sorted_detections
            .into_iter()
            .map(|displayed_detection| {
                let detection_id = displayed_detection.stored_detection.detection_id;
                let list_row = adw::ActionRow::builder()
                    .use_markup(false)
                    .title(displayed_file_name(&displayed_detection.stored_detection))
                    .subtitle(detection_summary_text(displayed_detection))
                    .subtitle_lines(0)
                    .tooltip_text(displayed_file_path(&displayed_detection.stored_detection))
                    .activatable(true)
                    .build();
                let needs_attention = detection_needs_attention(displayed_detection);
                list_row.add_prefix(
                    &gtk::Image::builder()
                        .icon_name(if needs_attention {
                            "dialog-warning-symbolic"
                        } else {
                            "object-select-symbolic"
                        })
                        .css_classes([if needs_attention {
                            "warning"
                        } else {
                            "success"
                        }])
                        .build(),
                );
                list_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
                let row_sender = sender.clone();
                list_row.connect_activated(move |_activated_row| {
                    row_sender.input(BackgroundDetectionsPageInput::IncidentOpened(detection_id));
                });
                self.list_group.add(&list_row);
                list_row
            })
            .collect();
    }

    fn show_opened_incident(&mut self) {
        let Some(displayed_detection) = self.opened_detection().cloned() else {
            self.opened_incident = OpenedIncident::NoIncidentOpen;
            self.incident_rows.guard().clear();
            self.view_stack.set_visible_child_name(LIST_VIEW_NAME);
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
        self.view_stack.set_visible_child_name(INCIDENT_VIEW_NAME);
    }

    fn open_awaited_incident(&mut self) {
        let AwaitedIncident::FileAwaited { file_path } = &self.awaited_incident else {
            return;
        };
        if let Some(displayed_detection) =
            self.displayed_detections
                .iter()
                .find(|displayed_detection| {
                    displayed_detection.stored_detection.file_path == *file_path
                })
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

    fn open_virustotal_dialog(&mut self, root: &adw::ToastOverlay) {
        let Some(file_path) = self
            .opened_detection()
            .map(|displayed_detection| displayed_detection.stored_detection.file_path.clone())
        else {
            return;
        };
        let lookup_dialog = VirusTotalLookupDialog::builder().launch(file_path).detach();
        lookup_dialog.widget().present(Some(root));
        self.virustotal_dialog = VirusTotalDialogHolder::DialogOpened {
            _lookup_dialog: lookup_dialog,
        };
    }

    fn run_incident_action(
        &mut self,
        chosen_action: TimelineStepAction,
        sender: &ComponentSender<Self>,
        root: &adw::ToastOverlay,
    ) {
        match chosen_action {
            TimelineStepAction::LookUpIncidentSignature => self.start_signature_lookup(sender),
            TimelineStepAction::CheckIncidentOnVirusTotal => self.open_virustotal_dialog(root),
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
            | TimelineStepAction::OpenSchedulePreferences => {}
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
            #[wrap(Some)]
            #[local_ref]
            set_child = stack_widget -> gtk::Stack {
                set_transition_type: gtk::StackTransitionType::Crossfade,

                add_named[Some(LIST_VIEW_NAME)] = &adw::PreferencesPage {
                    set_title: &gettext("Detections"),
                    add: list_group_widget,
                },

                add_named[Some(INCIDENT_VIEW_NAME)] = &adw::PreferencesPage {
                    set_title: &gettext("Detection"),

                    add = &adw::PreferencesGroup {
                        #[watch]
                        set_title: &gtk::glib::markup_escape_text(&model.opened_detection().map_or_else(String::new, |displayed_detection| displayed_file_name(&displayed_detection.stored_detection))),
                        #[wrap(Some)]
                        set_header_suffix = &gtk::Button {
                            set_icon_name: "go-previous-symbolic",
                            set_tooltip_text: Some(&gettext("Back to detections")),
                            set_valign: gtk::Align::Center,
                            add_css_class: "flat",
                            connect_clicked => BackgroundDetectionsPageInput::BackToListRequested,
                        },
                    },

                    add: incident_group_widget,
                },
            },
        }
    }

    fn init(
        page_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let incident_rows = FactoryVecDeque::builder()
            .launch(adw::PreferencesGroup::default())
            .forward(
                sender.input_sender(),
                BackgroundDetectionsPageInput::StepRequested,
            );
        let list_group = adw::PreferencesGroup::builder()
            .title(gettext("Detections"))
            .build();
        let view_stack = gtk::Stack::new();
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
            virustotal_dialog: VirusTotalDialogHolder::NoDialogOpened,
            list_rows: Vec::new(),
            incident_rows,
            list_group: list_group.clone(),
            view_stack: view_stack.clone(),
        };
        let stack_widget = &view_stack;
        let list_group_widget = &list_group;
        let incident_group = model.incident_rows.widget().clone();
        let incident_group_widget = &incident_group;
        let widgets = view_output!();
        model
            .list_group
            .set_description(Some(&gtk::glib::markup_escape_text(
                &model.list_description(),
            )));
        let followed_history = page_init.activity_history;
        sender.command(|command_sender, shutdown_receiver| {
            shutdown_receiver
                .register(follow_detection_journal(followed_history, command_sender))
                .drop_on_shutdown()
        });
        let visibility_sender = sender.clone();
        root.connect_map(move |_mapped_page| {
            visibility_sender.input(BackgroundDetectionsPageInput::ReloadRequested);
        });
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
                self.view_stack.set_visible_child_name(LIST_VIEW_NAME);
            }
            BackgroundDetectionsPageInput::StepRequested(TimelineStepRequest::CopyRequested(
                copied_text,
            )) => {
                root.clipboard().set_text(&copied_text);
                root.add_toast(adw::Toast::new(&gettext("Copied to clipboard")));
            }
            BackgroundDetectionsPageInput::StepRequested(TimelineStepRequest::ActionChosen(
                chosen_action,
            )) => self.run_incident_action(chosen_action, &sender, root),
        }
    }

    fn update_cmd(
        &mut self,
        page_command: BackgroundDetectionsPageCommand,
        sender: ComponentSender<Self>,
        root: &Self::Root,
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
                self.list_group
                    .set_description(Some(&gtk::glib::markup_escape_text(
                        &self.list_description(),
                    )));
            }
            BackgroundDetectionsPageCommand::DetectionsLoaded(displayed_detections) => {
                self.displayed_detections = displayed_detections;
                self.list_group
                    .set_description(Some(&gtk::glib::markup_escape_text(
                        &self.list_description(),
                    )));
                self.rebuild_list_rows(&sender);
                self.open_awaited_incident();
                if self.opened_incident != OpenedIncident::NoIncidentOpen {
                    self.show_opened_incident();
                }
                let _shell_closed =
                    sender.output(BackgroundDetectionsPageOutput::UnresolvedCountChanged(
                        self.displayed_detections
                            .iter()
                            .filter(|displayed_detection| {
                                detection_needs_attention(displayed_detection)
                            })
                            .count(),
                    ));
            }
            BackgroundDetectionsPageCommand::LoadingFailed(failure_text) => {
                root.add_toast(plain_text_toast(
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
                        root.add_toast(plain_text_toast(&sanitize_scanner_line(&failure_text)));
                    }
                }
                self.start_reload(&sender);
            }
        }
    }
}

#[cfg(test)]
mod background_detections_page_tests {
    use std::{cell::Cell, path::PathBuf};

    use super::*;
    use crate::background_detections::detection_journal_records::DetectionSource;

    fn stored_detection(detection_id: i64, resolution: DetectionResolution) -> StoredDetection {
        StoredDetection {
            detection_id,
            file_path: PathBuf::from("/home/user/Downloads/blocked.exe"),
            signature_name: "Win.Test-1".to_owned(),
            found_on_access: true,
            found_by_schedule: false,
            first_seen_unix: 1,
            last_seen_unix: 2,
            sighting_count: 1,
            resolution,
            resolved_at_unix: 0,
        }
    }

    fn opens_needed_for(
        detection: &StoredDetection,
        known_file_states: &HashMap<i64, DetectedFileState>,
    ) -> u32 {
        let open_count = Cell::new(0);
        let _file_state = file_state_for_detection(
            detection,
            known_file_states,
            |_file_path| {
                open_count.set(open_count.get() + 1);
                DetectedFileState::BlockedInPlace
            },
            |_file_path| DetectedFileState::ReadableInPlace,
        );
        open_count.get()
    }

    #[test]
    fn a_repeat_sighting_never_reopens_the_file_because_that_would_cause_another_sighting() {
        let detection = stored_detection(7, DetectionResolution::Unresolved);
        let displayed_detections = [DisplayedDetection {
            stored_detection: detection.clone(),
            file_state: DetectedFileState::BlockedInPlace,
        }];
        assert_eq!(
            opens_needed_for(&detection, &file_states_to_keep(&displayed_detections, &[])),
            0
        );
    }

    #[test]
    fn a_new_or_reopened_detection_is_checked_once() {
        let detection = stored_detection(7, DetectionResolution::Unresolved);
        assert_eq!(opens_needed_for(&detection, &HashMap::new()), 1);
        let displayed_detections = [DisplayedDetection {
            stored_detection: detection.clone(),
            file_state: DetectedFileState::NoLongerThere,
        }];
        let reopened_record = JournalDetectionRecord {
            observed_at_unix: 3,
            detection_source: DetectionSource::OnAccessScanner,
            file_path: detection.file_path.clone(),
            signature_name: detection.signature_name.clone(),
        };
        assert_eq!(
            opens_needed_for(
                &detection,
                &file_states_to_keep(&displayed_detections, &[reopened_record])
            ),
            1
        );
    }

    #[test]
    fn resolved_detections_are_never_opened() {
        assert_eq!(
            opens_needed_for(
                &stored_detection(7, DetectionResolution::DismissedByUser),
                &HashMap::new()
            ),
            0
        );
    }

    #[test]
    fn a_journal_batch_keeps_the_last_cursor_and_reports_access_problems() {
        let detection_record = JournalDetectionRecord {
            observed_at_unix: 1,
            detection_source: DetectionSource::OnAccessScanner,
            file_path: PathBuf::from("/tmp/file"),
            signature_name: "Win.Test-1".to_owned(),
        };
        let (detection_records, last_cursor, access_changes) = split_journal_batch(vec![
            DetectionJournalEvent::DetectionObserved {
                detection_record: detection_record.clone(),
                journal_cursor: "cursor-a".to_owned(),
            },
            DetectionJournalEvent::DetectionObserved {
                detection_record,
                journal_cursor: "cursor-b".to_owned(),
            },
            DetectionJournalEvent::JournalUnreadable,
        ]);
        assert_eq!(detection_records.len(), 2);
        assert_eq!(last_cursor, "cursor-b");
        assert_eq!(access_changes, vec![JournalAccess::JournalUnreadable]);
    }
}

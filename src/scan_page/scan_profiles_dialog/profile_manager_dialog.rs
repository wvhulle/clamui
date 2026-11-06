use gettextrs::gettext;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller,
    abstractions::Toaster,
    adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryVecDeque},
};

use crate::{
    scan_page::scan_profiles_dialog::{
        profile_display_text::{describe_profile_store_failure, displayed_profile_name},
        profile_editor_dialog::{
            ProfileEditorDialog, ProfileEditorDialogInit, ProfileEditorDialogOutput,
        },
        scan_profile_row::{ScanProfileRow, ScanProfileRowOutput},
        scan_profile_store::{
            EditTarget, ProfileDraft, ProfileId, ProfileOrigin, ProfileStoreFailure, ScanProfile,
            ScanProfileStore, exported_profile_json, run_blocking_profile_task,
        },
    },
    shared_widgets::awaited_dialogs::{
        ImportedFileOutcome, TextExportOutcome, alert_response, deliver_local_outcome,
        describe_export_failure, exported_text, imported_file,
    },
};

enum OpenProfileEditor {
    NoEditorOpen,
    EditorOpen {
        _profile_editor: Controller<ProfileEditorDialog>,
    },
}

pub struct ProfileManagerDialog {
    profile_store: ScanProfileStore,
    profile_rows: FactoryVecDeque<ScanProfileRow>,
    open_editor: OpenProfileEditor,
    toaster: Toaster,
}

#[derive(Clone, Debug)]
pub enum ConfirmedProfileChange {
    DefaultsRestored,
    ProfileDeleted { profile_id: ProfileId },
}

#[derive(Clone, Copy, Debug)]
pub enum CompletedProfileChange {
    DefaultsRestored,
    ProfileDeleted,
    ProfileImported,
}

#[derive(Debug)]
pub enum ProfileManagerDialogInput {
    ReloadRequested,
    NewProfileRequested,
    ImportRequested,
    RestoreDefaultsRequested,
    RunRequested(DynamicIndex),
    EditRequested(DynamicIndex),
    DeleteRequested(DynamicIndex),
    ExportRequested(DynamicIndex),
    ChangeConfirmed(ConfirmedProfileChange),
}

#[derive(Debug)]
pub enum ProfileManagerDialogOutput {
    ProfilesChanged,
    ProfileRunRequested(ScanProfile),
}

#[derive(Debug)]
pub enum ProfileManagerDialogCommand {
    ProfilesLoaded(Result<Vec<ScanProfile>, ProfileStoreFailure>),
    ImportedFileRead(ImportedFileOutcome),
    StoreChangeFinished {
        completed_change: CompletedProfileChange,
        change_outcome: Result<(), ProfileStoreFailure>,
    },
    ExportFinished(TextExportOutcome),
}

fn present_change_confirmation(
    confirmation_title: String,
    confirmation_body: String,
    confirm_label: String,
    confirmed_change: ConfirmedProfileChange,
    root: &adw::Dialog,
    sender: &ComponentSender<ProfileManagerDialog>,
) {
    let confirmation_dialog =
        adw::AlertDialog::new(Some(&confirmation_title), Some(&confirmation_body));
    confirmation_dialog.add_response("cancel", &gettext("Cancel"));
    confirmation_dialog.add_response("confirm", &confirm_label);
    confirmation_dialog.set_response_appearance("confirm", adw::ResponseAppearance::Destructive);
    confirmation_dialog.set_close_response("cancel");
    deliver_local_outcome(
        sender.input_sender().clone(),
        alert_response(confirmation_dialog, root.clone().upcast()),
        move |chosen_response| {
            (chosen_response == "confirm")
                .then_some(ProfileManagerDialogInput::ChangeConfirmed(confirmed_change))
        },
    );
}

fn completed_change_text(completed_change: CompletedProfileChange) -> String {
    match completed_change {
        CompletedProfileChange::DefaultsRestored => gettext("Default profiles restored"),
        CompletedProfileChange::ProfileDeleted => gettext("Profile deleted"),
        CompletedProfileChange::ProfileImported => gettext("Profile imported"),
    }
}

fn plain_text_toast(toast_text: &str) -> adw::Toast {
    adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build()
}

impl ProfileManagerDialog {
    fn reload_profiles(&self, sender: &ComponentSender<Self>) {
        let profile_store = self.profile_store.clone();
        sender.oneshot_command(async move {
            ProfileManagerDialogCommand::ProfilesLoaded(
                run_blocking_profile_task(move || profile_store.load_profiles()).await,
            )
        });
    }

    fn change_store(
        &self,
        sender: &ComponentSender<Self>,
        completed_change: CompletedProfileChange,
        store_change: impl FnOnce(&ScanProfileStore) -> Result<(), ProfileStoreFailure> + Send + 'static,
    ) {
        let profile_store = self.profile_store.clone();
        sender.oneshot_command(async move {
            ProfileManagerDialogCommand::StoreChangeFinished {
                completed_change,
                change_outcome: run_blocking_profile_task(move || store_change(&profile_store))
                    .await,
            }
        });
    }

    fn profile_at(&self, row_index: &DynamicIndex) -> Option<ScanProfile> {
        self.profile_rows
            .get(row_index.current_index())
            .map(|profile_row| profile_row.scan_profile.clone())
    }

    fn open_profile_editor(
        &mut self,
        edit_target: EditTarget,
        profile_draft: ProfileDraft,
        root: &adw::Dialog,
        sender: &ComponentSender<Self>,
    ) {
        let profile_editor = ProfileEditorDialog::builder()
            .launch(ProfileEditorDialogInit {
                profile_store: self.profile_store.clone(),
                edit_target,
                profile_draft,
            })
            .forward(sender.input_sender(), |editor_output| match editor_output {
                ProfileEditorDialogOutput::ProfileSaved => {
                    ProfileManagerDialogInput::ReloadRequested
                }
            });
        profile_editor.widget().present(Some(root));
        self.open_editor = OpenProfileEditor::EditorOpen {
            _profile_editor: profile_editor,
        };
    }
}

#[relm4::component(pub)]
impl Component for ProfileManagerDialog {
    type Init = ScanProfileStore;
    type Input = ProfileManagerDialogInput;
    type Output = ProfileManagerDialogOutput;
    type CommandOutput = ProfileManagerDialogCommand;

    view! {
        adw::Dialog {
            set_title: &gettext("Manage Profiles"),
            set_content_width: 560,
            set_content_height: 520,

            #[wrap(Some)]
            #[local_ref]
            set_child = toast_overlay -> adw::ToastOverlay {
                #[wrap(Some)]
                set_child = &adw::ToolbarView {
                    add_top_bar = &adw::HeaderBar {
                        pack_start = &gtk::Button {
                            set_icon_name: "edit-undo-symbolic",
                            set_tooltip_text: Some(&gettext("Restore Defaults")),
                            connect_clicked => ProfileManagerDialogInput::RestoreDefaultsRequested,
                        },

                        pack_end = &gtk::Button {
                            set_icon_name: "list-add-symbolic",
                            set_tooltip_text: Some(&gettext("New Profile")),
                            add_css_class: "suggested-action",
                            connect_clicked => ProfileManagerDialogInput::NewProfileRequested,
                        },

                        pack_end = &gtk::Button {
                            set_icon_name: "document-open-symbolic",
                            set_tooltip_text: Some(&gettext("Import")),
                            connect_clicked => ProfileManagerDialogInput::ImportRequested,
                        },
                    },

                    #[wrap(Some)]
                    set_content = &adw::PreferencesPage {
                        add = &adw::PreferencesGroup {
                            set_title: &gettext("Scan Profiles"),
                            set_description: Some(&gettext("Select a profile to edit or use for scanning")),

                            #[local_ref]
                            profile_list -> gtk::ListBox {
                                add_css_class: "boxed-list",
                                set_selection_mode: gtk::SelectionMode::None,
                            },
                        },
                    },
                },
            },
        }
    }

    fn init(
        profile_store: ScanProfileStore,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let profile_rows = FactoryVecDeque::builder()
            .launch(gtk::ListBox::default())
            .forward(sender.input_sender(), |row_output| match row_output {
                ScanProfileRowOutput::ScanRequested(row_index) => {
                    ProfileManagerDialogInput::RunRequested(row_index)
                }
                ScanProfileRowOutput::EditRequested(row_index) => {
                    ProfileManagerDialogInput::EditRequested(row_index)
                }
                ScanProfileRowOutput::DeletionRequested(row_index) => {
                    ProfileManagerDialogInput::DeleteRequested(row_index)
                }
                ScanProfileRowOutput::ExportRequested(row_index) => {
                    ProfileManagerDialogInput::ExportRequested(row_index)
                }
            });
        let model = Self {
            profile_store,
            profile_rows,
            open_editor: OpenProfileEditor::NoEditorOpen,
            toaster: Toaster::default(),
        };
        let toast_overlay = model.toaster.overlay_widget();
        let profile_list = model.profile_rows.widget();
        let widgets = view_output!();
        model.reload_profiles(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        manager_input: ProfileManagerDialogInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match manager_input {
            ProfileManagerDialogInput::ReloadRequested => {
                self.reload_profiles(&sender);
                let _page_closed = sender.output(ProfileManagerDialogOutput::ProfilesChanged);
            }
            ProfileManagerDialogInput::NewProfileRequested => {
                self.open_profile_editor(
                    EditTarget::NewProfile,
                    ProfileDraft::default(),
                    root,
                    &sender,
                );
            }
            ProfileManagerDialogInput::ImportRequested => deliver_local_outcome(
                sender.command_sender().clone(),
                imported_file(gettext("Import")),
                |import_outcome| {
                    Some(ProfileManagerDialogCommand::ImportedFileRead(
                        import_outcome,
                    ))
                },
            ),
            ProfileManagerDialogInput::RestoreDefaultsRequested => present_change_confirmation(
                gettext("Restore Default Profiles"),
                gettext(
                    "Restore the built-in default profiles? Any customizations to default \
                     profiles will be reset; custom profiles are preserved.",
                ),
                gettext("Restore Defaults"),
                ConfirmedProfileChange::DefaultsRestored,
                root,
                &sender,
            ),
            ProfileManagerDialogInput::RunRequested(row_index) => {
                if let Some(run_profile) = self.profile_at(&row_index) {
                    let _page_closed =
                        sender.output(ProfileManagerDialogOutput::ProfileRunRequested(run_profile));
                    root.close();
                }
            }
            ProfileManagerDialogInput::EditRequested(row_index) => {
                if let Some(edited_profile) = self.profile_at(&row_index) {
                    self.open_profile_editor(
                        EditTarget::ExistingProfile(edited_profile.profile_origin),
                        edited_profile.profile_draft,
                        root,
                        &sender,
                    );
                }
            }
            ProfileManagerDialogInput::DeleteRequested(row_index) => {
                if let Some(deleted_profile) = self.profile_at(&row_index) {
                    let deleted_name = displayed_profile_name(&deleted_profile);
                    match deleted_profile.profile_origin {
                        ProfileOrigin::Custom { profile_id } => present_change_confirmation(
                            gettext("Delete Profile"),
                            gettext("Delete the profile '{name}'?")
                                .replace("{name}", &deleted_name),
                            gettext("Delete"),
                            ConfirmedProfileChange::ProfileDeleted { profile_id },
                            root,
                            &sender,
                        ),
                        ProfileOrigin::Builtin(_protected_builtin) => {}
                    }
                }
            }
            ProfileManagerDialogInput::ChangeConfirmed(
                ConfirmedProfileChange::DefaultsRestored,
            ) => {
                self.change_store(
                    &sender,
                    CompletedProfileChange::DefaultsRestored,
                    ScanProfileStore::restore_builtin_profiles,
                );
            }
            ProfileManagerDialogInput::ChangeConfirmed(
                ConfirmedProfileChange::ProfileDeleted { profile_id },
            ) => {
                self.change_store(
                    &sender,
                    CompletedProfileChange::ProfileDeleted,
                    move |profile_store| profile_store.delete_custom_profile(&profile_id),
                );
            }
            ProfileManagerDialogInput::ExportRequested(row_index) => {
                match self
                    .profile_at(&row_index)
                    .map(|exported_profile| exported_profile_json(&exported_profile))
                {
                    Some(Ok(exported_json)) => deliver_local_outcome(
                        sender.command_sender().clone(),
                        exported_text("lazaret-profile.json".to_owned(), exported_json),
                        |export_outcome| {
                            Some(ProfileManagerDialogCommand::ExportFinished(export_outcome))
                        },
                    ),
                    Some(Err(export_failure)) => {
                        self.toaster
                            .add_toast(plain_text_toast(&describe_profile_store_failure(
                                &export_failure,
                            )))
                    }
                    None => {}
                }
            }
        }
    }

    fn update_cmd(
        &mut self,
        manager_command: ProfileManagerDialogCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match manager_command {
            ProfileManagerDialogCommand::ProfilesLoaded(Ok(loaded_profiles)) => {
                let mut profile_rows_guard = self.profile_rows.guard();
                profile_rows_guard.clear();
                loaded_profiles.into_iter().for_each(|loaded_profile| {
                    profile_rows_guard.push_back(loaded_profile);
                });
            }
            ProfileManagerDialogCommand::ProfilesLoaded(Err(load_failure)) => {
                self.toaster
                    .add_toast(plain_text_toast(&describe_profile_store_failure(
                        &load_failure,
                    )));
            }
            ProfileManagerDialogCommand::ImportedFileRead(ImportedFileOutcome::FileRead(
                imported_bytes,
            )) => {
                self.change_store(
                    &sender,
                    CompletedProfileChange::ProfileImported,
                    move |profile_store| {
                        profile_store
                            .import_profile(&imported_bytes)
                            .map(|_imported_profile| ())
                    },
                );
            }
            ProfileManagerDialogCommand::ImportedFileRead(ImportedFileOutcome::ImportCancelled)
            | ProfileManagerDialogCommand::ExportFinished(TextExportOutcome::ExportCancelled) => {}
            ProfileManagerDialogCommand::ImportedFileRead(ImportedFileOutcome::ImportFailed(
                read_failure,
            )) => {
                self.toaster
                    .add_toast(plain_text_toast(&describe_export_failure(&read_failure)));
            }
            ProfileManagerDialogCommand::StoreChangeFinished {
                completed_change,
                change_outcome: Ok(()),
            } => {
                self.toaster
                    .add_toast(plain_text_toast(&completed_change_text(completed_change)));
                sender.input(ProfileManagerDialogInput::ReloadRequested);
            }
            ProfileManagerDialogCommand::StoreChangeFinished {
                change_outcome: Err(change_failure),
                ..
            } => self
                .toaster
                .add_toast(plain_text_toast(&describe_profile_store_failure(
                    &change_failure,
                ))),
            ProfileManagerDialogCommand::ExportFinished(TextExportOutcome::TextSaved) => {
                self.toaster
                    .add_toast(plain_text_toast(&gettext("Profile exported")));
            }
            ProfileManagerDialogCommand::ExportFinished(TextExportOutcome::ExportFailed(
                export_failure,
            )) => {
                self.toaster
                    .add_toast(plain_text_toast(&describe_export_failure(&export_failure)));
            }
        }
    }
}

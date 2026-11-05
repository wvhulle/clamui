use gettextrs::gettext;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller, adw,
    adw::prelude::*,
    gtk,
    gtk::gio,
    prelude::{DynamicIndex, FactoryVecDeque},
};

use crate::{
    scan_profiles::{
        profile_editor_dialog::{
            ProfileEditorDialog, ProfileEditorDialogInit, ProfileEditorDialogOutput,
        },
        scan_profile_row::{ScanProfileRow, ScanProfileRowOutput},
        scan_profile_store::{ScanProfile, ScanProfileStore, exported_profile_json},
    },
    text_export_dialog::{TextExportOutcome, describe_export_failure, save_text_with_dialog},
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
}

#[derive(Debug)]
pub enum ProfileManagerDialogInput {
    ReloadRequested,
    NewProfileRequested,
    ImportRequested,
    RestoreDefaultsRequested,
    RestoreDefaultsConfirmed,
    RunRequested(DynamicIndex),
    EditRequested(DynamicIndex),
    DeleteRequested(DynamicIndex),
    DeleteConfirmed { profile_id: String },
    ExportRequested(DynamicIndex),
    ImportedFileChosen(gio::File),
}

#[derive(Debug)]
pub enum ProfileManagerDialogOutput {
    ProfilesChanged,
    RunProfile(ScanProfile),
}

#[derive(Debug)]
pub enum ProfileManagerDialogCommand {
    ImportedBytesRead(Result<Vec<u8>, relm4::gtk::glib::Error>),
    ExportFinished(TextExportOutcome),
}

impl ProfileManagerDialog {
    fn reload_profiles(&mut self, toast_overlay: &adw::ToastOverlay) {
        match self.profile_store.load_profiles() {
            Ok(loaded_profiles) => {
                let mut profile_rows_guard = self.profile_rows.guard();
                profile_rows_guard.clear();
                loaded_profiles.into_iter().for_each(|loaded_profile| {
                    profile_rows_guard.push_back(loaded_profile);
                });
            }
            Err(load_failure) => {
                toast_overlay.add_toast(adw::Toast::new(&load_failure.to_string()));
            }
        }
    }

    fn profile_at(&self, row_index: &DynamicIndex) -> Option<ScanProfile> {
        self.profile_rows
            .get(row_index.current_index())
            .map(|profile_row| profile_row.scan_profile.clone())
    }

    fn open_profile_editor(
        &mut self,
        edited_profile: ScanProfile,
        root: &adw::Dialog,
        sender: &ComponentSender<Self>,
    ) {
        let profile_editor = ProfileEditorDialog::builder()
            .launch(ProfileEditorDialogInit {
                profile_store: self.profile_store.clone(),
                edited_profile,
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

fn confirm_action(
    confirmation_title: String,
    confirmation_body: String,
    confirm_label: String,
    confirmed_input: ProfileManagerDialogInput,
    root: &adw::Dialog,
    sender: &ComponentSender<ProfileManagerDialog>,
) {
    let confirmation_dialog =
        adw::AlertDialog::new(Some(&confirmation_title), Some(&confirmation_body));
    confirmation_dialog.add_response("cancel", &gettext("Cancel"));
    confirmation_dialog.add_response("confirm", &confirm_label);
    confirmation_dialog.set_response_appearance("confirm", adw::ResponseAppearance::Destructive);
    confirmation_dialog.set_close_response("cancel");
    let input_sender = sender.input_sender().clone();
    let confirmed_input = std::cell::Cell::new(Some(confirmed_input));
    confirmation_dialog.connect_response(Some("confirm"), move |_dialog, _response| {
        if let Some(confirmed_input) = confirmed_input.take() {
            input_sender.emit(confirmed_input);
        }
    });
    confirmation_dialog.present(Some(root));
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
            #[name = "toast_overlay"]
            set_child = &adw::ToastOverlay {
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
                ScanProfileRowOutput::StartScan(row_index) => {
                    ProfileManagerDialogInput::RunRequested(row_index)
                }
                ScanProfileRowOutput::OpenEditor(row_index) => {
                    ProfileManagerDialogInput::EditRequested(row_index)
                }
                ScanProfileRowOutput::ConfirmDeletion(row_index) => {
                    ProfileManagerDialogInput::DeleteRequested(row_index)
                }
                ScanProfileRowOutput::SaveExport(row_index) => {
                    ProfileManagerDialogInput::ExportRequested(row_index)
                }
            });
        let mut model = Self {
            profile_store,
            profile_rows,
            open_editor: OpenProfileEditor::NoEditorOpen,
        };
        let profile_list = model.profile_rows.widget().clone();
        let widgets = view_output!();
        model.reload_profiles(&widgets.toast_overlay);
        ComponentParts { model, widgets }
    }

    fn update_with_view(
        &mut self,
        widgets: &mut Self::Widgets,
        manager_input: ProfileManagerDialogInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match manager_input {
            ProfileManagerDialogInput::ReloadRequested => {
                self.reload_profiles(&widgets.toast_overlay);
                let _page_closed = sender.output(ProfileManagerDialogOutput::ProfilesChanged);
            }
            ProfileManagerDialogInput::NewProfileRequested => {
                self.open_profile_editor(ScanProfile::default(), root, &sender);
            }
            ProfileManagerDialogInput::ImportRequested => {
                let input_sender = sender.input_sender().clone();
                let parent_window = root.root().and_downcast::<gtk::Window>();
                relm4::spawn_local(async move {
                    if let Ok(chosen_file) = gtk::FileDialog::builder()
                        .title(gettext("Import"))
                        .build()
                        .open_future(parent_window.as_ref())
                        .await
                    {
                        input_sender
                            .emit(ProfileManagerDialogInput::ImportedFileChosen(chosen_file));
                    }
                });
            }
            ProfileManagerDialogInput::ImportedFileChosen(chosen_file) => {
                let command_sender = sender.command_sender().clone();
                relm4::spawn_local(async move {
                    let imported_bytes = chosen_file
                        .load_contents_future()
                        .await
                        .map(|loaded_contents| loaded_contents.0.to_vec());
                    let _dialog_closed = command_sender.send(
                        ProfileManagerDialogCommand::ImportedBytesRead(imported_bytes),
                    );
                });
            }
            ProfileManagerDialogInput::RestoreDefaultsRequested => confirm_action(
                gettext("Restore Default Profiles"),
                gettext(
                    "Restore the built-in default profiles? Any customizations to default \
                     profiles will be reset; custom profiles are preserved.",
                ),
                gettext("Restore Defaults"),
                ProfileManagerDialogInput::RestoreDefaultsConfirmed,
                root,
                &sender,
            ),
            ProfileManagerDialogInput::RestoreDefaultsConfirmed => {
                match self.profile_store.restore_builtin_profiles() {
                    Ok(()) => {
                        widgets
                            .toast_overlay
                            .add_toast(adw::Toast::new(&gettext("Default profiles restored")));
                        sender.input(ProfileManagerDialogInput::ReloadRequested);
                    }
                    Err(restore_failure) => widgets
                        .toast_overlay
                        .add_toast(adw::Toast::new(&restore_failure.to_string())),
                }
            }
            ProfileManagerDialogInput::RunRequested(row_index) => {
                if let Some(run_profile) = self.profile_at(&row_index) {
                    let _page_closed =
                        sender.output(ProfileManagerDialogOutput::RunProfile(run_profile));
                    root.close();
                }
            }
            ProfileManagerDialogInput::EditRequested(row_index) => {
                if let Some(edited_profile) = self.profile_at(&row_index) {
                    self.open_profile_editor(edited_profile, root, &sender);
                }
            }
            ProfileManagerDialogInput::DeleteRequested(row_index) => {
                if let Some(deleted_profile) = self.profile_at(&row_index) {
                    confirm_action(
                        gettext("Delete Profile"),
                        gettext("Delete the profile '{name}'?")
                            .replace("{name}", &deleted_profile.profile_name),
                        gettext("Delete"),
                        ProfileManagerDialogInput::DeleteConfirmed {
                            profile_id: deleted_profile.profile_id,
                        },
                        root,
                        &sender,
                    );
                }
            }
            ProfileManagerDialogInput::DeleteConfirmed { profile_id } => {
                match self.profile_store.delete_profile(&profile_id) {
                    Ok(()) => {
                        widgets
                            .toast_overlay
                            .add_toast(adw::Toast::new(&gettext("Profile deleted")));
                        sender.input(ProfileManagerDialogInput::ReloadRequested);
                    }
                    Err(delete_failure) => widgets
                        .toast_overlay
                        .add_toast(adw::Toast::new(&delete_failure.to_string())),
                }
            }
            ProfileManagerDialogInput::ExportRequested(row_index) => {
                let exported_json = self
                    .profile_at(&row_index)
                    .map(|exported_profile| exported_profile_json(&exported_profile));
                match exported_json {
                    Some(Ok(exported_json)) => {
                        let parent_widget = root.clone().upcast::<gtk::Widget>();
                        let command_sender = sender.command_sender().clone();
                        relm4::spawn_local(async move {
                            let export_outcome = save_text_with_dialog(
                                &parent_widget,
                                "clamui-profile.json",
                                exported_json,
                            )
                            .await;
                            let _dialog_closed = command_sender
                                .send(ProfileManagerDialogCommand::ExportFinished(export_outcome));
                        });
                    }
                    Some(Err(export_failure)) => widgets
                        .toast_overlay
                        .add_toast(adw::Toast::new(&export_failure.to_string())),
                    None => {}
                }
            }
        }
        self.update_view(widgets, sender);
    }

    fn update_cmd_with_view(
        &mut self,
        widgets: &mut Self::Widgets,
        manager_command: ProfileManagerDialogCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match manager_command {
            ProfileManagerDialogCommand::ImportedBytesRead(Ok(imported_bytes)) => {
                match self.profile_store.import_profile(&imported_bytes) {
                    Ok(_imported_profile) => {
                        widgets
                            .toast_overlay
                            .add_toast(adw::Toast::new(&gettext("Profile imported")));
                        sender.input(ProfileManagerDialogInput::ReloadRequested);
                    }
                    Err(import_failure) => widgets
                        .toast_overlay
                        .add_toast(adw::Toast::new(&import_failure.to_string())),
                }
            }
            ProfileManagerDialogCommand::ImportedBytesRead(Err(read_failure)) => widgets
                .toast_overlay
                .add_toast(adw::Toast::new(&describe_export_failure(&read_failure))),
            ProfileManagerDialogCommand::ExportFinished(TextExportOutcome::TextSaved) => {
                widgets
                    .toast_overlay
                    .add_toast(adw::Toast::new(&gettext("Profile exported")));
            }
            ProfileManagerDialogCommand::ExportFinished(TextExportOutcome::ExportCancelled) => {}
            ProfileManagerDialogCommand::ExportFinished(TextExportOutcome::ExportFailed(
                export_failure,
            )) => widgets
                .toast_overlay
                .add_toast(adw::Toast::new(&describe_export_failure(&export_failure))),
        }
        self.update_view(widgets, sender);
    }
}

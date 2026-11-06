use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    scan_page::scan_profiles_dialog::{
        profile_value_row::{ProfileValueRow, ProfileValueRowOutput},
        scan_profile_store::{ProfileStoreFailure, ScanProfile, ScanProfileStore},
    },
    shared_widgets::awaited_dialogs::{chosen_folders_to_open, deliver_local_outcome},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileListKind {
    ScanTargets,
    ExcludedPatterns,
}

pub struct ProfileEditorDialog {
    profile_store: ScanProfileStore,
    edited_profile: ScanProfile,
    editor_notice: String,
    target_rows: FactoryVecDeque<ProfileValueRow>,
    pattern_rows: FactoryVecDeque<ProfileValueRow>,
    cleared_entry: ClearedEntry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClearedEntry {
    NoEntryCleared,
    EntryCleared(ProfileListKind),
}

pub struct ProfileEditorDialogInit {
    pub profile_store: ScanProfileStore,
    pub edited_profile: ScanProfile,
}

#[derive(Debug)]
pub enum ProfileEditorDialogInput {
    NameChanged(String),
    DescriptionChanged(String),
    AddFolderRequested,
    ListValueAdded {
        list_kind: ProfileListKind,
        added_value: String,
    },
    ListValueRemoved {
        list_kind: ProfileListKind,
        removed_value: String,
    },
    SaveRequested,
}

#[derive(Debug)]
pub enum ProfileEditorDialogOutput {
    ProfileSaved,
}

#[derive(Debug)]
pub enum ProfileEditorDialogCommand {
    ProfileSaveFinished(Result<(), ProfileStoreFailure>),
}

fn describe_store_failure(store_failure: &ProfileStoreFailure) -> String {
    match store_failure {
        ProfileStoreFailure::ProfileNameMissing => gettext("Profile name is required"),
        ProfileStoreFailure::ProfileNameTooLong => gettext("Name must be 50 characters or less"),
        ProfileStoreFailure::ProfileNameTaken => gettext("Another profile already uses this name"),
        ProfileStoreFailure::ProfileTargetsMissing => gettext("Add at least one target"),
        other_failure => other_failure.to_string(),
    }
}

fn value_rows(
    listed_values: &[String],
    list_kind: ProfileListKind,
    sender: &ComponentSender<ProfileEditorDialog>,
) -> FactoryVecDeque<ProfileValueRow> {
    let mut value_rows = FactoryVecDeque::builder()
        .launch(gtk::ListBox::default())
        .forward(sender.input_sender(), move |row_output| match row_output {
            ProfileValueRowOutput::RemovalRequested(removed_value) => {
                ProfileEditorDialogInput::ListValueRemoved {
                    list_kind,
                    removed_value,
                }
            }
        });
    let mut row_guard = value_rows.guard();
    listed_values.iter().cloned().for_each(|listed_value| {
        row_guard.push_back(listed_value);
    });
    drop(row_guard);
    value_rows
}

impl ProfileEditorDialog {
    fn edited_values(&mut self, list_kind: ProfileListKind) -> &mut Vec<String> {
        match list_kind {
            ProfileListKind::ScanTargets => &mut self.edited_profile.scan_targets,
            ProfileListKind::ExcludedPatterns => &mut self.edited_profile.excluded_patterns,
        }
    }

    fn value_rows_of(
        &mut self,
        list_kind: ProfileListKind,
    ) -> &mut FactoryVecDeque<ProfileValueRow> {
        match list_kind {
            ProfileListKind::ScanTargets => &mut self.target_rows,
            ProfileListKind::ExcludedPatterns => &mut self.pattern_rows,
        }
    }

    fn entry_was_cleared(&self, list_kind: ProfileListKind) -> bool {
        self.cleared_entry == ClearedEntry::EntryCleared(list_kind)
    }
}

#[relm4::component(pub)]
impl Component for ProfileEditorDialog {
    type Init = ProfileEditorDialogInit;
    type Input = ProfileEditorDialogInput;
    type Output = ProfileEditorDialogOutput;
    type CommandOutput = ProfileEditorDialogCommand;

    view! {
        adw::Dialog {
            set_title: &gettext("Edit Profile"),
            set_content_width: 520,
            set_content_height: 560,

            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    pack_end = &gtk::Button {
                        set_label: &gettext("Save"),
                        add_css_class: "suggested-action",
                        connect_clicked => ProfileEditorDialogInput::SaveRequested,
                    },
                },

                #[wrap(Some)]
                set_content = &adw::PreferencesPage {
                    add = &adw::PreferencesGroup {
                        adw::EntryRow {
                            set_title: &gettext("Name"),
                            set_text: &model.edited_profile.profile_name,
                            connect_changed[sender] => move |edited_row| {
                                sender.input(ProfileEditorDialogInput::NameChanged(edited_row.text().to_string()));
                            },
                        },

                        adw::EntryRow {
                            set_title: &gettext("Description"),
                            set_text: &model.edited_profile.profile_description,
                            connect_changed[sender] => move |edited_row| {
                                sender.input(ProfileEditorDialogInput::DescriptionChanged(edited_row.text().to_string()));
                            },
                        },
                    },

                    add = &adw::PreferencesGroup {
                        set_title: &gettext("Targets"),
                        #[wrap(Some)]
                        set_header_suffix = &gtk::Button {
                            set_icon_name: "folder-new-symbolic",
                            set_tooltip_text: Some(&gettext("Add Folder")),
                            set_valign: gtk::Align::Center,
                            add_css_class: "flat",
                            connect_clicked => ProfileEditorDialogInput::AddFolderRequested,
                        },

                        gtk::ListBox {
                            add_css_class: "boxed-list",
                            set_selection_mode: gtk::SelectionMode::None,

                            adw::EntryRow {
                                set_title: &gettext("Add Path"),
                                set_show_apply_button: true,
                                #[track(model.entry_was_cleared(ProfileListKind::ScanTargets))]
                                set_text: "",
                                connect_apply[sender] => move |applied_row| {
                                    sender.input(ProfileEditorDialogInput::ListValueAdded {
                                        list_kind: ProfileListKind::ScanTargets,
                                        added_value: applied_row.text().trim().to_owned(),
                                    });
                                },
                            },
                        },

                        #[local_ref]
                        target_list -> gtk::ListBox {
                            set_margin_top: 12,
                            add_css_class: "boxed-list",
                            set_selection_mode: gtk::SelectionMode::None,
                        },
                    },

                    add = &adw::PreferencesGroup {
                        set_title: &gettext("Exclusions"),
                        set_description: Some(&gettext("Added to the exclusions from Preferences while this profile runs.")),

                        gtk::ListBox {
                            add_css_class: "boxed-list",
                            set_selection_mode: gtk::SelectionMode::None,

                            adw::EntryRow {
                                set_title: &gettext("Add Pattern"),
                                set_show_apply_button: true,
                                #[track(model.entry_was_cleared(ProfileListKind::ExcludedPatterns))]
                                set_text: "",
                                connect_apply[sender] => move |applied_row| {
                                    sender.input(ProfileEditorDialogInput::ListValueAdded {
                                        list_kind: ProfileListKind::ExcludedPatterns,
                                        added_value: applied_row.text().trim().to_owned(),
                                    });
                                },
                            },
                        },

                        #[local_ref]
                        pattern_list -> gtk::ListBox {
                            set_margin_top: 12,
                            add_css_class: "boxed-list",
                            set_selection_mode: gtk::SelectionMode::None,
                        },
                    },

                    add = &adw::PreferencesGroup {
                        gtk::Label {
                            set_xalign: 0.0,
                            set_wrap: true,
                            add_css_class: "error",
                            #[watch]
                            set_visible: !model.editor_notice.is_empty(),
                            #[watch]
                            set_label: &model.editor_notice,
                        },
                    },
                },
            },
        }
    }

    fn init(
        dialog_init: ProfileEditorDialogInit,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let mut edited_profile = dialog_init.edited_profile;
        let inherited_paths = std::mem::take(&mut edited_profile.excluded_paths);
        edited_profile
            .excluded_patterns
            .splice(0..0, inherited_paths);
        let model = Self {
            profile_store: dialog_init.profile_store,
            target_rows: value_rows(
                &edited_profile.scan_targets,
                ProfileListKind::ScanTargets,
                &sender,
            ),
            pattern_rows: value_rows(
                &edited_profile.excluded_patterns,
                ProfileListKind::ExcludedPatterns,
                &sender,
            ),
            edited_profile,
            editor_notice: String::new(),
            cleared_entry: ClearedEntry::NoEntryCleared,
        };
        let target_list = model.target_rows.widget();
        let pattern_list = model.pattern_rows.widget();
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        editor_input: ProfileEditorDialogInput,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        self.cleared_entry = ClearedEntry::NoEntryCleared;
        match editor_input {
            ProfileEditorDialogInput::NameChanged(profile_name) => {
                self.edited_profile.profile_name = profile_name;
            }
            ProfileEditorDialogInput::DescriptionChanged(profile_description) => {
                self.edited_profile.profile_description = profile_description;
            }
            ProfileEditorDialogInput::AddFolderRequested => deliver_local_outcome(
                sender.input_sender().clone(),
                chosen_folders_to_open(gettext("Add Folder")),
                |chosen_paths| {
                    chosen_paths.first().map(|folder_path| {
                        ProfileEditorDialogInput::ListValueAdded {
                            list_kind: ProfileListKind::ScanTargets,
                            added_value: folder_path.to_string_lossy().into_owned(),
                        }
                    })
                },
            ),
            ProfileEditorDialogInput::ListValueAdded {
                list_kind,
                added_value,
            } => {
                if added_value.is_empty() {
                    return;
                }
                self.cleared_entry = ClearedEntry::EntryCleared(list_kind);
                if !self.edited_values(list_kind).contains(&added_value) {
                    self.edited_values(list_kind).push(added_value.clone());
                    self.value_rows_of(list_kind).guard().push_back(added_value);
                }
            }
            ProfileEditorDialogInput::ListValueRemoved {
                list_kind,
                removed_value,
            } => {
                self.edited_values(list_kind)
                    .retain(|edited_value| *edited_value != removed_value);
                let removed_position = self
                    .value_rows_of(list_kind)
                    .iter()
                    .position(|value_row| value_row.listed_value == removed_value);
                if let Some(removed_position) = removed_position {
                    self.value_rows_of(list_kind)
                        .guard()
                        .remove(removed_position);
                }
            }
            ProfileEditorDialogInput::SaveRequested => {
                let profile_store = self.profile_store.clone();
                let saved_profile = self.edited_profile.clone();
                sender.oneshot_command(async move {
                    ProfileEditorDialogCommand::ProfileSaveFinished(
                        tokio::task::spawn_blocking(move || {
                            profile_store
                                .save_profile(saved_profile)
                                .map(|_saved_profile| ())
                        })
                        .await
                        .unwrap_or_else(|interrupted_saving| {
                            Err(ProfileStoreFailure::from(std::io::Error::other(
                                interrupted_saving,
                            )))
                        }),
                    )
                });
            }
        }
    }

    fn update_cmd(
        &mut self,
        editor_command: ProfileEditorDialogCommand,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        self.cleared_entry = ClearedEntry::NoEntryCleared;
        match editor_command {
            ProfileEditorDialogCommand::ProfileSaveFinished(Ok(())) => {
                let _manager_closed = sender.output(ProfileEditorDialogOutput::ProfileSaved);
                root.close();
            }
            ProfileEditorDialogCommand::ProfileSaveFinished(Err(save_failure)) => {
                self.editor_notice = describe_store_failure(&save_failure);
            }
        }
    }
}

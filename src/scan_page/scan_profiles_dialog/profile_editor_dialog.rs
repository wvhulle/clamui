use gettextrs::gettext;
use relm4::{Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk, gtk::gio};

use crate::{
    host_services::clamav_scanner::scanner_output_parser::sanitize_scanner_line,
    scan_page::scan_profiles_dialog::scan_profile_store::{
        ProfileStoreFailure, ScanProfile, ScanProfileStore,
    },
};

#[derive(Clone, Copy, Debug)]
pub enum ProfileListKind {
    ScanTargets,
    ExcludedPatterns,
}

pub struct ProfileEditorDialog {
    profile_store: ScanProfileStore,
    edited_profile: ScanProfile,
    editor_notice: String,
}

pub struct ProfileEditorDialogInit {
    pub profile_store: ScanProfileStore,
    pub edited_profile: ScanProfile,
}

#[derive(Debug)]
pub enum ProfileEditorDialogInput {
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

fn listed_value_row(
    listed_value: &str,
    list_kind: ProfileListKind,
    sender: &ComponentSender<ProfileEditorDialog>,
) -> adw::ActionRow {
    let value_row = adw::ActionRow::builder()
        .use_markup(false)
        .title(sanitize_scanner_line(listed_value))
        .build();
    let remove_button = gtk::Button::builder()
        .icon_name("user-trash-symbolic")
        .tooltip_text(gettext("Remove"))
        .valign(gtk::Align::Center)
        .css_classes(["flat"])
        .build();
    let input_sender = sender.input_sender().clone();
    let removed_value = listed_value.to_owned();
    remove_button.connect_clicked(move |_clicked_button| {
        input_sender.emit(ProfileEditorDialogInput::ListValueRemoved {
            list_kind,
            removed_value: removed_value.clone(),
        });
    });
    value_row.add_suffix(&remove_button);
    value_row
}

fn refill_value_list(
    value_list: &gtk::ListBox,
    listed_values: &[String],
    list_kind: ProfileListKind,
    sender: &ComponentSender<ProfileEditorDialog>,
) {
    value_list.remove_all();
    listed_values.iter().for_each(|listed_value| {
        value_list.append(&listed_value_row(listed_value, list_kind, sender));
    });
}

fn added_value_row(
    row_title: String,
    list_kind: ProfileListKind,
    sender: &ComponentSender<ProfileEditorDialog>,
) -> adw::EntryRow {
    let entry_row = adw::EntryRow::builder()
        .title(row_title)
        .show_apply_button(true)
        .build();
    let input_sender = sender.input_sender().clone();
    entry_row.connect_apply(move |applied_row| {
        let added_value = applied_row.text().trim().to_owned();
        if !added_value.is_empty() {
            input_sender.emit(ProfileEditorDialogInput::ListValueAdded {
                list_kind,
                added_value,
            });
            applied_row.set_text("");
        }
    });
    entry_row
}

impl ProfileEditorDialog {
    fn edited_values(&mut self, list_kind: ProfileListKind) -> &mut Vec<String> {
        match list_kind {
            ProfileListKind::ScanTargets => &mut self.edited_profile.scan_targets,
            ProfileListKind::ExcludedPatterns => &mut self.edited_profile.excluded_patterns,
        }
    }
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

#[relm4::component(pub)]
impl Component for ProfileEditorDialog {
    type Init = ProfileEditorDialogInit;
    type Input = ProfileEditorDialogInput;
    type Output = ProfileEditorDialogOutput;
    type CommandOutput = ();

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
                        #[name = "name_row"]
                        adw::EntryRow {
                            set_title: &gettext("Name"),
                            set_text: &model.edited_profile.profile_name,
                        },

                        #[name = "description_row"]
                        adw::EntryRow {
                            set_title: &gettext("Description"),
                            set_text: &model.edited_profile.profile_description,
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

                        #[name = "target_list"]
                        gtk::ListBox {
                            add_css_class: "boxed-list",
                            set_selection_mode: gtk::SelectionMode::None,
                            append: &added_value_row(gettext("Add Path"), ProfileListKind::ScanTargets, &sender),
                        },

                        #[name = "target_values"]
                        gtk::ListBox {
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
                            append: &added_value_row(gettext("Add Pattern"), ProfileListKind::ExcludedPatterns, &sender),
                        },

                        #[name = "exclusion_values"]
                        gtk::ListBox {
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
            edited_profile,
            editor_notice: String::new(),
        };
        let widgets = view_output!();
        refill_value_list(
            &widgets.target_values,
            &model.edited_profile.scan_targets,
            ProfileListKind::ScanTargets,
            &sender,
        );
        refill_value_list(
            &widgets.exclusion_values,
            &model.edited_profile.excluded_patterns,
            ProfileListKind::ExcludedPatterns,
            &sender,
        );
        ComponentParts { model, widgets }
    }

    fn update_with_view(
        &mut self,
        widgets: &mut Self::Widgets,
        editor_input: ProfileEditorDialogInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match editor_input {
            ProfileEditorDialogInput::AddFolderRequested => {
                let input_sender = sender.input_sender().clone();
                let parent_window = root.root().and_downcast::<gtk::Window>();
                relm4::spawn_local(async move {
                    let chosen_folder = gtk::FileDialog::builder()
                        .title(gettext("Add Folder"))
                        .build()
                        .select_folder_future(parent_window.as_ref())
                        .await;
                    if let Some(folder_path) = chosen_folder
                        .ok()
                        .and_then(|chosen_folder: gio::File| chosen_folder.path())
                    {
                        input_sender.emit(ProfileEditorDialogInput::ListValueAdded {
                            list_kind: ProfileListKind::ScanTargets,
                            added_value: folder_path.to_string_lossy().into_owned(),
                        });
                    }
                });
            }
            ProfileEditorDialogInput::ListValueAdded {
                list_kind,
                added_value,
            } => {
                let edited_values = self.edited_values(list_kind);
                if !edited_values.contains(&added_value) {
                    edited_values.push(added_value);
                }
            }
            ProfileEditorDialogInput::ListValueRemoved {
                list_kind,
                removed_value,
            } => {
                self.edited_values(list_kind)
                    .retain(|edited_value| *edited_value != removed_value);
            }
            ProfileEditorDialogInput::SaveRequested => {
                let saved_profile = ScanProfile {
                    profile_name: widgets.name_row.text().to_string(),
                    profile_description: widgets.description_row.text().to_string(),
                    ..self.edited_profile.clone()
                };
                match self.profile_store.save_profile(saved_profile) {
                    Ok(_saved_profile) => {
                        let _manager_closed =
                            sender.output(ProfileEditorDialogOutput::ProfileSaved);
                        root.close();
                    }
                    Err(save_failure) => {
                        self.editor_notice = describe_store_failure(&save_failure);
                    }
                }
            }
        }
        refill_value_list(
            &widgets.target_values,
            &self.edited_profile.scan_targets,
            ProfileListKind::ScanTargets,
            &sender,
        );
        refill_value_list(
            &widgets.exclusion_values,
            &self.edited_profile.excluded_patterns,
            ProfileListKind::ExcludedPatterns,
            &sender,
        );
        self.update_view(widgets, sender);
    }
}

use gettextrs::gettext;
use relm4::{ComponentParts, ComponentSender, SimpleComponent, adw, adw::prelude::*, gtk};

use crate::{
    host_services::clamav_config::{
        setting_provenance::{ClamavConfigKind, ConfigFileOwner, change_snippet, values_with_edit},
        typed_setting_values::{
            DraftEdit, SizeUnit, SwitchPosition, TypedSettingValue, WriteRefusal,
        },
    },
    shared_widgets::engine_settings::config_setting_row::size_unit_labels,
};

const SIZE_COUNT_CEILING: f64 = 4_294_967_295.0;

pub struct ConfigLineCopyInit {
    pub setting_key: String,
    pub sibling_values: Vec<String>,
    pub value_position: usize,
    pub editor_draft: TypedSettingValue,
    pub config_file_owner: ConfigFileOwner,
    pub config_kind: ClamavConfigKind,
}

pub struct ConfigLineCopyDialog {
    setting_key: String,
    sibling_values: Vec<String>,
    value_position: usize,
    editor_draft: TypedSettingValue,
    config_file_owner: ConfigFileOwner,
    config_kind: ClamavConfigKind,
}

#[derive(Debug)]
pub enum ConfigLineCopyDialogInput {
    DraftEdited(DraftEdit),
    CopyRequested,
    DialogClosed,
}

#[derive(Debug)]
pub enum ConfigLineCopyDialogOutput {
    ConfigLineCopied(String),
    CopyDialogClosed,
}

pub fn copied_config_line(
    config_file_owner: ConfigFileOwner,
    config_kind: ClamavConfigKind,
    setting_key: &str,
    sibling_values: &[String],
    value_position: usize,
    editor_draft: &TypedSettingValue,
) -> Result<String, WriteRefusal> {
    let config_value = editor_draft.writable_value(setting_key)?;
    Ok(change_snippet(
        config_file_owner,
        config_kind,
        setting_key,
        &values_with_edit(sibling_values, value_position, config_value),
    ))
}

impl ConfigLineCopyDialog {
    fn copied_line(&self) -> Result<String, WriteRefusal> {
        copied_config_line(
            self.config_file_owner,
            self.config_kind,
            &self.setting_key,
            &self.sibling_values,
            self.value_position,
            &self.editor_draft,
        )
    }

    const fn shows_switch(&self) -> bool {
        matches!(self.editor_draft, TypedSettingValue::BooleanValue(_))
    }

    fn shows_switch_on(&self) -> bool {
        self.editor_draft
            .shown_switch_position()
            .is_some_and(SwitchPosition::is_switched_on)
    }

    const fn shows_count(&self) -> bool {
        matches!(self.editor_draft, TypedSettingValue::CountValue { .. })
    }

    const fn shows_size(&self) -> bool {
        matches!(self.editor_draft, TypedSettingValue::SizeValue(_))
    }

    const fn shows_text(&self) -> bool {
        matches!(
            self.editor_draft,
            TypedSettingValue::PathValue(_) | TypedSettingValue::TextValue(_)
        )
    }

    fn count_range(&self) -> (f64, f64) {
        match self.editor_draft {
            TypedSettingValue::CountValue {
                minimum, maximum, ..
            } => (minimum as f64, maximum as f64),
            TypedSettingValue::SizeValue(_)
            | TypedSettingValue::BooleanValue(_)
            | TypedSettingValue::PathValue(_)
            | TypedSettingValue::TextValue(_) => (0.0, SIZE_COUNT_CEILING),
        }
    }

    fn shown_count(&self) -> f64 {
        self.editor_draft.shown_count().unwrap_or_default() as f64
    }

    fn shown_unit_position(&self) -> u32 {
        self.editor_draft
            .shown_size_unit()
            .map_or(0, SizeUnit::unit_position)
    }

    fn shown_text(&self) -> String {
        self.editor_draft
            .shown_text()
            .map(str::to_owned)
            .unwrap_or_default()
    }

    fn text_style_classes(&self) -> &'static [&'static str] {
        if self.copied_line().is_ok() {
            &[]
        } else {
            &["error"]
        }
    }

    fn line_preview(&self) -> String {
        self.copied_line().unwrap_or_default()
    }
}

#[relm4::component(pub)]
impl SimpleComponent for ConfigLineCopyDialog {
    type Init = ConfigLineCopyInit;
    type Input = ConfigLineCopyDialogInput;
    type Output = ConfigLineCopyDialogOutput;

    view! {
        adw::Dialog {
            set_title: &gettext("Copy Configuration Line"),
            set_content_width: 460,
            connect_closed => ConfigLineCopyDialogInput::DialogClosed,

            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {},

                #[wrap(Some)]
                set_content = &adw::PreferencesPage {
                    add = &adw::PreferencesGroup {
                        set_description: Some(&gettext(
                            "Nothing is applied. Choose a value and copy the line, then add it \
                             to your configuration yourself.",
                        )),

                        #[name = "switch_editor"]
                        adw::SwitchRow {
                            set_use_markup: false,
                            set_title: &model.setting_key,
                            set_visible: model.shows_switch(),
                            #[watch]
                            #[block_signal(switch_handler)]
                            set_active: model.shows_switch_on(),
                            connect_active_notify[sender] => move |toggled_row| {
                                sender.input(ConfigLineCopyDialogInput::DraftEdited(
                                    DraftEdit::SwitchSet(SwitchPosition::from_switch_active(
                                        toggled_row.is_active(),
                                    )),
                                ));
                            } @switch_handler,
                        },

                        #[name = "count_editor"]
                        adw::SpinRow {
                            set_use_markup: false,
                            set_title: &model.setting_key,
                            set_visible: model.shows_count() || model.shows_size(),
                            set_digits: 0,
                            set_numeric: true,
                            set_adjustment: Some(&gtk::Adjustment::new(
                                model.shown_count(),
                                model.count_range().0,
                                model.count_range().1,
                                1.0,
                                10.0,
                                0.0,
                            )),
                            #[watch]
                            #[block_signal(count_handler)]
                            set_value: model.shown_count(),
                            connect_value_notify[sender] => move |edited_row| {
                                sender.input(ConfigLineCopyDialogInput::DraftEdited(
                                    DraftEdit::NumberSet(edited_row.value() as u64),
                                ));
                            } @count_handler,
                        },

                        adw::ComboRow {
                            set_title: &gettext("Unit"),
                            set_visible: model.shows_size(),
                            set_model: Some(&size_unit_labels()),
                            #[watch]
                            #[block_signal(unit_handler)]
                            set_selected: model.shown_unit_position(),
                            connect_selected_notify[sender] => move |chosen_row| {
                                if let Some(size_unit) = SizeUnit::unit_at_position(chosen_row.selected()) {
                                    sender.input(ConfigLineCopyDialogInput::DraftEdited(
                                        DraftEdit::SizeUnitSet(size_unit),
                                    ));
                                }
                            } @unit_handler,
                        },

                        #[name = "text_editor"]
                        adw::EntryRow {
                            set_use_markup: false,
                            set_title: &model.setting_key,
                            set_visible: model.shows_text(),
                            set_text: &model.shown_text(),
                            #[watch]
                            set_css_classes: model.text_style_classes(),
                            connect_changed[sender] => move |edited_row| {
                                sender.input(ConfigLineCopyDialogInput::DraftEdited(
                                    DraftEdit::TextSet(edited_row.text().to_string()),
                                ));
                            },
                        },
                    },

                    add = &adw::PreferencesGroup {
                        adw::ActionRow {
                            set_use_markup: false,
                            set_title: &gettext("Line to copy"),
                            set_subtitle_selectable: true,
                            set_subtitle_lines: 0,
                            add_css_class: "property",
                            #[watch]
                            set_subtitle: &model.line_preview(),
                        },
                    },

                    add = &adw::PreferencesGroup {
                        gtk::Button {
                            set_label: &gettext("Copy Line"),
                            set_halign: gtk::Align::Center,
                            add_css_class: "pill",
                            add_css_class: "suggested-action",
                            #[watch]
                            set_sensitive: model.copied_line().is_ok(),
                            connect_clicked => ConfigLineCopyDialogInput::CopyRequested,
                        },
                    },
                },
            },
        }
    }

    fn init(
        copy_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = Self {
            setting_key: copy_init.setting_key,
            sibling_values: copy_init.sibling_values,
            value_position: copy_init.value_position,
            editor_draft: copy_init.editor_draft,
            config_file_owner: copy_init.config_file_owner,
            config_kind: copy_init.config_kind,
        };
        let widgets = view_output!();
        let focused_editor: gtk::Widget = match model.editor_draft {
            TypedSettingValue::BooleanValue(_) => widgets.switch_editor.clone().upcast(),
            TypedSettingValue::PathValue(_) | TypedSettingValue::TextValue(_) => widgets
                .text_editor
                .delegate()
                .map_or_else(|| widgets.text_editor.clone().upcast(), Cast::upcast),
            TypedSettingValue::CountValue { .. } | TypedSettingValue::SizeValue(_) => widgets
                .count_editor
                .delegate()
                .map_or_else(|| widgets.count_editor.clone().upcast(), Cast::upcast),
        };
        root.set_focus(Some(&focused_editor));
        ComponentParts { model, widgets }
    }

    fn update(&mut self, dialog_input: Self::Input, sender: ComponentSender<Self>) {
        match dialog_input {
            ConfigLineCopyDialogInput::DraftEdited(draft_edit) => {
                self.editor_draft = self.editor_draft.clone().with_draft_edit(draft_edit);
            }
            ConfigLineCopyDialogInput::CopyRequested => {
                if let Ok(config_line) = self.copied_line() {
                    let _parent_closed =
                        sender.output(ConfigLineCopyDialogOutput::ConfigLineCopied(config_line));
                }
            }
            ConfigLineCopyDialogInput::DialogClosed => {
                let _parent_closed = sender.output(ConfigLineCopyDialogOutput::CopyDialogClosed);
            }
        }
    }
}

#[cfg(test)]
mod config_line_copy_dialog_tests {
    use super::*;

    #[test]
    fn the_copied_line_matches_the_snippet_for_the_edited_value() {
        let copied_line = |config_file_owner, editor_draft: TypedSettingValue| {
            copied_config_line(
                config_file_owner,
                ClamavConfigKind::ClamdDaemonConfig,
                "MaxThreads",
                &["4".to_owned()],
                0,
                &editor_draft.with_draft_edit(DraftEdit::NumberSet(3)),
            )
        };
        let count_draft = TypedSettingValue::CountValue {
            count_value: 4,
            minimum: 1,
            maximum: 256,
        };
        assert_eq!(
            copied_line(ConfigFileOwner::SystemPackage, count_draft.clone()),
            Ok("MaxThreads 3".to_owned())
        );
        assert_eq!(
            copied_line(ConfigFileOwner::NixOsConfiguration, count_draft),
            Ok("services.clamav.daemon.settings.MaxThreads = 3;".to_owned())
        );
    }

    #[test]
    fn a_repeated_path_copies_every_value_with_the_edit_in_place() {
        assert_eq!(
            copied_config_line(
                ConfigFileOwner::SystemPackage,
                ClamavConfigKind::ClamdDaemonConfig,
                "OnAccessIncludePath",
                &["/home".to_owned(), "/srv".to_owned()],
                1,
                &TypedSettingValue::PathValue("/data".to_owned()),
            ),
            Ok("OnAccessIncludePath /home\nOnAccessIncludePath /data".to_owned())
        );
    }

    #[test]
    fn an_invalid_value_is_never_copied() {
        assert!(
            copied_config_line(
                ConfigFileOwner::SystemPackage,
                ClamavConfigKind::ClamdDaemonConfig,
                "OnAccessIncludePath",
                &["/home".to_owned()],
                0,
                &TypedSettingValue::PathValue("home".to_owned()),
            )
            .is_err()
        );
    }
}

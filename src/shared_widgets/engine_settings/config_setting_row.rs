use gettextrs::gettext;
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    gtk::glib,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::host_services::{
    clamav_admin_service::protection_change_rules::whole_number_in_text,
    clamav_config::{
        setting_provenance::SettingLock,
        typed_setting_values::{
            DraftApplyTiming, DraftEdit, SIZE_UNITS, SettingParseFailure, SizeUnit, SwitchPosition,
            TypedSettingValue, parse_setting_value,
        },
    },
};

const SIZE_COUNT_CEILING: f64 = 4_294_967_295.0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RowChangeActivity {
    ChangesAllowed,
    ApplyingThisRow,
    ApplyingOtherRow,
}

impl RowChangeActivity {
    pub const fn accepts_changes(self) -> bool {
        matches!(self, Self::ChangesAllowed)
    }

    pub const fn shows_applying_spinner(self) -> bool {
        matches!(self, Self::ApplyingThisRow)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingAvailability {
    ChangeableNow,
    LockedUntilUnlocked,
    NotAllowedAtRuntime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingLockReason {
    UnlockRequired,
    NotAllowedAtRuntime,
}

pub fn setting_lock_tooltip(lock_reason: SettingLockReason) -> String {
    match lock_reason {
        SettingLockReason::UnlockRequired => gettext(
            "Unlock to change this setting. While locked, you can copy its line for your \
             configuration.",
        ),
        SettingLockReason::NotAllowedAtRuntime => gettext(
            "Your administrator doesn't allow changing this setting from Lazaret. You can copy \
             its line for your configuration.",
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DraftComparison {
    SameAsStored,
    ChangedFromStored,
}

pub fn size_unit_label(size_unit: SizeUnit) -> String {
    match size_unit {
        SizeUnit::PlainBytes => gettext("bytes"),
        SizeUnit::Kibibytes => gettext("KiB"),
        SizeUnit::Mebibytes => gettext("MiB"),
    }
}

pub fn size_unit_labels() -> gtk::StringList {
    let unit_labels = SIZE_UNITS.map(size_unit_label);
    gtk::StringList::new(&unit_labels.each_ref().map(String::as_str))
}

pub fn describe_parse_failure(parse_failure: SettingParseFailure) -> String {
    match parse_failure {
        SettingParseFailure::UnknownOption => {
            gettext("Lazaret doesn't know this option, so it only shows it.")
        }
        SettingParseFailure::NotYesOrNo => gettext("Needs review: this value should be yes or no."),
        SettingParseFailure::NotAWholeNumber => {
            gettext("Needs review: this value should be a whole number.")
        }
        SettingParseFailure::CountOutOfRange { minimum, maximum } => {
            gettext("Needs review: this value should be between {minimum} and {maximum}.")
                .replace("{minimum}", &minimum.to_string())
                .replace("{maximum}", &maximum.to_string())
        }
        SettingParseFailure::NotASize => gettext(
            "Needs review: this value should be a size in bytes, or a number followed by K or M.",
        ),
        SettingParseFailure::PathNotAbsolute => {
            gettext("Needs review: this value should be a full path that starts with /.")
        }
        SettingParseFailure::EmptyText => gettext("Needs review: this value is empty."),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigRowPresentation {
    ProtectedSettingRow(Result<TypedSettingValue, SettingParseFailure>),
    UnknownOptionRow,
    NeedsReviewRow(SettingParseFailure),
    LockedSettingRow {
        lock_reason: SettingLockReason,
        editor_draft: TypedSettingValue,
    },
    EditableSettingRow(TypedSettingValue),
}

impl ConfigRowPresentation {
    const fn editable_draft(&self) -> Option<&TypedSettingValue> {
        match self {
            Self::EditableSettingRow(editor_draft) => Some(editor_draft),
            Self::ProtectedSettingRow(_)
            | Self::UnknownOptionRow
            | Self::NeedsReviewRow(_)
            | Self::LockedSettingRow { .. } => None,
        }
    }
}

pub fn config_row_presentation(
    setting_key: &str,
    setting_value: &str,
    setting_lock: SettingLock,
    setting_availability: SettingAvailability,
) -> ConfigRowPresentation {
    match setting_lock {
        SettingLock::NeverChangedHere => ConfigRowPresentation::ProtectedSettingRow(
            parse_setting_value(setting_key, setting_value),
        ),
        SettingLock::ChangedThroughSnippet => match parse_setting_value(setting_key, setting_value)
        {
            Err(SettingParseFailure::UnknownOption) => ConfigRowPresentation::UnknownOptionRow,
            Err(
                parse_failure @ (SettingParseFailure::NotYesOrNo
                | SettingParseFailure::NotAWholeNumber
                | SettingParseFailure::CountOutOfRange { .. }
                | SettingParseFailure::NotASize
                | SettingParseFailure::PathNotAbsolute
                | SettingParseFailure::EmptyText),
            ) => ConfigRowPresentation::NeedsReviewRow(parse_failure),
            Ok(editor_draft) => match setting_availability {
                SettingAvailability::ChangeableNow => {
                    ConfigRowPresentation::EditableSettingRow(editor_draft)
                }
                SettingAvailability::LockedUntilUnlocked => {
                    ConfigRowPresentation::LockedSettingRow {
                        lock_reason: SettingLockReason::UnlockRequired,
                        editor_draft,
                    }
                }
                SettingAvailability::NotAllowedAtRuntime => {
                    ConfigRowPresentation::LockedSettingRow {
                        lock_reason: SettingLockReason::NotAllowedAtRuntime,
                        editor_draft,
                    }
                }
            },
        },
    }
}

pub struct ConfigSettingRowInit {
    pub setting_key: String,
    pub setting_value: String,
    pub sibling_values: Vec<String>,
    pub value_position: usize,
    pub row_presentation: ConfigRowPresentation,
    pub change_activity: RowChangeActivity,
}

pub struct ConfigSettingRow {
    setting_key: String,
    setting_value: String,
    sibling_values: Vec<String>,
    value_position: usize,
    row_presentation: ConfigRowPresentation,
    change_activity: RowChangeActivity,
}

#[derive(Debug)]
pub enum ConfigSettingRowInput {
    ChangeActivityChanged(RowChangeActivity),
    DraftEdited(DraftEdit),
    ApplyRequested,
    DraftEditedAndApplied(DraftEdit),
    LineCopyRequested,
}

#[derive(Debug)]
pub enum ConfigSettingRowOutput {
    ValueApplied {
        setting_key: String,
        sibling_values: Vec<String>,
        value_position: usize,
        config_value: String,
    },
    LineCopyRequested {
        setting_key: String,
        sibling_values: Vec<String>,
        value_position: usize,
        editor_draft: TypedSettingValue,
    },
}

enum RowEditorWidgets {
    ReadOnlyWidgets,
    SwitchWidgets {
        switch_row: adw::SwitchRow,
        toggle_handler: glib::SignalHandlerId,
    },
    CountWidgets {
        spin_row: adw::SpinRow,
        value_handler: glib::SignalHandlerId,
        apply_button: gtk::Button,
    },
    SizeWidgets {
        spin_row: adw::SpinRow,
        value_handler: glib::SignalHandlerId,
        unit_dropdown: gtk::DropDown,
        unit_handler: glib::SignalHandlerId,
        apply_button: gtk::Button,
    },
    EntryWidgets {
        entry_row: adw::EntryRow,
    },
}

pub struct ConfigSettingRowWidgets {
    setting_row: adw::PreferencesRow,
    applying_spinner: adw::Spinner,
    editor_widgets: RowEditorWidgets,
}

fn suffix_icon(icon_name: &str, tooltip_text: &str, style_class: &str) -> gtk::Image {
    gtk::Image::builder()
        .icon_name(icon_name)
        .tooltip_text(tooltip_text)
        .valign(gtk::Align::Center)
        .css_classes([style_class])
        .build()
}

fn read_only_row(setting_key: &str, row_subtitle: &str) -> adw::PreferencesRow {
    adw::ActionRow::builder()
        .use_markup(false)
        .title(setting_key)
        .subtitle(row_subtitle)
        .subtitle_selectable(true)
        .subtitle_lines(0)
        .css_classes(["property"])
        .build()
        .upcast()
}

fn apply_button() -> gtk::Button {
    gtk::Button::builder()
        .icon_name("object-select-symbolic")
        .tooltip_text(gettext("Apply"))
        .valign(gtk::Align::Center)
        .css_classes(["suggested-action", "circular"])
        .build()
}

fn count_spin_row(setting_key: &str, minimum: f64, maximum: f64, shown_value: f64) -> adw::SpinRow {
    let spin_row = adw::SpinRow::with_range(minimum, maximum, 1.0);
    spin_row.set_title(setting_key);
    spin_row.set_use_markup(false);
    spin_row.set_digits(0);
    spin_row.set_numeric(true);
    spin_row.set_value(shown_value);
    spin_row
}

fn spin_entered_edit(spin_row: &adw::SpinRow) -> ConfigSettingRowInput {
    whole_number_in_text(spin_row.text().trim()).map_or(
        ConfigSettingRowInput::ApplyRequested,
        |entered_count| {
            ConfigSettingRowInput::DraftEditedAndApplied(DraftEdit::NumberSet(entered_count))
        },
    )
}

fn connect_spin_activation(spin_row: &adw::SpinRow, sender: &FactorySender<ConfigSettingRow>) {
    if let Some(spin_button) = spin_row
        .delegate()
        .and_then(|spin_delegate| spin_delegate.downcast::<gtk::SpinButton>().ok())
    {
        let activation_sender = sender.clone();
        let activated_row = spin_row.clone();
        spin_button.connect_activate(move |_activated_button| {
            activation_sender.input(spin_entered_edit(&activated_row));
        });
    }
}

impl ConfigSettingRow {
    pub fn is_changed_row(&self, setting_key: &str, value_position: usize) -> bool {
        self.setting_key == setting_key && self.value_position == value_position
    }

    fn draft_comparison(&self, editor_draft: &TypedSettingValue) -> DraftComparison {
        if parse_setting_value(&self.setting_key, &self.setting_value).as_ref() == Ok(editor_draft)
        {
            DraftComparison::SameAsStored
        } else {
            DraftComparison::ChangedFromStored
        }
    }

    fn applicable_value(&self, editor_draft: &TypedSettingValue) -> Option<String> {
        match self.draft_comparison(editor_draft) {
            DraftComparison::SameAsStored => None,
            DraftComparison::ChangedFromStored => {
                editor_draft.writable_value(&self.setting_key).ok()
            }
        }
    }

    fn apply_is_possible(&self) -> bool {
        self.row_presentation
            .editable_draft()
            .and_then(|editor_draft| self.applicable_value(editor_draft))
            .is_some()
    }

    fn draft_is_refused(&self) -> bool {
        self.row_presentation
            .editable_draft()
            .is_some_and(|editor_draft| editor_draft.writable_value(&self.setting_key).is_err())
    }

    fn report_applied_draft(&self, editor_draft: &TypedSettingValue, sender: &FactorySender<Self>) {
        if let Some(config_value) = self.applicable_value(editor_draft) {
            let _parent_closed = sender.output(ConfigSettingRowOutput::ValueApplied {
                setting_key: self.setting_key.clone(),
                sibling_values: self.sibling_values.clone(),
                value_position: self.value_position,
                config_value,
            });
        }
    }

    fn edit_draft(&mut self, draft_edit: DraftEdit, sender: &FactorySender<Self>) {
        let Some(editor_draft) = self.row_presentation.editable_draft() else {
            return;
        };
        let edited_draft = editor_draft.clone().with_draft_edit(draft_edit);
        match editor_draft.apply_timing() {
            DraftApplyTiming::AppliedOnEveryEdit => {
                self.report_applied_draft(&edited_draft, sender)
            }
            DraftApplyTiming::AppliedOnRequest => {
                self.row_presentation = ConfigRowPresentation::EditableSettingRow(edited_draft);
            }
        }
    }

    fn request_apply(&self, sender: &FactorySender<Self>) {
        if let Some(editor_draft) = self.row_presentation.editable_draft() {
            self.report_applied_draft(editor_draft, sender);
        }
    }

    fn request_line_copy(&self, sender: &FactorySender<Self>) {
        if let ConfigRowPresentation::LockedSettingRow { editor_draft, .. } = &self.row_presentation
        {
            let _parent_closed = sender.output(ConfigSettingRowOutput::LineCopyRequested {
                setting_key: self.setting_key.clone(),
                sibling_values: self.sibling_values.clone(),
                value_position: self.value_position,
                editor_draft: editor_draft.clone(),
            });
        }
    }

    fn editor_root(&self, editor_draft: &TypedSettingValue) -> adw::PreferencesRow {
        match editor_draft {
            TypedSettingValue::BooleanValue(switch_position) => adw::SwitchRow::builder()
                .use_markup(false)
                .title(&self.setting_key)
                .active(switch_position.is_switched_on())
                .build()
                .upcast(),
            TypedSettingValue::CountValue {
                count_value,
                minimum,
                maximum,
            } => count_spin_row(
                &self.setting_key,
                *minimum as f64,
                *maximum as f64,
                *count_value as f64,
            )
            .upcast(),
            TypedSettingValue::SizeValue(size_amount) => count_spin_row(
                &self.setting_key,
                0.0,
                SIZE_COUNT_CEILING,
                size_amount.unit_count as f64,
            )
            .upcast(),
            TypedSettingValue::PathValue(draft_text) | TypedSettingValue::TextValue(draft_text) => {
                adw::EntryRow::builder()
                    .use_markup(false)
                    .title(&self.setting_key)
                    .text(draft_text)
                    .show_apply_button(true)
                    .build()
                    .upcast()
            }
        }
    }

    fn connect_editor(
        &self,
        root: &adw::PreferencesRow,
        sender: &FactorySender<Self>,
    ) -> RowEditorWidgets {
        let Some(editor_draft) = self.row_presentation.editable_draft() else {
            return RowEditorWidgets::ReadOnlyWidgets;
        };
        match editor_draft {
            TypedSettingValue::BooleanValue(_) => root.downcast_ref::<adw::SwitchRow>().map_or(
                RowEditorWidgets::ReadOnlyWidgets,
                |switch_row| {
                    let toggle_sender = sender.clone();
                    let toggle_handler = switch_row.connect_active_notify(move |toggled_row| {
                        toggle_sender.input(ConfigSettingRowInput::DraftEdited(
                            DraftEdit::SwitchSet(SwitchPosition::from_switch_active(
                                toggled_row.is_active(),
                            )),
                        ));
                    });
                    RowEditorWidgets::SwitchWidgets {
                        switch_row: switch_row.clone(),
                        toggle_handler,
                    }
                },
            ),
            TypedSettingValue::CountValue { .. } => root.downcast_ref::<adw::SpinRow>().map_or(
                RowEditorWidgets::ReadOnlyWidgets,
                |spin_row| {
                    let value_sender = sender.clone();
                    let value_handler = spin_row.connect_value_notify(move |edited_row| {
                        value_sender.input(ConfigSettingRowInput::DraftEdited(
                            DraftEdit::NumberSet(edited_row.value() as u64),
                        ));
                    });
                    connect_spin_activation(spin_row, sender);
                    let apply_button = apply_button();
                    let apply_sender = sender.clone();
                    apply_button.connect_clicked(move |_clicked_button| {
                        apply_sender.input(ConfigSettingRowInput::ApplyRequested);
                    });
                    spin_row.add_suffix(&apply_button);
                    RowEditorWidgets::CountWidgets {
                        spin_row: spin_row.clone(),
                        value_handler,
                        apply_button,
                    }
                },
            ),
            TypedSettingValue::SizeValue(size_amount) => root
                .downcast_ref::<adw::SpinRow>()
                .map_or(RowEditorWidgets::ReadOnlyWidgets, |spin_row| {
                    let value_sender = sender.clone();
                    let value_handler = spin_row.connect_value_notify(move |edited_row| {
                        value_sender.input(ConfigSettingRowInput::DraftEdited(
                            DraftEdit::NumberSet(edited_row.value() as u64),
                        ));
                    });
                    connect_spin_activation(spin_row, sender);
                    let unit_dropdown = gtk::DropDown::builder()
                        .model(&size_unit_labels())
                        .selected(size_amount.size_unit.unit_position())
                        .valign(gtk::Align::Center)
                        .tooltip_text(gettext("Unit"))
                        .build();
                    let unit_sender = sender.clone();
                    let unit_handler = unit_dropdown.connect_selected_notify(move |chosen_unit| {
                        if let Some(size_unit) = SizeUnit::unit_at_position(chosen_unit.selected())
                        {
                            unit_sender.input(ConfigSettingRowInput::DraftEdited(
                                DraftEdit::SizeUnitSet(size_unit),
                            ));
                        }
                    });
                    let apply_button = apply_button();
                    let apply_sender = sender.clone();
                    apply_button.connect_clicked(move |_clicked_button| {
                        apply_sender.input(ConfigSettingRowInput::ApplyRequested);
                    });
                    spin_row.add_suffix(&unit_dropdown);
                    spin_row.add_suffix(&apply_button);
                    RowEditorWidgets::SizeWidgets {
                        spin_row: spin_row.clone(),
                        value_handler,
                        unit_dropdown,
                        unit_handler,
                        apply_button,
                    }
                }),
            TypedSettingValue::PathValue(_) | TypedSettingValue::TextValue(_) => root
                .downcast_ref::<adw::EntryRow>()
                .map_or(RowEditorWidgets::ReadOnlyWidgets, |entry_row| {
                    let text_sender = sender.clone();
                    entry_row.connect_changed(move |edited_row| {
                        text_sender.input(ConfigSettingRowInput::DraftEdited(DraftEdit::TextSet(
                            edited_row.text().to_string(),
                        )));
                    });
                    let apply_sender = sender.clone();
                    entry_row.connect_apply(move |_applied_row| {
                        apply_sender.input(ConfigSettingRowInput::ApplyRequested);
                    });
                    RowEditorWidgets::EntryWidgets {
                        entry_row: entry_row.clone(),
                    }
                }),
        }
    }

    fn add_read_only_suffixes(&self, root: &adw::PreferencesRow, sender: &FactorySender<Self>) {
        let Some(action_row) = root.downcast_ref::<adw::ActionRow>() else {
            return;
        };
        match &self.row_presentation {
            ConfigRowPresentation::ProtectedSettingRow(_) => {
                action_row.add_suffix(&suffix_icon(
                    "changes-prevent-symbolic",
                    &gettext(
                        "This setting runs commands or changes who ClamAV runs as, so Lazaret \
                         never offers to change it",
                    ),
                    "dim-label",
                ));
            }
            ConfigRowPresentation::UnknownOptionRow => {
                action_row.add_suffix(&suffix_icon(
                    "dialog-information-symbolic",
                    &describe_parse_failure(SettingParseFailure::UnknownOption),
                    "dim-label",
                ));
            }
            ConfigRowPresentation::NeedsReviewRow(_) => {
                action_row.add_suffix(&suffix_icon(
                    "dialog-warning-symbolic",
                    &gettext("Check this value in the configuration file."),
                    "warning",
                ));
            }
            ConfigRowPresentation::LockedSettingRow { lock_reason, .. } => {
                action_row.add_suffix(&suffix_icon(
                    "changes-prevent-symbolic",
                    &setting_lock_tooltip(*lock_reason),
                    "dim-label",
                ));
                let copy_button = gtk::Button::builder()
                    .icon_name("edit-copy-symbolic")
                    .tooltip_text(gettext("Copy configuration line…"))
                    .valign(gtk::Align::Center)
                    .css_classes(["flat"])
                    .build();
                let copy_sender = sender.clone();
                copy_button.connect_clicked(move |_clicked_button| {
                    copy_sender.input(ConfigSettingRowInput::LineCopyRequested);
                });
                action_row.add_suffix(&copy_button);
                action_row.set_activatable_widget(Some(&copy_button));
            }
            ConfigRowPresentation::EditableSettingRow(_) => {}
        }
    }
}

impl FactoryComponent for ConfigSettingRow {
    type ParentWidget = adw::PreferencesGroup;
    type CommandOutput = ();
    type Input = ConfigSettingRowInput;
    type Output = ConfigSettingRowOutput;
    type Init = ConfigSettingRowInit;
    type Root = adw::PreferencesRow;
    type Widgets = ConfigSettingRowWidgets;
    type Index = DynamicIndex;

    fn init_model(
        row_init: Self::Init,
        _row_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self {
            setting_key: row_init.setting_key,
            setting_value: row_init.setting_value,
            sibling_values: row_init.sibling_values,
            value_position: row_init.value_position,
            row_presentation: row_init.row_presentation,
            change_activity: row_init.change_activity,
        }
    }

    fn init_root(&self) -> Self::Root {
        match &self.row_presentation {
            ConfigRowPresentation::EditableSettingRow(editor_draft) => {
                self.editor_root(editor_draft)
            }
            ConfigRowPresentation::NeedsReviewRow(parse_failure) => read_only_row(
                &self.setting_key,
                &format!(
                    "{}\n{}",
                    self.setting_value,
                    describe_parse_failure(*parse_failure)
                ),
            ),
            ConfigRowPresentation::LockedSettingRow {
                editor_draft: TypedSettingValue::BooleanValue(switch_position),
                ..
            }
            | ConfigRowPresentation::ProtectedSettingRow(Ok(TypedSettingValue::BooleanValue(
                switch_position,
            ))) => {
                let switch_row = adw::ActionRow::builder()
                    .use_markup(false)
                    .title(&self.setting_key)
                    .build();
                switch_row.add_suffix(
                    &gtk::Switch::builder()
                        .active(switch_position.is_switched_on())
                        .sensitive(false)
                        .valign(gtk::Align::Center)
                        .build(),
                );
                switch_row.upcast()
            }
            ConfigRowPresentation::ProtectedSettingRow(_)
            | ConfigRowPresentation::UnknownOptionRow
            | ConfigRowPresentation::LockedSettingRow { .. } => {
                read_only_row(&self.setting_key, &self.setting_value)
            }
        }
    }

    fn init_widgets(
        &mut self,
        _row_index: &DynamicIndex,
        root: Self::Root,
        _returned_widget: &gtk::Widget,
        sender: FactorySender<Self>,
    ) -> Self::Widgets {
        let applying_spinner = adw::Spinner::builder()
            .tooltip_text(gettext("Applying, and restarting ClamAV"))
            .visible(false)
            .build();
        self.add_read_only_suffixes(&root, &sender);
        let editor_widgets = self.connect_editor(&root, &sender);
        if let Some(entry_row) = root.downcast_ref::<adw::EntryRow>() {
            entry_row.add_suffix(&applying_spinner);
        } else if let Some(action_row) = root.downcast_ref::<adw::ActionRow>() {
            action_row.add_suffix(&applying_spinner);
        }
        ConfigSettingRowWidgets {
            setting_row: root,
            applying_spinner,
            editor_widgets,
        }
    }

    fn update(&mut self, row_input: Self::Input, sender: FactorySender<Self>) {
        match row_input {
            ConfigSettingRowInput::ChangeActivityChanged(change_activity) => {
                self.change_activity = change_activity;
            }
            ConfigSettingRowInput::DraftEdited(draft_edit) => self.edit_draft(draft_edit, &sender),
            ConfigSettingRowInput::ApplyRequested => self.request_apply(&sender),
            ConfigSettingRowInput::DraftEditedAndApplied(draft_edit) => {
                self.edit_draft(draft_edit, &sender);
                self.request_apply(&sender);
            }
            ConfigSettingRowInput::LineCopyRequested => self.request_line_copy(&sender),
        }
    }

    fn update_view(&self, widgets: &mut Self::Widgets, _sender: FactorySender<Self>) {
        widgets
            .applying_spinner
            .set_visible(self.change_activity.shows_applying_spinner());
        widgets
            .setting_row
            .set_sensitive(self.change_activity.accepts_changes());
        let Some(editor_draft) = self.row_presentation.editable_draft() else {
            return;
        };
        match &widgets.editor_widgets {
            RowEditorWidgets::ReadOnlyWidgets => {}
            RowEditorWidgets::SwitchWidgets {
                switch_row,
                toggle_handler,
            } => {
                if let Some(switch_position) = editor_draft.shown_switch_position() {
                    switch_row.block_signal(toggle_handler);
                    switch_row.set_active(switch_position.is_switched_on());
                    switch_row.unblock_signal(toggle_handler);
                }
            }
            RowEditorWidgets::CountWidgets {
                spin_row,
                value_handler,
                apply_button,
            } => {
                if let Some(shown_count) = editor_draft.shown_count() {
                    spin_row.block_signal(value_handler);
                    spin_row.set_value(shown_count as f64);
                    spin_row.unblock_signal(value_handler);
                }
                apply_button.set_sensitive(self.apply_is_possible());
            }
            RowEditorWidgets::SizeWidgets {
                spin_row,
                value_handler,
                unit_dropdown,
                unit_handler,
                apply_button,
            } => {
                if let Some(shown_count) = editor_draft.shown_count() {
                    spin_row.block_signal(value_handler);
                    spin_row.set_value(shown_count as f64);
                    spin_row.unblock_signal(value_handler);
                }
                if let Some(size_unit) = editor_draft.shown_size_unit() {
                    unit_dropdown.block_signal(unit_handler);
                    unit_dropdown.set_selected(size_unit.unit_position());
                    unit_dropdown.unblock_signal(unit_handler);
                }
                apply_button.set_sensitive(self.apply_is_possible());
            }
            RowEditorWidgets::EntryWidgets { entry_row } => {
                entry_row.set_show_apply_button(self.apply_is_possible());
                if self.draft_is_refused() {
                    entry_row.add_css_class("error");
                } else {
                    entry_row.remove_css_class("error");
                }
            }
        }
    }
}

#[cfg(test)]
mod config_setting_row_tests {
    use super::*;
    use crate::host_services::clamav_config::typed_setting_values::SizeAmount;

    fn presentation_of(
        setting_key: &str,
        setting_value: &str,
        setting_availability: SettingAvailability,
    ) -> ConfigRowPresentation {
        config_row_presentation(
            setting_key,
            setting_value,
            SettingLock::ChangedThroughSnippet,
            setting_availability,
        )
    }

    #[test]
    fn a_locked_row_has_no_editable_widget() {
        [
            SettingAvailability::LockedUntilUnlocked,
            SettingAvailability::NotAllowedAtRuntime,
        ]
        .into_iter()
        .for_each(|setting_availability| {
            let row_presentation =
                presentation_of("OnAccessExtraScanning", "yes", setting_availability);
            assert!(
                matches!(
                    row_presentation,
                    ConfigRowPresentation::LockedSettingRow { .. }
                ),
                "{setting_availability:?}"
            );
        });
        let protected_row = config_row_presentation(
            "LogFile",
            "/var/log/clamd.log",
            SettingLock::NeverChangedHere,
            SettingAvailability::ChangeableNow,
        );
        assert_eq!(
            protected_row,
            ConfigRowPresentation::ProtectedSettingRow(Ok(TypedSettingValue::PathValue(
                "/var/log/clamd.log".to_owned()
            )))
        );
        assert_eq!(
            config_row_presentation(
                "Foreground",
                "yes",
                SettingLock::NeverChangedHere,
                SettingAvailability::ChangeableNow,
            ),
            ConfigRowPresentation::ProtectedSettingRow(Ok(TypedSettingValue::BooleanValue(
                SwitchPosition::SwitchedOn
            )))
        );
        assert_eq!(
            presentation_of(
                "OnAccessPrevention",
                "true",
                SettingAvailability::NotAllowedAtRuntime
            ),
            ConfigRowPresentation::LockedSettingRow {
                lock_reason: SettingLockReason::NotAllowedAtRuntime,
                editor_draft: TypedSettingValue::BooleanValue(SwitchPosition::SwitchedOn),
            }
        );
        assert_eq!(protected_row.editable_draft(), None);
    }

    #[test]
    fn unlocked_rows_get_an_editor_for_their_value_type() {
        assert_eq!(
            presentation_of(
                "OnAccessExtraScanning",
                "yes",
                SettingAvailability::ChangeableNow
            ),
            ConfigRowPresentation::EditableSettingRow(TypedSettingValue::BooleanValue(
                SwitchPosition::SwitchedOn
            ))
        );
        assert_eq!(
            presentation_of("MaxThreads", "4", SettingAvailability::ChangeableNow),
            ConfigRowPresentation::EditableSettingRow(TypedSettingValue::CountValue {
                count_value: 4,
                minimum: 1,
                maximum: 256
            })
        );
        assert_eq!(
            presentation_of("MaxFileSize", "25M", SettingAvailability::ChangeableNow),
            ConfigRowPresentation::EditableSettingRow(TypedSettingValue::SizeValue(SizeAmount {
                unit_count: 25,
                size_unit: SizeUnit::Mebibytes
            }))
        );
        assert_eq!(
            presentation_of(
                "OnAccessIncludePath",
                "/home",
                SettingAvailability::ChangeableNow
            ),
            ConfigRowPresentation::EditableSettingRow(TypedSettingValue::PathValue(
                "/home".to_owned()
            ))
        );
    }

    #[test]
    fn unknown_and_unparseable_values_are_read_only() {
        let unknown_row = presentation_of(
            "NotARealClamdOption",
            "rejected",
            SettingAvailability::ChangeableNow,
        );
        assert_eq!(unknown_row, ConfigRowPresentation::UnknownOptionRow);
        let unparseable_row = presentation_of(
            "OnAccessExtraScanning",
            "tru",
            SettingAvailability::ChangeableNow,
        );
        assert_eq!(
            unparseable_row,
            ConfigRowPresentation::NeedsReviewRow(SettingParseFailure::NotYesOrNo)
        );
        assert_eq!(unknown_row.editable_draft(), None);
        assert_eq!(unparseable_row.editable_draft(), None);
    }

    #[test]
    fn typed_editors_write_the_same_config_text_as_before() {
        let edited_text = |editor_draft: TypedSettingValue, draft_edit: DraftEdit| {
            editor_draft.with_draft_edit(draft_edit).config_value_text()
        };
        assert_eq!(
            edited_text(
                TypedSettingValue::BooleanValue(SwitchPosition::SwitchedOn),
                DraftEdit::SwitchSet(SwitchPosition::SwitchedOff)
            ),
            "no"
        );
        assert_eq!(
            edited_text(
                TypedSettingValue::CountValue {
                    count_value: 4,
                    minimum: 1,
                    maximum: 256
                },
                DraftEdit::NumberSet(8)
            ),
            "8"
        );
        assert_eq!(
            edited_text(
                TypedSettingValue::SizeValue(SizeAmount {
                    unit_count: 5,
                    size_unit: SizeUnit::Mebibytes
                }),
                DraftEdit::SizeUnitSet(SizeUnit::Kibibytes)
            ),
            "5K"
        );
        assert_eq!(
            edited_text(
                TypedSettingValue::PathValue("/home".to_owned()),
                DraftEdit::TextSet("/srv/inbox".to_owned())
            ),
            "/srv/inbox"
        );
    }

    #[test]
    fn counts_stay_in_range_and_mismatched_edits_change_nothing() {
        let count_draft = TypedSettingValue::CountValue {
            count_value: 4,
            minimum: 1,
            maximum: 256,
        };
        assert_eq!(
            count_draft
                .clone()
                .with_draft_edit(DraftEdit::NumberSet(9000))
                .config_value_text(),
            "256"
        );
        assert_eq!(
            count_draft
                .clone()
                .with_draft_edit(DraftEdit::SwitchSet(SwitchPosition::SwitchedOn)),
            count_draft
        );
    }

    #[test]
    fn invalid_paths_and_text_cannot_be_applied() {
        assert!(
            TypedSettingValue::PathValue("relative/path".to_owned())
                .writable_value("OnAccessIncludePath")
                .is_err()
        );
        assert!(
            TypedSettingValue::TextValue("mirror;reboot".to_owned())
                .writable_value("DatabaseMirror")
                .is_err()
        );
        assert_eq!(
            TypedSettingValue::PathValue("/srv".to_owned()).writable_value("OnAccessIncludePath"),
            Ok("/srv".to_owned())
        );
    }
}

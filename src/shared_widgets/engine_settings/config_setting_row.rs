use gettextrs::gettext;
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::host_services::clamav_config::setting_provenance::SettingLock;

pub struct ConfigSettingRowInit {
    pub setting_key: String,
    pub setting_value: String,
    pub setting_lock: SettingLock,
    pub sibling_values: Vec<String>,
    pub value_position: usize,
}

pub struct ConfigSettingRow {
    setting_key: String,
    setting_value: String,
    setting_lock: SettingLock,
    sibling_values: Vec<String>,
    value_position: usize,
    change_running: bool,
}

#[derive(Debug)]
pub enum ConfigSettingRowInput {
    ChangeRunningChanged(bool),
}

#[derive(Debug)]
pub enum ConfigSettingRowOutput {
    ValueApplied {
        row_index: DynamicIndex,
        setting_key: String,
        sibling_values: Vec<String>,
        value_position: usize,
        edited_text: String,
    },
}

pub struct ConfigSettingRowWidgets {
    setting_row: adw::PreferencesRow,
    applying_spinner: adw::Spinner,
}

fn lock_indicator(tooltip_text: &str) -> gtk::Image {
    gtk::Image::builder()
        .icon_name("changes-prevent-symbolic")
        .tooltip_text(tooltip_text)
        .valign(gtk::Align::Center)
        .css_classes(["dim-label"])
        .build()
}

fn protected_setting_row(setting_key: &str, setting_value: &str) -> adw::PreferencesRow {
    let setting_row = adw::ActionRow::builder()
        .use_markup(false)
        .title(setting_key)
        .subtitle(setting_value)
        .subtitle_selectable(true)
        .build();
    setting_row.add_suffix(&lock_indicator(&gettext(
        "This setting runs commands or changes who ClamAV runs as, so Lazaret never offers to \
         change it",
    )));
    setting_row.upcast()
}

fn editable_setting_row(setting_key: &str, setting_value: &str) -> adw::PreferencesRow {
    let setting_row = adw::EntryRow::builder()
        .title(setting_key)
        .text(setting_value)
        .show_apply_button(true)
        .build();
    setting_row.add_suffix(&lock_indicator(&gettext(
        "Managed outside Lazaret. Unless the setting is unlocked, applying copies the change \
         instead of making it.",
    )));
    setting_row.upcast()
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
            setting_lock: row_init.setting_lock,
            sibling_values: row_init.sibling_values,
            value_position: row_init.value_position,
            change_running: false,
        }
    }

    fn init_root(&self) -> Self::Root {
        match self.setting_lock {
            SettingLock::NeverChangedHere => {
                protected_setting_row(&self.setting_key, &self.setting_value)
            }
            SettingLock::ChangedThroughSnippet => {
                editable_setting_row(&self.setting_key, &self.setting_value)
            }
        }
    }

    fn init_widgets(
        &mut self,
        row_index: &DynamicIndex,
        root: Self::Root,
        _returned_widget: &gtk::Widget,
        sender: FactorySender<Self>,
    ) -> Self::Widgets {
        let applying_spinner = adw::Spinner::builder()
            .tooltip_text(gettext("Applying, and restarting ClamAV"))
            .visible(false)
            .build();
        if let Some(entry_row) = root.downcast_ref::<adw::EntryRow>() {
            entry_row.add_suffix(&applying_spinner);
            let applied_index = row_index.clone();
            let setting_key = self.setting_key.clone();
            let sibling_values = self.sibling_values.clone();
            let value_position = self.value_position;
            entry_row.connect_apply(move |applied_row| {
                let _parent_closed = sender.output(ConfigSettingRowOutput::ValueApplied {
                    row_index: applied_index.clone(),
                    setting_key: setting_key.clone(),
                    sibling_values: sibling_values.clone(),
                    value_position,
                    edited_text: applied_row.text().to_string(),
                });
            });
        }
        ConfigSettingRowWidgets {
            setting_row: root,
            applying_spinner,
        }
    }

    fn update(&mut self, row_input: Self::Input, _sender: FactorySender<Self>) {
        match row_input {
            ConfigSettingRowInput::ChangeRunningChanged(change_running) => {
                self.change_running = change_running;
            }
        }
    }

    fn update_view(&self, widgets: &mut Self::Widgets, _sender: FactorySender<Self>) {
        widgets.applying_spinner.set_visible(self.change_running);
        widgets.setting_row.set_sensitive(!self.change_running);
    }
}

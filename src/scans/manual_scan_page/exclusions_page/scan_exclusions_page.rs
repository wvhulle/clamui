use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk, gtk::gio,
    prelude::FactoryVecDeque,
};

use crate::{
    host_services::{
        clamav_scanner::scan_exclusion_rules::ExclusionEntry,
        desktop::{
            stored_settings::{
                EXCLUSION_RULES_KEY, add_exclusion_entry, application_settings,
                read_exclusion_entries, remove_exclusion_entry, set_entry_enabled,
            },
            stored_settings_watch::forward_setting_changes,
        },
    },
    scans::manual_scan_page::exclusions_page::scan_exclusion_row::{
        ScanExclusionRow, ScanExclusionRowOutput, is_preset_pattern,
    },
};

pub struct ScanExclusionsSection {
    stored_settings: gio::Settings,
    exclusion_entries: Vec<ExclusionEntry>,
    draft_cleared: bool,
    preset_rows: FactoryVecDeque<ScanExclusionRow>,
    custom_rows: FactoryVecDeque<ScanExclusionRow>,
}

#[derive(Debug)]
pub enum ScanExclusionsSectionInput {
    DraftPatternApplied(String),
    EnabledToggled {
        exclusion_pattern: String,
        is_enabled: bool,
    },
    RemovalRequested {
        exclusion_pattern: String,
    },
    StoredRulesChanged,
}

fn forwarded_row_output(row_output: ScanExclusionRowOutput) -> ScanExclusionsSectionInput {
    match row_output {
        ScanExclusionRowOutput::EnabledToggled {
            exclusion_pattern,
            is_enabled,
        } => ScanExclusionsSectionInput::EnabledToggled {
            exclusion_pattern,
            is_enabled,
        },
        ScanExclusionRowOutput::RemovalRequested { exclusion_pattern } => {
            ScanExclusionsSectionInput::RemovalRequested { exclusion_pattern }
        }
    }
}

fn boxed_list() -> gtk::ListBox {
    gtk::ListBox::builder()
        .css_classes(["boxed-list"])
        .selection_mode(gtk::SelectionMode::None)
        .build()
}

impl ScanExclusionsSection {
    fn show_exclusion_entries(&mut self, exclusion_entries: Vec<ExclusionEntry>) {
        if exclusion_entries == self.exclusion_entries {
            return;
        }
        let mut preset_guard = self.preset_rows.guard();
        let mut custom_guard = self.custom_rows.guard();
        preset_guard.clear();
        custom_guard.clear();
        exclusion_entries
            .iter()
            .cloned()
            .for_each(|exclusion_entry| {
                if is_preset_pattern(&exclusion_entry.exclusion_pattern) {
                    preset_guard.push_back(exclusion_entry);
                } else {
                    custom_guard.push_back(exclusion_entry);
                }
            });
        drop(preset_guard);
        drop(custom_guard);
        self.exclusion_entries = exclusion_entries;
    }

    fn record_enabled_change(&mut self, changed_pattern: &str, is_enabled: bool) {
        self.exclusion_entries
            .iter_mut()
            .filter(|exclusion_entry| exclusion_entry.exclusion_pattern == changed_pattern)
            .for_each(|exclusion_entry| exclusion_entry.is_enabled = is_enabled);
    }
}

#[relm4::component(pub)]
impl Component for ScanExclusionsSection {
    type Init = ();
    type Input = ScanExclusionsSectionInput;
    type Output = ();
    type CommandOutput = ();

    view! {
        adw::PreferencesGroup {
            gtk::Box {
            set_orientation: gtk::Orientation::Vertical,
            set_spacing: 24,

            adw::PreferencesGroup {
                set_title: &gettext("Preset Exclusions"),
                set_description: Some(&gettext(
                    "Common directories to exclude from scanning. Changes save immediately.",
                )),

                #[local_ref]
                preset_list -> gtk::ListBox {},
            },

            adw::PreferencesGroup {
                set_title: &gettext("Custom Exclusions"),
                set_description: Some(&gettext(
                    "Enter an absolute path or a pattern such as *.tmp. Changes save immediately.",
                )),

                gtk::ListBox {
                    add_css_class: "boxed-list",
                    set_selection_mode: gtk::SelectionMode::None,
                    set_margin_bottom: 12,

                    adw::EntryRow {
                        set_title: &gettext("/path/to/exclude or *.tmp"),
                        set_show_apply_button: true,
                        #[track(model.draft_cleared)]
                        set_text: "",
                        connect_apply[sender] => move |applied_row| {
                            sender.input(ScanExclusionsSectionInput::DraftPatternApplied(
                                applied_row.text().to_string(),
                            ));
                        },
                    },
                },

                #[local_ref]
                custom_list -> gtk::ListBox {},
            },
            },
        }
    }

    fn init(
        _page_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let stored_settings = application_settings();
        forward_setting_changes(
            &stored_settings,
            &[EXCLUSION_RULES_KEY],
            sender.input_sender(),
            |_changed_settings, _changed_key| ScanExclusionsSectionInput::StoredRulesChanged,
        );
        let mut model = Self {
            exclusion_entries: Vec::new(),
            draft_cleared: false,
            preset_rows: FactoryVecDeque::builder()
                .launch(boxed_list())
                .forward(sender.input_sender(), forwarded_row_output),
            custom_rows: FactoryVecDeque::builder()
                .launch(boxed_list())
                .forward(sender.input_sender(), forwarded_row_output),
            stored_settings,
        };
        model.show_exclusion_entries(read_exclusion_entries(&model.stored_settings));
        let preset_list = model.preset_rows.widget();
        let custom_list = model.custom_rows.widget();
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: ScanExclusionsSectionInput,
        _sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        self.draft_cleared = false;
        match page_input {
            ScanExclusionsSectionInput::DraftPatternApplied(draft_pattern) => {
                let added_pattern = draft_pattern.trim().to_owned();
                if !added_pattern.is_empty() {
                    add_exclusion_entry(
                        &self.stored_settings,
                        ExclusionEntry::enabled_pattern(added_pattern),
                    );
                    self.draft_cleared = true;
                }
            }
            ScanExclusionsSectionInput::EnabledToggled {
                exclusion_pattern,
                is_enabled,
            } => {
                self.record_enabled_change(&exclusion_pattern, is_enabled);
                set_entry_enabled(&self.stored_settings, &exclusion_pattern, is_enabled);
            }
            ScanExclusionsSectionInput::RemovalRequested { exclusion_pattern } => {
                remove_exclusion_entry(&self.stored_settings, &exclusion_pattern);
            }
            ScanExclusionsSectionInput::StoredRulesChanged => {
                self.show_exclusion_entries(read_exclusion_entries(&self.stored_settings));
            }
        }
    }
}

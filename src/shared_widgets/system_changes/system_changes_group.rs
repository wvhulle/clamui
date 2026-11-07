use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    host_services::settings_helper::helper_audit_records::HelperAuditEntry,
    shared_widgets::{
        loading_indicators::{LOAD_FAILED_PAGE_NAME, loading_placeholder_stack},
        step_timeline::runtime_reduction_steps::ReducedSettingGroup,
        system_changes::{
            system_change_row::SystemChangeRow,
            system_changes_state::{
                SystemChangesReadFailure, SystemChangesView, audit_entries_for_settings,
                read_system_changes,
            },
        },
    },
};

pub struct SystemChangesGroupInit {
    pub setting_group: ReducedSettingGroup,
    pub group_description: String,
    pub empty_title: String,
}

pub struct SystemChangesGroup {
    setting_group: ReducedSettingGroup,
    system_changes_view: SystemChangesView,
    system_change_rows: FactoryVecDeque<SystemChangeRow>,
}

#[derive(Debug)]
pub enum SystemChangesGroupInput {
    ReloadRequested,
}

#[derive(Debug)]
pub enum SystemChangesGroupCommand {
    SystemChangesLoaded(Result<Vec<HelperAuditEntry>, SystemChangesReadFailure>),
}

pub fn system_changes_failure_text(system_changes_view: &SystemChangesView) -> String {
    match system_changes_view {
        SystemChangesView::SystemChangesFailed(read_failure) => {
            gettext("The system journal can't be read: {error}")
                .replace("{error}", &read_failure.to_string())
        }
        SystemChangesView::SystemChangesLoading | SystemChangesView::SystemChangesLoaded => {
            String::new()
        }
    }
}

impl SystemChangesGroup {
    fn reload_system_changes(sender: &ComponentSender<Self>) {
        sender.oneshot_command(async {
            SystemChangesGroupCommand::SystemChangesLoaded(read_system_changes().await)
        });
    }

    fn replace_rows(&mut self, audit_entries: Vec<HelperAuditEntry>) {
        let mut row_guard = self.system_change_rows.guard();
        row_guard.clear();
        audit_entries.into_iter().for_each(|audit_entry| {
            row_guard.push_back(audit_entry);
        });
    }
}

#[relm4::component(pub)]
impl Component for SystemChangesGroup {
    type Init = SystemChangesGroupInit;
    type Input = SystemChangesGroupInput;
    type Output = ();
    type CommandOutput = SystemChangesGroupCommand;

    view! {
        adw::PreferencesGroup {
            set_title: &gettext("System changes"),
            set_description: Some(&group_init.group_description),
            #[wrap(Some)]
            set_header_suffix = &gtk::Button {
                set_icon_name: "view-refresh-symbolic",
                set_tooltip_text: Some(&gettext("Refresh")),
                set_valign: gtk::Align::Center,
                add_css_class: "flat",
                connect_clicked => SystemChangesGroupInput::ReloadRequested,
            },

            #[local_ref]
            system_change_list -> gtk::ListBox {
                add_css_class: "boxed-list",
                set_selection_mode: gtk::SelectionMode::None,
                #[wrap(Some)]
                #[local_ref]
                set_placeholder = system_change_placeholder -> gtk::Stack {
                    add_named[Some(LOAD_FAILED_PAGE_NAME)] = &adw::StatusPage {
                        add_css_class: "compact",
                        set_icon_name: Some("dialog-error-symbolic"),
                        set_title: &gettext("System changes can't be read"),
                        #[watch]
                        set_description: Some(&gtk::glib::markup_escape_text(
                            &system_changes_failure_text(&model.system_changes_view),
                        )),
                    },
                    #[watch]
                    set_visible_child_name: model.system_changes_view.placeholder_page_name(),
                },
            },
        }
    }

    fn init(
        group_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = Self {
            setting_group: group_init.setting_group,
            system_changes_view: SystemChangesView::SystemChangesLoading,
            system_change_rows: FactoryVecDeque::builder()
                .launch(gtk::ListBox::default())
                .detach(),
        };
        let system_change_list = model.system_change_rows.widget();
        let system_change_placeholder = &loading_placeholder_stack(
            &gettext("Loading system changes…"),
            &adw::StatusPage::builder()
                .css_classes(["compact"])
                .icon_name("changes-prevent-symbolic")
                .title(group_init.empty_title.as_str())
                .build(),
        );
        let widgets = view_output!();
        Self::reload_system_changes(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        group_input: SystemChangesGroupInput,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match group_input {
            SystemChangesGroupInput::ReloadRequested => Self::reload_system_changes(&sender),
        }
    }

    fn update_cmd(
        &mut self,
        group_command: SystemChangesGroupCommand,
        _sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match group_command {
            SystemChangesGroupCommand::SystemChangesLoaded(Ok(audit_entries)) => {
                self.system_changes_view = SystemChangesView::SystemChangesLoaded;
                let grouped_entries = audit_entries_for_settings(audit_entries, self.setting_group);
                self.replace_rows(grouped_entries);
            }
            SystemChangesGroupCommand::SystemChangesLoaded(Err(read_failure)) => {
                self.system_changes_view = SystemChangesView::SystemChangesFailed(read_failure);
                self.replace_rows(Vec::new());
            }
        }
    }
}

use std::path::PathBuf;

use relm4::{FactorySender, adw, adw::prelude::*, gtk::glib, prelude::FactoryComponent};

use crate::{
    host_services::desktop::file_manager_actions::{
        FileManagerKind, file_manager_action_installed, install_file_manager_action,
        remove_file_manager_action,
    },
    scan_page::scan_schedule_page::scan_schedule_units::current_launcher_path,
};

pub struct FileManagerRow {
    file_manager: FileManagerKind,
    data_directory: PathBuf,
    action_installed: bool,
    change_failure_text: String,
}

#[derive(Debug)]
pub enum FileManagerRowInput {
    IntegrationToggled(bool),
}

#[derive(Debug)]
pub enum FileManagerRowCommand {
    IntegrationChangeFinished(Result<(), String>),
}

fn changed_integration(
    file_manager: FileManagerKind,
    data_directory: PathBuf,
    action_installed: bool,
) -> Result<(), String> {
    if action_installed {
        current_launcher_path().and_then(|launcher_path| {
            install_file_manager_action(file_manager, &data_directory, &launcher_path)
        })
    } else {
        remove_file_manager_action(file_manager, &data_directory)
    }
    .map_err(|change_failure| change_failure.to_string())
}

#[relm4::factory(pub)]
impl FactoryComponent for FileManagerRow {
    type Init = FileManagerKind;
    type Input = FileManagerRowInput;
    type Output = ();
    type CommandOutput = FileManagerRowCommand;
    type ParentWidget = adw::PreferencesGroup;

    view! {
        adw::SwitchRow {
            set_title: self.file_manager.displayed_name(),
            #[watch]
            #[block_signal(integration_toggled_handler)]
            set_active: self.action_installed,
            #[watch]
            set_subtitle: &self.change_failure_text,
            connect_active_notify[sender] => move |changed_row| {
                sender.input(FileManagerRowInput::IntegrationToggled(changed_row.is_active()));
            } @integration_toggled_handler,
        }
    }

    fn init_model(
        file_manager: Self::Init,
        _row_index: &Self::Index,
        _sender: FactorySender<Self>,
    ) -> Self {
        let data_directory = glib::user_data_dir();
        Self {
            action_installed: file_manager_action_installed(file_manager, &data_directory),
            file_manager,
            data_directory,
            change_failure_text: String::new(),
        }
    }

    fn update(&mut self, row_input: Self::Input, sender: FactorySender<Self>) {
        match row_input {
            FileManagerRowInput::IntegrationToggled(action_installed) => {
                self.action_installed = action_installed;
                let file_manager = self.file_manager;
                let data_directory = self.data_directory.clone();
                sender.oneshot_command(async move {
                    FileManagerRowCommand::IntegrationChangeFinished(changed_integration(
                        file_manager,
                        data_directory,
                        action_installed,
                    ))
                });
            }
        }
    }

    fn update_cmd(&mut self, row_command: Self::CommandOutput, _sender: FactorySender<Self>) {
        match row_command {
            FileManagerRowCommand::IntegrationChangeFinished(change_outcome) => {
                self.change_failure_text = change_outcome.err().unwrap_or_default();
            }
        }
    }
}

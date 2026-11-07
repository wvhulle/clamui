use std::{
    io,
    path::{Path, PathBuf},
};

use gettextrs::gettext;
use relm4::{FactorySender, adw, adw::prelude::*, gtk::glib, prelude::FactoryComponent};

use crate::{
    host_services::desktop::file_manager_actions::{
        FileManagerKind, file_manager_action_installed, install_file_manager_action,
        remove_file_manager_action,
    },
    scans::scheduled_scans_page::scan_schedule_units::current_launcher_path,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrationPresence {
    ActionInstalled,
    ActionAbsent,
}

#[derive(Debug, thiserror::Error)]
pub enum IntegrationChangeFailure {
    #[error("the Lazaret launcher could not be located: {0}")]
    LauncherNotFound(io::Error),
    #[error("the file manager action could not be written: {0}")]
    ActionUnwritable(io::Error),
    #[error("the file manager action could not be removed: {0}")]
    ActionUnremovable(io::Error),
}

#[derive(Debug)]
pub enum IntegrationState {
    IntegrationInstalled,
    IntegrationAbsent,
    ChangingIntegration {
        target_presence: IntegrationPresence,
    },
    ChangeFailed {
        actual_presence: IntegrationPresence,
        change_failure: IntegrationChangeFailure,
    },
}

#[derive(Debug)]
pub enum IntegrationChangeOutcome {
    ChangeSucceeded {
        target_presence: IntegrationPresence,
    },
    ChangeRefused {
        actual_presence: IntegrationPresence,
        change_failure: IntegrationChangeFailure,
    },
}

pub struct FileManagerRow {
    file_manager: FileManagerKind,
    data_directory: PathBuf,
    integration_state: IntegrationState,
}

#[derive(Debug)]
pub enum FileManagerRowInput {
    InstallRequested,
    RemovalRequested,
}

#[derive(Debug)]
pub enum FileManagerRowCommand {
    IntegrationChangeFinished(IntegrationChangeOutcome),
}

const fn settled_integration(integration_presence: IntegrationPresence) -> IntegrationState {
    match integration_presence {
        IntegrationPresence::ActionInstalled => IntegrationState::IntegrationInstalled,
        IntegrationPresence::ActionAbsent => IntegrationState::IntegrationAbsent,
    }
}

fn read_integration_presence(
    file_manager: FileManagerKind,
    data_directory: &Path,
) -> IntegrationPresence {
    if file_manager_action_installed(file_manager, data_directory) {
        IntegrationPresence::ActionInstalled
    } else {
        IntegrationPresence::ActionAbsent
    }
}

pub fn integration_after_change(change_outcome: IntegrationChangeOutcome) -> IntegrationState {
    match change_outcome {
        IntegrationChangeOutcome::ChangeSucceeded { target_presence } => {
            settled_integration(target_presence)
        }
        IntegrationChangeOutcome::ChangeRefused {
            actual_presence,
            change_failure,
        } => IntegrationState::ChangeFailed {
            actual_presence,
            change_failure,
        },
    }
}

pub const fn switch_shows_installed(integration_state: &IntegrationState) -> bool {
    matches!(
        integration_state,
        IntegrationState::IntegrationInstalled
            | IntegrationState::ChangingIntegration {
                target_presence: IntegrationPresence::ActionInstalled,
            }
            | IntegrationState::ChangeFailed {
                actual_presence: IntegrationPresence::ActionInstalled,
                ..
            }
    )
}

const fn accepts_integration_toggles(integration_state: &IntegrationState) -> bool {
    !matches!(
        integration_state,
        IntegrationState::ChangingIntegration { .. }
    )
}

fn describe_integration_failure(integration_state: &IntegrationState) -> String {
    match integration_state {
        IntegrationState::IntegrationInstalled
        | IntegrationState::IntegrationAbsent
        | IntegrationState::ChangingIntegration { .. } => String::new(),
        IntegrationState::ChangeFailed { change_failure, .. } => match change_failure {
            IntegrationChangeFailure::LauncherNotFound(launcher_failure) => {
                gettext("Lazaret could not find its own launcher: {error}")
                    .replace("{error}", &launcher_failure.to_string())
            }
            IntegrationChangeFailure::ActionUnwritable(write_failure) => {
                gettext("The file manager action could not be added: {error}")
                    .replace("{error}", &write_failure.to_string())
            }
            IntegrationChangeFailure::ActionUnremovable(remove_failure) => {
                gettext("The file manager action could not be removed: {error}")
                    .replace("{error}", &remove_failure.to_string())
            }
        },
    }
}

fn install_integration(
    file_manager: FileManagerKind,
    data_directory: &Path,
) -> Result<(), IntegrationChangeFailure> {
    let launcher_path =
        current_launcher_path().map_err(IntegrationChangeFailure::LauncherNotFound)?;
    install_file_manager_action(file_manager, data_directory, &launcher_path)
        .map_err(IntegrationChangeFailure::ActionUnwritable)
}

fn remove_integration(
    file_manager: FileManagerKind,
    data_directory: &Path,
) -> Result<(), IntegrationChangeFailure> {
    remove_file_manager_action(file_manager, data_directory)
        .map_err(IntegrationChangeFailure::ActionUnremovable)
}

fn finished_integration_change(
    file_manager: FileManagerKind,
    data_directory: &Path,
    target_presence: IntegrationPresence,
    change_attempt: Result<(), IntegrationChangeFailure>,
) -> IntegrationChangeOutcome {
    match change_attempt {
        Ok(()) => IntegrationChangeOutcome::ChangeSucceeded { target_presence },
        Err(change_failure) => IntegrationChangeOutcome::ChangeRefused {
            actual_presence: read_integration_presence(file_manager, data_directory),
            change_failure,
        },
    }
}

impl FileManagerRow {
    fn start_integration_change(
        &mut self,
        target_presence: IntegrationPresence,
        sender: &FactorySender<Self>,
    ) {
        if !accepts_integration_toggles(&self.integration_state) {
            return;
        }
        self.integration_state = IntegrationState::ChangingIntegration { target_presence };
        let file_manager = self.file_manager;
        let data_directory = self.data_directory.clone();
        sender.oneshot_command(async move {
            let change_attempt = match target_presence {
                IntegrationPresence::ActionInstalled => {
                    install_integration(file_manager, &data_directory)
                }
                IntegrationPresence::ActionAbsent => {
                    remove_integration(file_manager, &data_directory)
                }
            };
            FileManagerRowCommand::IntegrationChangeFinished(finished_integration_change(
                file_manager,
                &data_directory,
                target_presence,
                change_attempt,
            ))
        });
    }
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
            set_sensitive: accepts_integration_toggles(&self.integration_state),
            #[watch]
            #[block_signal(integration_toggled_handler)]
            set_active: switch_shows_installed(&self.integration_state),
            #[watch]
            set_subtitle: &describe_integration_failure(&self.integration_state),
            connect_active_notify[sender] => move |changed_row| {
                sender.input(if changed_row.is_active() {
                    FileManagerRowInput::InstallRequested
                } else {
                    FileManagerRowInput::RemovalRequested
                });
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
            integration_state: settled_integration(read_integration_presence(
                file_manager,
                &data_directory,
            )),
            file_manager,
            data_directory,
        }
    }

    fn update(&mut self, row_input: Self::Input, sender: FactorySender<Self>) {
        match row_input {
            FileManagerRowInput::InstallRequested => {
                self.start_integration_change(IntegrationPresence::ActionInstalled, &sender);
            }
            FileManagerRowInput::RemovalRequested => {
                self.start_integration_change(IntegrationPresence::ActionAbsent, &sender);
            }
        }
    }

    fn update_cmd(&mut self, row_command: Self::CommandOutput, _sender: FactorySender<Self>) {
        match row_command {
            FileManagerRowCommand::IntegrationChangeFinished(change_outcome) => {
                self.integration_state = integration_after_change(change_outcome);
            }
        }
    }
}

#[cfg(test)]
mod file_manager_row_tests {
    use super::*;

    #[test]
    fn a_failed_install_leaves_the_switch_showing_not_installed() {
        let integration_state = integration_after_change(IntegrationChangeOutcome::ChangeRefused {
            actual_presence: IntegrationPresence::ActionAbsent,
            change_failure: IntegrationChangeFailure::ActionUnwritable(io::Error::from(
                io::ErrorKind::PermissionDenied,
            )),
        });
        assert!(!switch_shows_installed(&integration_state));
        assert!(accepts_integration_toggles(&integration_state));
    }

    #[test]
    fn a_failed_removal_leaves_the_switch_showing_installed() {
        let integration_state = integration_after_change(IntegrationChangeOutcome::ChangeRefused {
            actual_presence: IntegrationPresence::ActionInstalled,
            change_failure: IntegrationChangeFailure::ActionUnremovable(io::Error::from(
                io::ErrorKind::PermissionDenied,
            )),
        });
        assert!(switch_shows_installed(&integration_state));
    }

    #[test]
    fn a_running_change_refuses_further_toggles() {
        let integration_state = IntegrationState::ChangingIntegration {
            target_presence: IntegrationPresence::ActionInstalled,
        };
        assert!(!accepts_integration_toggles(&integration_state));
        assert!(switch_shows_installed(&integration_state));
    }

    #[test]
    fn a_failed_install_through_the_filesystem_reports_what_is_really_there() {
        let data_root = tempfile::tempdir().expect("data root");
        let blocking_file = data_root.path().join("nautilus");
        std::fs::write(&blocking_file, b"").expect("blocking file");
        let data_directory = data_root.path().to_path_buf();
        let change_attempt = install_file_manager_action(
            FileManagerKind::Nautilus,
            &data_directory,
            std::path::Path::new("/usr/bin/lazaret"),
        )
        .map_err(IntegrationChangeFailure::ActionUnwritable);
        let integration_state = integration_after_change(finished_integration_change(
            FileManagerKind::Nautilus,
            &data_directory,
            IntegrationPresence::ActionInstalled,
            change_attempt,
        ));
        assert!(matches!(
            integration_state,
            IntegrationState::ChangeFailed {
                actual_presence: IntegrationPresence::ActionAbsent,
                ..
            }
        ));
        assert!(!switch_shows_installed(&integration_state));
    }
}

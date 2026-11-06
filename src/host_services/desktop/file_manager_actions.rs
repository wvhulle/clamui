use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

const EXECUTABLE_FILE_MODE: u32 = 0o755;
const LAUNCHER_PLACEHOLDER: &str = "@LAUNCHER@";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileManagerKind {
    Nautilus,
    Nemo,
    Dolphin,
}

pub const SUPPORTED_FILE_MANAGERS: [FileManagerKind; 3] = [
    FileManagerKind::Nautilus,
    FileManagerKind::Nemo,
    FileManagerKind::Dolphin,
];

impl FileManagerKind {
    pub const fn displayed_name(self) -> &'static str {
        match self {
            Self::Nautilus => "Files (Nautilus)",
            Self::Nemo => "Nemo",
            Self::Dolphin => "Dolphin",
        }
    }

    const fn action_template(self) -> &'static str {
        match self {
            Self::Nautilus => {
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/data/file-manager-actions/nautilus-scan-script.in"
                ))
            }
            Self::Nemo => include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/data/file-manager-actions/nemo-scan.nemo_action.in"
            )),
            Self::Dolphin => {
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/data/file-manager-actions/dolphin-scan.desktop.in"
                ))
            }
        }
    }

    const fn relative_action_path(self) -> &'static str {
        match self {
            Self::Nautilus => "nautilus/scripts/Scan with Lazaret",
            Self::Nemo => "nemo/actions/page.codeberg.wvhulle.Lazaret.nemo_action",
            Self::Dolphin => "kio/servicemenus/page.codeberg.wvhulle.Lazaret.desktop",
        }
    }

    fn action_path(self, data_directory: &Path) -> PathBuf {
        data_directory.join(self.relative_action_path())
    }
}

fn double_quoted_body(launcher_path: &Path) -> String {
    launcher_path.to_string_lossy().chars().fold(
        String::new(),
        |mut escaped_path, path_character| {
            if matches!(path_character, '"' | '`' | '$' | '\\') {
                escaped_path.push('\\');
            }
            escaped_path.push(path_character);
            escaped_path
        },
    )
}

pub fn file_manager_action_text(file_manager: FileManagerKind, launcher_path: &Path) -> String {
    file_manager
        .action_template()
        .replace(LAUNCHER_PLACEHOLDER, &double_quoted_body(launcher_path))
}

pub fn file_manager_action_installed(file_manager: FileManagerKind, data_directory: &Path) -> bool {
    file_manager.action_path(data_directory).is_file()
}

pub fn install_file_manager_action(
    file_manager: FileManagerKind,
    data_directory: &Path,
    launcher_path: &Path,
) -> io::Result<()> {
    let action_path = file_manager.action_path(data_directory);
    if let Some(action_directory) = action_path.parent() {
        fs::create_dir_all(action_directory)?;
    }
    fs::write(
        &action_path,
        file_manager_action_text(file_manager, launcher_path),
    )?;
    fs::set_permissions(
        &action_path,
        fs::Permissions::from_mode(EXECUTABLE_FILE_MODE),
    )
}

pub fn remove_file_manager_action(
    file_manager: FileManagerKind,
    data_directory: &Path,
) -> io::Result<()> {
    match fs::remove_file(file_manager.action_path(data_directory)) {
        Err(remove_failure) if remove_failure.kind() != io::ErrorKind::NotFound => {
            Err(remove_failure)
        }
        _removed_or_absent => Ok(()),
    }
}

#[cfg(test)]
mod file_manager_actions_tests {
    use super::*;

    #[test]
    fn installing_and_removing_only_touches_the_action_file() {
        let data_root = tempfile::tempdir().expect("data root");
        let launcher_path = Path::new("/usr/bin/lazaret");
        SUPPORTED_FILE_MANAGERS.iter().for_each(|file_manager| {
            assert!(!file_manager_action_installed(
                *file_manager,
                data_root.path()
            ));
            install_file_manager_action(*file_manager, data_root.path(), launcher_path)
                .expect("installed action");
            assert!(file_manager_action_installed(
                *file_manager,
                data_root.path()
            ));
            let action_path = file_manager.action_path(data_root.path());
            assert!(
                fs::read_to_string(&action_path)
                    .expect("action text")
                    .contains("\"/usr/bin/lazaret\"")
            );
            assert_eq!(
                fs::metadata(&action_path)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
            remove_file_manager_action(*file_manager, data_root.path()).expect("removed action");
            assert!(!file_manager_action_installed(
                *file_manager,
                data_root.path()
            ));
            remove_file_manager_action(*file_manager, data_root.path())
                .expect("removing twice is harmless");
        });
    }

    #[test]
    fn launcher_paths_cannot_escape_their_quotes() {
        let action_text = file_manager_action_text(
            FileManagerKind::Nautilus,
            Path::new("/opt/a\"$(touch x)`b`\\/lazaret"),
        );
        assert!(action_text.contains("exec \"/opt/a\\\"\\$(touch x)\\`b\\`\\\\/lazaret\" \"$@\""));
    }
}

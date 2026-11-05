use std::{
    fs, io,
    io::Write,
    path::{Path, PathBuf},
};

use gettextrs::gettext;
use serde::{Deserialize, Serialize};

use crate::application_settings::scan_exclusion_rules::ExclusionEntry;

const STORAGE_VERSION: u64 = 1;
const MAXIMUM_NAME_LENGTH: usize = 50;

#[derive(Debug, thiserror::Error)]
pub enum ProfileStoreFailure {
    #[error("the profile file could not be accessed: {0}")]
    ProfileFileUnavailable(#[from] io::Error),
    #[error("the profile data is not valid: {0}")]
    ProfileDataInvalid(#[from] serde_json::Error),
    #[error("the profile file could not be replaced: {0}")]
    ProfileFileNotReplaced(#[from] tempfile::PersistError),
    #[error("a profile name is required")]
    ProfileNameMissing,
    #[error("the profile name is too long")]
    ProfileNameTooLong,
    #[error("another profile already uses this name")]
    ProfileNameTaken,
    #[error("default profiles cannot be deleted")]
    BuiltinProfileProtected,
    #[error("the profile needs at least one target")]
    ProfileTargetsMissing,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanProfile {
    #[serde(rename = "id", default)]
    pub profile_id: String,
    #[serde(rename = "name")]
    pub profile_name: String,
    #[serde(rename = "description", default)]
    pub profile_description: String,
    #[serde(rename = "targets", default)]
    pub scan_targets: Vec<String>,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
    #[serde(default)]
    pub excluded_patterns: Vec<String>,
    #[serde(rename = "is_default", default)]
    pub is_builtin: bool,
}

impl ScanProfile {
    pub fn displayed_name(&self) -> String {
        match self.profile_id.as_str() {
            "builtin-quick-scan" => gettext("Quick Scan"),
            "builtin-full-scan" => gettext("Full Scan"),
            "builtin-home-folder" => gettext("Home Folder"),
            _custom_profile => self.profile_name.clone(),
        }
    }

    pub fn displayed_description(&self) -> String {
        match self.profile_id.as_str() {
            "builtin-quick-scan" => {
                gettext("Fast scan of the Downloads folder for quick threat detection")
            }
            "builtin-full-scan" => {
                gettext("Comprehensive system-wide scan of all accessible directories")
            }
            "builtin-home-folder" => {
                gettext("Scan of the user's home directory and personal files")
            }
            _custom_profile => self.profile_description.clone(),
        }
    }

    pub fn exclusion_entries(&self) -> Vec<ExclusionEntry> {
        self.excluded_paths
            .iter()
            .chain(&self.excluded_patterns)
            .cloned()
            .map(ExclusionEntry::enabled_pattern)
            .collect()
    }

    pub fn expanded_targets(&self, home_directory: &Path) -> Vec<PathBuf> {
        self.scan_targets
            .iter()
            .map(|scan_target| expanded_profile_target(scan_target, home_directory))
            .collect()
    }
}

fn expanded_profile_target(scan_target: &str, home_directory: &Path) -> PathBuf {
    if scan_target == "~" {
        home_directory.to_path_buf()
    } else if let Some(home_relative_target) = scan_target.strip_prefix("~/") {
        home_directory.join(home_relative_target)
    } else {
        PathBuf::from(scan_target)
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct StoredProfiles {
    version: u64,
    profiles: Vec<ScanProfile>,
}

const HOME_CACHE_EXCLUSIONS: [&str; 13] = [
    "~/.cache",
    "~/.local/share/Trash",
    "~/.rustup",
    "~/.cargo/registry",
    "~/.cargo/git",
    "~/.npm",
    "~/.local/share/pnpm/store",
    "~/.yarn/berry/cache",
    "~/go/pkg/mod",
    "~/.gradle/caches",
    "~/.m2/repository",
    "~/.local/share/containers/storage",
    "~/.local/share/flatpak/repo",
];

fn string_list(listed_values: &[&str]) -> Vec<String> {
    listed_values
        .iter()
        .map(|listed_value| (*listed_value).to_owned())
        .collect()
}

pub fn builtin_profiles(downloads_directory: &str) -> [ScanProfile; 3] {
    [
        ScanProfile {
            profile_id: "builtin-quick-scan".to_owned(),
            profile_name: "Quick Scan".to_owned(),
            profile_description: "Fast scan of the Downloads folder for quick threat detection"
                .to_owned(),
            scan_targets: vec![downloads_directory.to_owned()],
            excluded_paths: Vec::new(),
            excluded_patterns: Vec::new(),
            is_builtin: true,
        },
        ScanProfile {
            profile_id: "builtin-full-scan".to_owned(),
            profile_name: "Full Scan".to_owned(),
            profile_description: "Comprehensive system-wide scan of all accessible directories"
                .to_owned(),
            scan_targets: string_list(&["/"]),
            excluded_paths: string_list(&[
                "/proc",
                "/sys",
                "/dev",
                "/run",
                "/tmp",
                "/var/cache",
                "/var/tmp",
            ]),
            excluded_patterns: Vec::new(),
            is_builtin: true,
        },
        ScanProfile {
            profile_id: "builtin-home-folder".to_owned(),
            profile_name: "Home Folder".to_owned(),
            profile_description: "Scan of the user's home directory and personal files".to_owned(),
            scan_targets: string_list(&["~"]),
            excluded_paths: string_list(&HOME_CACHE_EXCLUSIONS),
            excluded_patterns: Vec::new(),
            is_builtin: true,
        },
    ]
}

fn normalized_profile(
    mut candidate_profile: ScanProfile,
) -> Result<ScanProfile, ProfileStoreFailure> {
    candidate_profile.profile_name = candidate_profile.profile_name.trim().to_owned();
    if candidate_profile.profile_name.is_empty() {
        return Err(ProfileStoreFailure::ProfileNameMissing);
    }
    if candidate_profile.profile_name.chars().count() > MAXIMUM_NAME_LENGTH {
        return Err(ProfileStoreFailure::ProfileNameTooLong);
    }
    if candidate_profile.scan_targets.is_empty() {
        return Err(ProfileStoreFailure::ProfileTargetsMissing);
    }
    Ok(candidate_profile)
}

#[derive(Clone, Debug)]
pub struct ScanProfileStore {
    store_path: PathBuf,
    downloads_directory: String,
}

impl ScanProfileStore {
    pub fn at_path(store_path: PathBuf, downloads_directory: String) -> Self {
        Self {
            store_path,
            downloads_directory,
        }
    }

    fn read_stored_profiles(&self) -> Result<Vec<ScanProfile>, ProfileStoreFailure> {
        match fs::read(&self.store_path) {
            Ok(stored_bytes) => {
                Ok(serde_json::from_slice::<StoredProfiles>(&stored_bytes)?.profiles)
            }
            Err(read_failure) if read_failure.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(read_failure) => Err(read_failure.into()),
        }
    }

    fn write_profiles(&self, profiles: Vec<ScanProfile>) -> Result<(), ProfileStoreFailure> {
        let store_directory = self.store_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(store_directory)?;
        let mut replacement_file = tempfile::NamedTempFile::new_in(store_directory)?;
        replacement_file.write_all(&serde_json::to_vec_pretty(&StoredProfiles {
            version: STORAGE_VERSION,
            profiles,
        })?)?;
        replacement_file.as_file().sync_all()?;
        replacement_file.persist(&self.store_path)?;
        Ok(())
    }

    pub fn load_profiles(&self) -> Result<Vec<ScanProfile>, ProfileStoreFailure> {
        let stored_profiles = self.read_stored_profiles()?;
        let missing_builtins = builtin_profiles(&self.downloads_directory)
            .into_iter()
            .filter(|builtin_profile| {
                !stored_profiles
                    .iter()
                    .any(|stored_profile| stored_profile.profile_id == builtin_profile.profile_id)
            });
        let mut loaded_profiles = stored_profiles
            .iter()
            .cloned()
            .chain(missing_builtins)
            .collect::<Vec<_>>();
        loaded_profiles.sort_by_key(|loaded_profile| {
            (
                loaded_profile.is_builtin,
                loaded_profile.profile_name.to_lowercase(),
            )
        });
        Ok(loaded_profiles)
    }

    pub fn save_profile(
        &self,
        saved_profile: ScanProfile,
    ) -> Result<ScanProfile, ProfileStoreFailure> {
        let mut saved_profile = normalized_profile(saved_profile)?;
        if saved_profile.profile_id.is_empty() {
            saved_profile.profile_id = relm4::gtk::glib::uuid_string_random().to_string();
        }
        let loaded_profiles = self.load_profiles()?;
        if loaded_profiles.iter().any(|loaded_profile| {
            loaded_profile.profile_id != saved_profile.profile_id
                && loaded_profile
                    .profile_name
                    .eq_ignore_ascii_case(&saved_profile.profile_name)
        }) {
            return Err(ProfileStoreFailure::ProfileNameTaken);
        }
        let retained_profiles = loaded_profiles
            .into_iter()
            .filter(|loaded_profile| loaded_profile.profile_id != saved_profile.profile_id);
        self.write_profiles(
            retained_profiles
                .chain(std::iter::once(saved_profile.clone()))
                .collect(),
        )?;
        Ok(saved_profile)
    }

    pub fn delete_profile(&self, deleted_id: &str) -> Result<(), ProfileStoreFailure> {
        let loaded_profiles = self.load_profiles()?;
        if loaded_profiles.iter().any(|loaded_profile| {
            loaded_profile.profile_id == deleted_id && loaded_profile.is_builtin
        }) {
            return Err(ProfileStoreFailure::BuiltinProfileProtected);
        }
        self.write_profiles(
            loaded_profiles
                .into_iter()
                .filter(|loaded_profile| loaded_profile.profile_id != deleted_id)
                .collect(),
        )
    }

    pub fn restore_builtin_profiles(&self) -> Result<(), ProfileStoreFailure> {
        let custom_profiles = self
            .read_stored_profiles()?
            .into_iter()
            .filter(|stored_profile| !stored_profile.is_builtin)
            .collect();
        self.write_profiles(custom_profiles)
    }

    pub fn import_profile(&self, imported_json: &[u8]) -> Result<ScanProfile, ProfileStoreFailure> {
        let imported_profile = serde_json::from_slice::<ScanProfile>(imported_json)?;
        self.save_profile(ScanProfile {
            profile_id: String::new(),
            is_builtin: false,
            ..imported_profile
        })
    }
}

pub fn exported_profile_json(
    exported_profile: &ScanProfile,
) -> Result<String, ProfileStoreFailure> {
    Ok(serde_json::to_string_pretty(exported_profile)?)
}

#[cfg(test)]
mod scan_profile_store_tests {
    use super::*;

    fn temporary_store(temporary_root: &tempfile::TempDir) -> ScanProfileStore {
        ScanProfileStore::at_path(
            temporary_root.path().join("config/profiles.json"),
            "/home/user/Downloads".to_owned(),
        )
    }

    fn custom_profile(profile_name: &str) -> ScanProfile {
        ScanProfile {
            profile_name: profile_name.to_owned(),
            scan_targets: vec!["/scan".to_owned()],
            ..ScanProfile::default()
        }
    }

    #[test]
    fn defaults_exist_without_a_file_and_custom_profiles_sort_first() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let profile_store = temporary_store(&temporary_root);
        assert_eq!(profile_store.load_profiles().expect("defaults").len(), 3);
        profile_store
            .save_profile(custom_profile("Mine"))
            .expect("saved");
        let loaded_profiles = profile_store.load_profiles().expect("loaded");
        assert_eq!(loaded_profiles.len(), 4);
        assert_eq!(loaded_profiles[0].profile_name, "Mine");
        assert!(!loaded_profiles[0].profile_id.is_empty());
    }

    #[test]
    fn invalid_profiles_are_rejected() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let profile_store = temporary_store(&temporary_root);
        assert!(matches!(
            profile_store.save_profile(custom_profile("   ")),
            Err(ProfileStoreFailure::ProfileNameMissing)
        ));
        assert!(matches!(
            profile_store.save_profile(custom_profile(&"x".repeat(51))),
            Err(ProfileStoreFailure::ProfileNameTooLong)
        ));
        assert!(matches!(
            profile_store.save_profile(custom_profile("quick scan")),
            Err(ProfileStoreFailure::ProfileNameTaken)
        ));
        assert!(matches!(
            profile_store.save_profile(ScanProfile {
                scan_targets: Vec::new(),
                ..custom_profile("No targets")
            }),
            Err(ProfileStoreFailure::ProfileTargetsMissing)
        ));
    }

    #[test]
    fn home_folder_scan_skips_package_caches_but_keeps_project_folders() {
        let home_directory = Path::new("/home/user");
        let home_profile = builtin_profiles("/home/user/Downloads")
            .into_iter()
            .find(|builtin_profile| builtin_profile.profile_id == "builtin-home-folder")
            .expect("home folder profile");
        let home_exclusions =
            crate::application_settings::scan_exclusion_rules::ScanExclusions::from_entries(
                &home_profile.exclusion_entries(),
                home_directory,
            );
        [
            "/home/user/.rustup/toolchains/nightly",
            "/home/user/.cargo/registry/src",
            "/home/user/.cache/mozilla",
            "/home/user/go/pkg/mod/github.com",
        ]
        .into_iter()
        .for_each(|cache_directory| {
            assert!(
                home_exclusions.excludes_directory(Path::new(cache_directory)),
                "{cache_directory}"
            );
        });
        [
            "/home/user/Downloads",
            "/home/user/.cargo/bin",
            "/home/user/Code/project",
            "/home/user/.local/share/applications",
        ]
        .into_iter()
        .for_each(|kept_directory| {
            assert!(
                !home_exclusions.excludes_directory(Path::new(kept_directory)),
                "{kept_directory}"
            );
        });
    }

    #[test]
    fn builtin_profiles_cannot_be_deleted_but_can_be_restored() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let profile_store = temporary_store(&temporary_root);
        assert!(matches!(
            profile_store.delete_profile("builtin-full-scan"),
            Err(ProfileStoreFailure::BuiltinProfileProtected)
        ));
        let edited_builtin = profile_store
            .load_profiles()
            .expect("loaded")
            .into_iter()
            .find(|loaded_profile| loaded_profile.profile_id == "builtin-quick-scan")
            .expect("quick scan");
        profile_store
            .save_profile(ScanProfile {
                scan_targets: vec!["/edited".to_owned()],
                ..edited_builtin
            })
            .expect("edited");
        profile_store
            .save_profile(custom_profile("Kept"))
            .expect("custom");
        profile_store.restore_builtin_profiles().expect("restored");
        let restored_profiles = profile_store.load_profiles().expect("loaded");
        assert!(
            restored_profiles
                .iter()
                .any(|restored_profile| restored_profile.profile_name == "Kept")
        );
        assert_eq!(
            restored_profiles
                .iter()
                .find(|restored_profile| restored_profile.profile_id == "builtin-quick-scan")
                .expect("quick scan")
                .scan_targets,
            vec!["/home/user/Downloads".to_owned()]
        );
    }

    #[test]
    fn exported_profiles_import_as_new_custom_profiles() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let profile_store = temporary_store(&temporary_root);
        let exported_json = exported_profile_json(&ScanProfile {
            profile_id: "builtin-quick-scan".to_owned(),
            is_builtin: true,
            ..custom_profile("Shared")
        })
        .expect("exported");
        let imported_profile = profile_store
            .import_profile(exported_json.as_bytes())
            .expect("imported");
        assert!(!imported_profile.is_builtin);
        assert_ne!(imported_profile.profile_id, "builtin-quick-scan");
        assert!(matches!(
            profile_store.import_profile(b"not json"),
            Err(ProfileStoreFailure::ProfileDataInvalid(_))
        ));
    }

    #[test]
    fn targets_expand_the_home_directory() {
        let expanded_targets = ScanProfile {
            scan_targets: vec!["~".to_owned(), "~/Videos".to_owned(), "/opt".to_owned()],
            ..ScanProfile::default()
        }
        .expanded_targets(Path::new("/home/user"));
        assert_eq!(
            expanded_targets,
            vec![
                PathBuf::from("/home/user"),
                PathBuf::from("/home/user/Videos"),
                PathBuf::from("/opt")
            ]
        );
    }
}

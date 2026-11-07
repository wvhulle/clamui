use std::{
    fs, io,
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::host_services::clamav_scanner::scan_exclusion_rules::ExclusionEntry;

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
    #[error("the profile task was interrupted: {0}")]
    ProfileTaskInterrupted(#[from] tokio::task::JoinError),
    #[error("a profile name is required")]
    ProfileNameMissing,
    #[error("the profile name is too long")]
    ProfileNameTooLong,
    #[error("another profile already uses this name")]
    ProfileNameTaken,
    #[error("the profile needs at least one target")]
    ProfileTargetsMissing,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProfileId(String);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BuiltinProfile {
    QuickScan,
    FullScan,
    HomeFolder,
}

impl BuiltinProfile {
    pub const ALL_BUILTINS: [Self; 3] = [Self::QuickScan, Self::FullScan, Self::HomeFolder];

    const fn stored_id(self) -> &'static str {
        match self {
            Self::QuickScan => "builtin-quick-scan",
            Self::FullScan => "builtin-full-scan",
            Self::HomeFolder => "builtin-home-folder",
        }
    }

    fn from_stored_id(stored_id: &str) -> Option<Self> {
        Self::ALL_BUILTINS
            .into_iter()
            .find(|builtin_profile| builtin_profile.stored_id() == stored_id)
    }

    const fn canonical_name(self) -> &'static str {
        match self {
            Self::QuickScan => "Quick Scan",
            Self::FullScan => "Full Scan",
            Self::HomeFolder => "Home Folder",
        }
    }

    const fn canonical_description(self) -> &'static str {
        match self {
            Self::QuickScan => "Fast scan of the Downloads folder for quick threat detection",
            Self::FullScan => "Comprehensive system-wide scan of all accessible directories",
            Self::HomeFolder => "Scan of the user's home directory and personal files",
        }
    }

    fn with_canonical_naming(self, profile_draft: ProfileDraft) -> ProfileDraft {
        ProfileDraft {
            profile_name: self.canonical_name().to_owned(),
            profile_description: self.canonical_description().to_owned(),
            ..profile_draft
        }
    }

    fn default_draft(self, downloads_directory: &str) -> ProfileDraft {
        let default_scope = match self {
            Self::QuickScan => ProfileDraft {
                scan_targets: vec![downloads_directory.to_owned()],
                ..ProfileDraft::default()
            },
            Self::FullScan => ProfileDraft {
                scan_targets: string_list(&["/"]),
                excluded_patterns: string_list(&[
                    "/proc",
                    "/sys",
                    "/dev",
                    "/run",
                    "/tmp",
                    "/var/cache",
                    "/var/tmp",
                ]),
                ..ProfileDraft::default()
            },
            Self::HomeFolder => ProfileDraft {
                scan_targets: string_list(&["~"]),
                excluded_patterns: string_list(&HOME_CACHE_EXCLUSIONS),
                ..ProfileDraft::default()
            },
        };
        self.with_canonical_naming(default_scope)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ProfileOrigin {
    Builtin(BuiltinProfile),
    Custom { profile_id: ProfileId },
}

impl ProfileOrigin {
    fn from_stored_id(stored_id: String, profile_name: &str) -> Self {
        match BuiltinProfile::from_stored_id(&stored_id) {
            Some(builtin_profile) => Self::Builtin(builtin_profile),
            None if stored_id.is_empty() => Self::Custom {
                profile_id: ProfileId(format!(
                    "legacy-profile-{}",
                    profile_name.trim().to_lowercase()
                )),
            },
            None => Self::Custom {
                profile_id: ProfileId(stored_id),
            },
        }
    }

    fn stored_id(&self) -> &str {
        match self {
            Self::Builtin(builtin_profile) => builtin_profile.stored_id(),
            Self::Custom { profile_id } => &profile_id.0,
        }
    }

    const fn is_builtin(&self) -> bool {
        match self {
            Self::Builtin(_builtin_profile) => true,
            Self::Custom { .. } => false,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProfileDraft {
    pub profile_name: String,
    pub profile_description: String,
    pub scan_targets: Vec<String>,
    pub excluded_patterns: Vec<String>,
}

impl ProfileDraft {
    pub fn exclusion_entries(&self) -> Vec<ExclusionEntry> {
        self.excluded_patterns
            .iter()
            .cloned()
            .map(ExclusionEntry::enabled_pattern)
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanProfile {
    pub profile_origin: ProfileOrigin,
    pub profile_draft: ProfileDraft,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditTarget {
    NewProfile,
    ExistingProfile(ProfileOrigin),
}

pub fn expanded_profile_targets(scan_targets: &[String], home_directory: &Path) -> Vec<PathBuf> {
    scan_targets
        .iter()
        .map(|scan_target| expanded_profile_target(scan_target, home_directory))
        .collect()
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
struct StoredScanProfile {
    #[serde(default)]
    id: String,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    excluded_paths: Vec<String>,
    #[serde(default)]
    excluded_patterns: Vec<String>,
    #[serde(default)]
    is_default: bool,
}

impl StoredScanProfile {
    fn into_draft(self) -> ProfileDraft {
        ProfileDraft {
            profile_name: self.name,
            profile_description: self.description,
            scan_targets: self.targets,
            excluded_patterns: self
                .excluded_paths
                .into_iter()
                .chain(self.excluded_patterns)
                .collect(),
        }
    }

    fn into_scan_profile(self) -> ScanProfile {
        let profile_origin = ProfileOrigin::from_stored_id(self.id.clone(), &self.name);
        let stored_draft = self.into_draft();
        let profile_draft = match &profile_origin {
            ProfileOrigin::Builtin(builtin_profile) => {
                builtin_profile.with_canonical_naming(stored_draft)
            }
            ProfileOrigin::Custom { .. } => stored_draft,
        };
        ScanProfile {
            profile_origin,
            profile_draft,
        }
    }

    fn from_scan_profile(scan_profile: &ScanProfile) -> Self {
        Self {
            id: scan_profile.profile_origin.stored_id().to_owned(),
            name: scan_profile.profile_draft.profile_name.clone(),
            description: scan_profile.profile_draft.profile_description.clone(),
            targets: scan_profile.profile_draft.scan_targets.clone(),
            excluded_paths: Vec::new(),
            excluded_patterns: scan_profile.profile_draft.excluded_patterns.clone(),
            is_default: scan_profile.profile_origin.is_builtin(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct StoredProfiles {
    version: u64,
    profiles: Vec<StoredScanProfile>,
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

pub fn builtin_scan_profile(
    builtin_profile: BuiltinProfile,
    downloads_directory: &str,
) -> ScanProfile {
    ScanProfile {
        profile_origin: ProfileOrigin::Builtin(builtin_profile),
        profile_draft: builtin_profile.default_draft(downloads_directory),
    }
}

fn normalized_draft(
    mut candidate_draft: ProfileDraft,
) -> Result<ProfileDraft, ProfileStoreFailure> {
    candidate_draft.profile_name = candidate_draft.profile_name.trim().to_owned();
    if candidate_draft.profile_name.is_empty() {
        return Err(ProfileStoreFailure::ProfileNameMissing);
    }
    if candidate_draft.profile_name.chars().count() > MAXIMUM_NAME_LENGTH {
        return Err(ProfileStoreFailure::ProfileNameTooLong);
    }
    if candidate_draft.scan_targets.is_empty() {
        return Err(ProfileStoreFailure::ProfileTargetsMissing);
    }
    Ok(candidate_draft)
}

pub async fn run_blocking_profile_task<TaskOutput: Send + 'static>(
    profile_task: impl FnOnce() -> Result<TaskOutput, ProfileStoreFailure> + Send + 'static,
) -> Result<TaskOutput, ProfileStoreFailure> {
    tokio::task::spawn_blocking(profile_task).await?
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
            Ok(stored_bytes) => Ok(serde_json::from_slice::<StoredProfiles>(&stored_bytes)?
                .profiles
                .into_iter()
                .map(StoredScanProfile::into_scan_profile)
                .collect()),
            Err(read_failure) if read_failure.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(read_failure) => Err(read_failure.into()),
        }
    }

    fn write_profiles(&self, profiles: &[ScanProfile]) -> Result<(), ProfileStoreFailure> {
        let store_directory = self.store_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(store_directory)?;
        let mut replacement_file = tempfile::NamedTempFile::new_in(store_directory)?;
        replacement_file.write_all(&serde_json::to_vec_pretty(&StoredProfiles {
            version: STORAGE_VERSION,
            profiles: profiles
                .iter()
                .map(StoredScanProfile::from_scan_profile)
                .collect(),
        })?)?;
        replacement_file.as_file().sync_all()?;
        replacement_file.persist(&self.store_path)?;
        Ok(())
    }

    pub fn load_profiles(&self) -> Result<Vec<ScanProfile>, ProfileStoreFailure> {
        let stored_profiles = self.read_stored_profiles()?;
        let missing_builtins = BuiltinProfile::ALL_BUILTINS
            .into_iter()
            .filter(|builtin_profile| {
                !stored_profiles.iter().any(|stored_profile| {
                    stored_profile.profile_origin == ProfileOrigin::Builtin(*builtin_profile)
                })
            })
            .map(|builtin_profile| builtin_scan_profile(builtin_profile, &self.downloads_directory))
            .collect::<Vec<_>>();
        let mut loaded_profiles = stored_profiles
            .into_iter()
            .chain(missing_builtins)
            .collect::<Vec<_>>();
        loaded_profiles.sort_by_key(|loaded_profile| {
            (
                loaded_profile.profile_origin.is_builtin(),
                loaded_profile.profile_draft.profile_name.to_lowercase(),
            )
        });
        Ok(loaded_profiles)
    }

    pub fn save_profile(
        &self,
        edit_target: EditTarget,
        profile_draft: ProfileDraft,
    ) -> Result<ScanProfile, ProfileStoreFailure> {
        let saved_origin = match edit_target {
            EditTarget::NewProfile => ProfileOrigin::Custom {
                profile_id: ProfileId(relm4::gtk::glib::uuid_string_random().to_string()),
            },
            EditTarget::ExistingProfile(profile_origin) => profile_origin,
        };
        let named_draft = match &saved_origin {
            ProfileOrigin::Builtin(builtin_profile) => {
                builtin_profile.with_canonical_naming(profile_draft)
            }
            ProfileOrigin::Custom { .. } => profile_draft,
        };
        let saved_profile = ScanProfile {
            profile_draft: normalized_draft(named_draft)?,
            profile_origin: saved_origin,
        };
        let loaded_profiles = self.load_profiles()?;
        if loaded_profiles.iter().any(|loaded_profile| {
            loaded_profile.profile_origin != saved_profile.profile_origin
                && loaded_profile
                    .profile_draft
                    .profile_name
                    .eq_ignore_ascii_case(&saved_profile.profile_draft.profile_name)
        }) {
            return Err(ProfileStoreFailure::ProfileNameTaken);
        }
        let written_profiles = loaded_profiles
            .into_iter()
            .filter(|loaded_profile| loaded_profile.profile_origin != saved_profile.profile_origin)
            .chain(std::iter::once(saved_profile.clone()))
            .collect::<Vec<_>>();
        self.write_profiles(&written_profiles)?;
        Ok(saved_profile)
    }

    pub fn delete_custom_profile(&self, deleted_id: &ProfileId) -> Result<(), ProfileStoreFailure> {
        let deleted_origin = ProfileOrigin::Custom {
            profile_id: deleted_id.clone(),
        };
        let retained_profiles = self
            .load_profiles()?
            .into_iter()
            .filter(|loaded_profile| loaded_profile.profile_origin != deleted_origin)
            .collect::<Vec<_>>();
        self.write_profiles(&retained_profiles)
    }

    pub fn restore_builtin_profiles(&self) -> Result<(), ProfileStoreFailure> {
        let custom_profiles = self
            .read_stored_profiles()?
            .into_iter()
            .filter(|stored_profile| !stored_profile.profile_origin.is_builtin())
            .collect::<Vec<_>>();
        self.write_profiles(&custom_profiles)
    }

    pub fn import_profile(&self, imported_json: &[u8]) -> Result<ScanProfile, ProfileStoreFailure> {
        let imported_profile = serde_json::from_slice::<StoredScanProfile>(imported_json)?;
        self.save_profile(EditTarget::NewProfile, imported_profile.into_draft())
    }
}

pub fn exported_profile_json(
    exported_profile: &ScanProfile,
) -> Result<String, ProfileStoreFailure> {
    Ok(serde_json::to_string_pretty(
        &StoredScanProfile::from_scan_profile(exported_profile),
    )?)
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

    fn custom_draft(profile_name: &str) -> ProfileDraft {
        ProfileDraft {
            profile_name: profile_name.to_owned(),
            scan_targets: vec!["/scan".to_owned()],
            ..ProfileDraft::default()
        }
    }

    fn profile_with_origin(
        loaded_profiles: &[ScanProfile],
        profile_origin: &ProfileOrigin,
    ) -> ScanProfile {
        loaded_profiles
            .iter()
            .find(|loaded_profile| loaded_profile.profile_origin == *profile_origin)
            .cloned()
            .expect("profile with origin")
    }

    #[test]
    fn defaults_exist_without_a_file_and_custom_profiles_sort_first() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let profile_store = temporary_store(&temporary_root);
        assert_eq!(profile_store.load_profiles().expect("defaults").len(), 3);
        profile_store
            .save_profile(EditTarget::NewProfile, custom_draft("Mine"))
            .expect("saved");
        let loaded_profiles = profile_store.load_profiles().expect("loaded");
        assert_eq!(loaded_profiles.len(), 4);
        assert_eq!(loaded_profiles[0].profile_draft.profile_name, "Mine");
        assert!(matches!(
            loaded_profiles[0].profile_origin,
            ProfileOrigin::Custom { .. }
        ));
    }

    #[test]
    fn new_profiles_are_stored_with_a_generated_custom_id() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let profile_store = temporary_store(&temporary_root);
        let first_profile = profile_store
            .save_profile(EditTarget::NewProfile, custom_draft("First"))
            .expect("first");
        let second_profile = profile_store
            .save_profile(EditTarget::NewProfile, custom_draft("Second"))
            .expect("second");
        assert_ne!(first_profile.profile_origin, second_profile.profile_origin);
        let stored_json = fs::read_to_string(temporary_root.path().join("config/profiles.json"))
            .expect("stored file");
        let stored_profiles =
            serde_json::from_str::<StoredProfiles>(&stored_json).expect("stored profiles");
        assert!(
            stored_profiles
                .profiles
                .iter()
                .all(|stored_profile| !stored_profile.id.is_empty())
        );
    }

    #[test]
    fn invalid_profiles_are_rejected() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let profile_store = temporary_store(&temporary_root);
        assert!(matches!(
            profile_store.save_profile(EditTarget::NewProfile, custom_draft("   ")),
            Err(ProfileStoreFailure::ProfileNameMissing)
        ));
        assert!(matches!(
            profile_store.save_profile(EditTarget::NewProfile, custom_draft(&"x".repeat(51))),
            Err(ProfileStoreFailure::ProfileNameTooLong)
        ));
        assert!(matches!(
            profile_store.save_profile(EditTarget::NewProfile, custom_draft("quick scan")),
            Err(ProfileStoreFailure::ProfileNameTaken)
        ));
        assert!(matches!(
            profile_store.save_profile(
                EditTarget::NewProfile,
                ProfileDraft {
                    scan_targets: Vec::new(),
                    ..custom_draft("No targets")
                }
            ),
            Err(ProfileStoreFailure::ProfileTargetsMissing)
        ));
    }

    #[test]
    fn home_folder_scan_skips_package_caches_but_keeps_project_folders() {
        let home_directory = Path::new("/home/user");
        let home_profile = builtin_scan_profile(BuiltinProfile::HomeFolder, "/home/user/Downloads");
        let home_exclusions =
            crate::host_services::clamav_scanner::scan_exclusion_rules::ScanExclusions::from_entries(
                &home_profile.profile_draft.exclusion_entries(),
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
    fn edited_builtin_profiles_can_be_restored_while_custom_profiles_stay() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let profile_store = temporary_store(&temporary_root);
        let quick_scan_origin = ProfileOrigin::Builtin(BuiltinProfile::QuickScan);
        let edited_builtin = profile_with_origin(
            &profile_store.load_profiles().expect("loaded"),
            &quick_scan_origin,
        );
        profile_store
            .save_profile(
                EditTarget::ExistingProfile(quick_scan_origin.clone()),
                ProfileDraft {
                    scan_targets: vec!["/edited".to_owned()],
                    ..edited_builtin.profile_draft
                },
            )
            .expect("edited");
        let kept_profile = profile_store
            .save_profile(EditTarget::NewProfile, custom_draft("Kept"))
            .expect("custom");
        profile_store.restore_builtin_profiles().expect("restored");
        let restored_profiles = profile_store.load_profiles().expect("loaded");
        assert_eq!(
            profile_with_origin(&restored_profiles, &kept_profile.profile_origin),
            kept_profile
        );
        assert_eq!(
            profile_with_origin(&restored_profiles, &quick_scan_origin)
                .profile_draft
                .scan_targets,
            vec!["/home/user/Downloads".to_owned()]
        );
    }

    #[test]
    fn renaming_a_builtin_profile_keeps_its_builtin_name() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let profile_store = temporary_store(&temporary_root);
        let quick_scan_origin = ProfileOrigin::Builtin(BuiltinProfile::QuickScan);
        let renamed_builtin = profile_store
            .save_profile(
                EditTarget::ExistingProfile(quick_scan_origin.clone()),
                ProfileDraft {
                    profile_name: "Downloads".to_owned(),
                    profile_description: "Renamed".to_owned(),
                    ..custom_draft("Downloads")
                },
            )
            .expect("saved");
        assert_eq!(renamed_builtin.profile_draft.profile_name, "Quick Scan");
        let loaded_profiles = profile_store.load_profiles().expect("loaded");
        assert_eq!(loaded_profiles.len(), 3);
        let loaded_builtin = profile_with_origin(&loaded_profiles, &quick_scan_origin);
        assert_eq!(loaded_builtin.profile_draft.profile_name, "Quick Scan");
        assert_eq!(
            loaded_builtin.profile_draft.profile_description,
            BuiltinProfile::QuickScan.canonical_description()
        );
        assert_eq!(
            loaded_builtin.profile_draft.scan_targets,
            vec!["/scan".to_owned()]
        );
    }

    #[test]
    fn old_stored_profiles_still_load() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let profile_store = temporary_store(&temporary_root);
        fs::create_dir_all(temporary_root.path().join("config")).expect("config directory");
        fs::write(
            temporary_root.path().join("config/profiles.json"),
            r#"{
                "version": 1,
                "profiles": [
                    {
                        "id": "builtin-quick-scan",
                        "name": "Downloads",
                        "description": "Renamed",
                        "targets": ["/old/downloads"],
                        "excluded_paths": [],
                        "excluded_patterns": [],
                        "is_default": true
                    },
                    {
                        "id": "4b0c-custom",
                        "name": "Projects",
                        "targets": ["~/Code"],
                        "excluded_paths": ["~/Code/target"],
                        "excluded_patterns": ["*.iso"],
                        "is_default": true
                    },
                    {
                        "name": "Without Id",
                        "targets": ["/srv"]
                    }
                ]
            }"#,
        )
        .expect("old file");
        let loaded_profiles = profile_store.load_profiles().expect("loaded");
        assert_eq!(loaded_profiles.len(), 5);
        let quick_scan = profile_with_origin(
            &loaded_profiles,
            &ProfileOrigin::Builtin(BuiltinProfile::QuickScan),
        );
        assert_eq!(quick_scan.profile_draft.profile_name, "Quick Scan");
        assert_eq!(
            quick_scan.profile_draft.scan_targets,
            vec!["/old/downloads".to_owned()]
        );
        let projects_profile = loaded_profiles
            .iter()
            .find(|loaded_profile| loaded_profile.profile_draft.profile_name == "Projects")
            .expect("projects");
        assert!(matches!(
            projects_profile.profile_origin,
            ProfileOrigin::Custom { .. }
        ));
        assert_eq!(
            projects_profile.profile_draft.excluded_patterns,
            vec!["~/Code/target".to_owned(), "*.iso".to_owned()]
        );
        let unnamed_origin = loaded_profiles
            .iter()
            .find(|loaded_profile| loaded_profile.profile_draft.profile_name == "Without Id")
            .map(|loaded_profile| loaded_profile.profile_origin.clone())
            .expect("profile without id");
        assert_eq!(
            profile_with_origin(
                &profile_store.load_profiles().expect("reloaded"),
                &unnamed_origin
            )
            .profile_draft
            .profile_name,
            "Without Id"
        );
    }

    #[test]
    fn exported_profiles_import_as_new_custom_profiles() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let profile_store = temporary_store(&temporary_root);
        let exported_json = exported_profile_json(&ScanProfile {
            profile_origin: ProfileOrigin::Builtin(BuiltinProfile::QuickScan),
            profile_draft: custom_draft("Shared"),
        })
        .expect("exported");
        let imported_profile = profile_store
            .import_profile(exported_json.as_bytes())
            .expect("imported");
        assert!(matches!(
            imported_profile.profile_origin,
            ProfileOrigin::Custom { .. }
        ));
        assert_eq!(imported_profile.profile_draft.profile_name, "Shared");
        assert!(matches!(
            profile_store.import_profile(b"not json"),
            Err(ProfileStoreFailure::ProfileDataInvalid(_))
        ));
    }

    #[test]
    fn targets_expand_the_home_directory() {
        let expanded_targets = expanded_profile_targets(
            &["~".to_owned(), "~/Videos".to_owned(), "/opt".to_owned()],
            Path::new("/home/user"),
        );
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

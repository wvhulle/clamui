use gettextrs::gettext;

use crate::scans::manual_scan_page::scan_profiles_dialog::scan_profile_store::{
    BuiltinProfile, ProfileOrigin, ProfileStoreFailure, ScanProfile,
};

pub fn builtin_profile_name(builtin_profile: BuiltinProfile) -> String {
    match builtin_profile {
        BuiltinProfile::QuickScan => gettext("Quick Scan"),
        BuiltinProfile::FullScan => gettext("Full Scan"),
        BuiltinProfile::HomeFolder => gettext("Home Folder"),
    }
}

pub fn builtin_profile_description(builtin_profile: BuiltinProfile) -> String {
    match builtin_profile {
        BuiltinProfile::QuickScan => {
            gettext("Fast scan of the Downloads folder for quick threat detection")
        }
        BuiltinProfile::FullScan => {
            gettext("Comprehensive system-wide scan of all accessible directories")
        }
        BuiltinProfile::HomeFolder => {
            gettext("Scan of the user's home directory and personal files")
        }
    }
}

pub fn displayed_profile_name(scan_profile: &ScanProfile) -> String {
    match scan_profile.profile_origin {
        ProfileOrigin::Builtin(builtin_profile) => builtin_profile_name(builtin_profile),
        ProfileOrigin::Custom { .. } => scan_profile.profile_draft.profile_name.clone(),
    }
}

pub fn displayed_profile_description(scan_profile: &ScanProfile) -> String {
    match scan_profile.profile_origin {
        ProfileOrigin::Builtin(builtin_profile) => builtin_profile_description(builtin_profile),
        ProfileOrigin::Custom { .. } => scan_profile.profile_draft.profile_description.clone(),
    }
}

pub fn describe_profile_store_failure(store_failure: &ProfileStoreFailure) -> String {
    match store_failure {
        ProfileStoreFailure::ProfileFileUnavailable(access_failure) => {
            gettext("The profile file could not be accessed: {error}")
                .replace("{error}", &access_failure.to_string())
        }
        ProfileStoreFailure::ProfileDataInvalid(parse_failure) => {
            gettext("The profile data is not valid: {error}")
                .replace("{error}", &parse_failure.to_string())
        }
        ProfileStoreFailure::ProfileFileNotReplaced(persist_failure) => {
            gettext("The profile file could not be replaced: {error}")
                .replace("{error}", &persist_failure.to_string())
        }
        ProfileStoreFailure::ProfileTaskInterrupted(interrupted_task) => {
            gettext("The profile task was interrupted: {error}")
                .replace("{error}", &interrupted_task.to_string())
        }
        ProfileStoreFailure::ProfileNameMissing => gettext("Profile name is required"),
        ProfileStoreFailure::ProfileNameTooLong => gettext("Name must be 50 characters or less"),
        ProfileStoreFailure::ProfileNameTaken => gettext("Another profile already uses this name"),
        ProfileStoreFailure::ProfileTargetsMissing => gettext("Add at least one target"),
    }
}

use relm4::gtk;

use crate::{
    host_services::clamav_scanner::scan_exclusion_rules::ExclusionEntry,
    scans::manual_scan_page::scan_profiles_dialog::scan_profile_store::{
        ProfileOrigin, ScanProfile,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectedScanProfile {
    ManualTargets,
    ProfileChosen { profile_origin: ProfileOrigin },
}

pub enum ProfileChoiceRow<'profiles> {
    ManualTargetsRow,
    StoredProfileRow(&'profiles ScanProfile),
}

impl ProfileChoiceRow<'_> {
    fn row_selection(&self) -> SelectedScanProfile {
        match self {
            Self::ManualTargetsRow => SelectedScanProfile::ManualTargets,
            Self::StoredProfileRow(stored_profile) => SelectedScanProfile::ProfileChosen {
                profile_origin: stored_profile.profile_origin.clone(),
            },
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum TargetRowsChange {
    KeepTargetRows,
    ClearTargetRows,
    ReplaceTargetRows { profile_targets: Vec<String> },
}

pub struct ScanProfileChoice {
    known_profiles: Vec<ScanProfile>,
    selected_profile: SelectedScanProfile,
}

impl ScanProfileChoice {
    pub const fn without_profiles() -> Self {
        Self {
            known_profiles: Vec::new(),
            selected_profile: SelectedScanProfile::ManualTargets,
        }
    }

    pub fn choice_rows(&self) -> Vec<ProfileChoiceRow<'_>> {
        std::iter::once(ProfileChoiceRow::ManualTargetsRow)
            .chain(
                self.known_profiles
                    .iter()
                    .map(ProfileChoiceRow::StoredProfileRow),
            )
            .collect()
    }

    pub fn selected_row_position(&self) -> u32 {
        self.choice_rows()
            .iter()
            .position(|choice_row| choice_row.row_selection() == self.selected_profile)
            .and_then(|row_position| u32::try_from(row_position).ok())
            .unwrap_or(gtk::INVALID_LIST_POSITION)
    }

    fn selected_scan_profile(&self) -> Option<&ScanProfile> {
        match &self.selected_profile {
            SelectedScanProfile::ManualTargets => None,
            SelectedScanProfile::ProfileChosen { profile_origin } => self
                .known_profiles
                .iter()
                .find(|known_profile| known_profile.profile_origin == *profile_origin),
        }
    }

    fn selected_profile_targets(&self) -> Option<Vec<String>> {
        self.selected_scan_profile()
            .map(|selected_profile| selected_profile.profile_draft.scan_targets.clone())
    }

    pub fn selected_exclusion_entries(&self) -> Vec<ExclusionEntry> {
        self.selected_scan_profile()
            .map(|selected_profile| selected_profile.profile_draft.exclusion_entries())
            .unwrap_or_default()
    }

    fn target_rows_for_selection(&self) -> TargetRowsChange {
        match self.selected_profile_targets() {
            Some(profile_targets) => TargetRowsChange::ReplaceTargetRows { profile_targets },
            None => TargetRowsChange::KeepTargetRows,
        }
    }

    pub fn choose_row(&mut self, row_position: usize) -> TargetRowsChange {
        let chosen_selection = self
            .choice_rows()
            .get(row_position)
            .map(ProfileChoiceRow::row_selection);
        match chosen_selection {
            None => TargetRowsChange::KeepTargetRows,
            Some(chosen_selection) if chosen_selection == self.selected_profile => {
                TargetRowsChange::KeepTargetRows
            }
            Some(chosen_selection) => {
                self.selected_profile = chosen_selection;
                self.target_rows_for_selection()
            }
        }
    }

    pub fn replace_known_profiles(
        &mut self,
        reloaded_profiles: Vec<ScanProfile>,
    ) -> TargetRowsChange {
        let previous_targets = self.selected_profile_targets();
        self.known_profiles = reloaded_profiles;
        if self.selected_profile == SelectedScanProfile::ManualTargets {
            return TargetRowsChange::KeepTargetRows;
        }
        match self.selected_profile_targets() {
            None => {
                self.selected_profile = SelectedScanProfile::ManualTargets;
                TargetRowsChange::ClearTargetRows
            }
            Some(reloaded_targets) if previous_targets.as_ref() == Some(&reloaded_targets) => {
                TargetRowsChange::KeepTargetRows
            }
            Some(profile_targets) => TargetRowsChange::ReplaceTargetRows { profile_targets },
        }
    }

    pub fn run_profile(&mut self, run_profile: ScanProfile) -> TargetRowsChange {
        let profile_targets = run_profile.profile_draft.scan_targets.clone();
        self.selected_profile = SelectedScanProfile::ProfileChosen {
            profile_origin: run_profile.profile_origin.clone(),
        };
        match self
            .known_profiles
            .iter_mut()
            .find(|known_profile| known_profile.profile_origin == run_profile.profile_origin)
        {
            Some(known_profile) => *known_profile = run_profile,
            None => self.known_profiles.push(run_profile),
        }
        TargetRowsChange::ReplaceTargetRows { profile_targets }
    }
}

#[cfg(test)]
mod scan_profile_choice_tests {
    use super::*;
    use crate::scans::manual_scan_page::scan_profiles_dialog::scan_profile_store::{
        BuiltinProfile, EditTarget, ProfileDraft, ScanProfileStore,
    };

    fn temporary_store(temporary_root: &tempfile::TempDir) -> ScanProfileStore {
        ScanProfileStore::at_path(
            temporary_root.path().join("profiles.json"),
            "/home/user/Downloads".to_owned(),
        )
    }

    fn custom_draft(profile_name: &str) -> ProfileDraft {
        ProfileDraft {
            profile_name: profile_name.to_owned(),
            scan_targets: vec!["/srv".to_owned()],
            excluded_patterns: vec!["/srv/cache".to_owned()],
            ..ProfileDraft::default()
        }
    }

    fn row_position_of(
        profile_choice: &ScanProfileChoice,
        wanted_selection: &SelectedScanProfile,
    ) -> usize {
        profile_choice
            .choice_rows()
            .iter()
            .position(|choice_row| choice_row.row_selection() == *wanted_selection)
            .expect("listed choice")
    }

    fn excluded_patterns(profile_choice: &ScanProfileChoice) -> Vec<String> {
        profile_choice
            .selected_exclusion_entries()
            .into_iter()
            .map(|exclusion_entry| exclusion_entry.exclusion_pattern)
            .collect()
    }

    #[test]
    fn reloading_profiles_keeps_the_selected_profile_and_its_exclusions() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let profile_store = temporary_store(&temporary_root);
        let mut profile_choice = ScanProfileChoice::without_profiles();
        profile_choice.replace_known_profiles(profile_store.load_profiles().expect("loaded"));
        let full_scan_selection = SelectedScanProfile::ProfileChosen {
            profile_origin: ProfileOrigin::Builtin(BuiltinProfile::FullScan),
        };
        let full_scan_row = row_position_of(&profile_choice, &full_scan_selection);
        assert_eq!(
            profile_choice.choose_row(full_scan_row),
            TargetRowsChange::ReplaceTargetRows {
                profile_targets: vec!["/".to_owned()]
            }
        );
        profile_store
            .save_profile(EditTarget::NewProfile, custom_draft("Another"))
            .expect("saved");
        assert_eq!(
            profile_choice.replace_known_profiles(profile_store.load_profiles().expect("reloaded")),
            TargetRowsChange::KeepTargetRows
        );
        assert_eq!(
            profile_choice.selected_row_position() as usize,
            full_scan_row + 1
        );
        assert!(excluded_patterns(&profile_choice).contains(&"/proc".to_owned()));
        assert!(excluded_patterns(&profile_choice).contains(&"/sys".to_owned()));
        assert!(excluded_patterns(&profile_choice).contains(&"/dev".to_owned()));
    }

    #[test]
    fn choosing_the_selected_row_again_keeps_the_target_rows() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let profile_store = temporary_store(&temporary_root);
        let mut profile_choice = ScanProfileChoice::without_profiles();
        profile_choice.replace_known_profiles(profile_store.load_profiles().expect("loaded"));
        let chosen_row = row_position_of(
            &profile_choice,
            &SelectedScanProfile::ProfileChosen {
                profile_origin: ProfileOrigin::Builtin(BuiltinProfile::HomeFolder),
            },
        );
        profile_choice.choose_row(chosen_row);
        assert_eq!(
            profile_choice.choose_row(chosen_row),
            TargetRowsChange::KeepTargetRows
        );
    }

    #[test]
    fn deleting_the_selected_profile_falls_back_to_manual_targets() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let profile_store = temporary_store(&temporary_root);
        let saved_profile = profile_store
            .save_profile(EditTarget::NewProfile, custom_draft("Server"))
            .expect("saved");
        let mut profile_choice = ScanProfileChoice::without_profiles();
        profile_choice.replace_known_profiles(profile_store.load_profiles().expect("loaded"));
        let server_row = row_position_of(
            &profile_choice,
            &SelectedScanProfile::ProfileChosen {
                profile_origin: saved_profile.profile_origin.clone(),
            },
        );
        profile_choice.choose_row(server_row);
        let ProfileOrigin::Custom { profile_id } = saved_profile.profile_origin else {
            panic!("saved profile is custom");
        };
        profile_store
            .delete_custom_profile(&profile_id)
            .expect("deleted");
        assert_eq!(
            profile_choice.replace_known_profiles(profile_store.load_profiles().expect("reloaded")),
            TargetRowsChange::ClearTargetRows
        );
        assert_eq!(profile_choice.selected_row_position(), 0);
        assert!(profile_choice.selected_exclusion_entries().is_empty());
    }

    #[test]
    fn editing_the_selected_profile_targets_replaces_the_target_rows() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let profile_store = temporary_store(&temporary_root);
        let saved_profile = profile_store
            .save_profile(EditTarget::NewProfile, custom_draft("Server"))
            .expect("saved");
        let mut profile_choice = ScanProfileChoice::without_profiles();
        profile_choice.run_profile(saved_profile.clone());
        profile_store
            .save_profile(
                EditTarget::ExistingProfile(saved_profile.profile_origin),
                ProfileDraft {
                    scan_targets: vec!["/srv/www".to_owned()],
                    ..saved_profile.profile_draft
                },
            )
            .expect("edited");
        assert_eq!(
            profile_choice.replace_known_profiles(profile_store.load_profiles().expect("reloaded")),
            TargetRowsChange::ReplaceTargetRows {
                profile_targets: vec!["/srv/www".to_owned()]
            }
        );
    }
}

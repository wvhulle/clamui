use std::path::{Component, Path};

use crate::host_services::protection_evidence::{
    host_protection_evidence::{
        ClamdUserExclusion, ConfiguredPrevention, OnAccessConfig, OnAccessConflict,
        OnAccessEvidence, OnAccessScanner, WatchScope, WatchedLocation,
    },
    kernel_on_access_support::{
        InotifyWatchLimit, KernelBlockingSupport, KernelConfigReadFailure, WatchLimitReadFailure,
    },
};

pub const DEFAULT_INOTIFY_WATCH_LIMIT: u64 = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnAccessBlocking {
    BlocksDetectedFiles,
    PreventionOff,
    PreventionConflictsWithMounts,
    KernelCannotBlock,
    KernelSupportUnknown(KernelConfigReadFailure),
}

pub fn on_access_blocking(
    configured_prevention: ConfiguredPrevention,
    setting_conflicts: &[OnAccessConflict],
    kernel_blocking_support: KernelBlockingSupport,
) -> OnAccessBlocking {
    match (configured_prevention, kernel_blocking_support) {
        (ConfiguredPrevention::PreventionOff, _) => OnAccessBlocking::PreventionOff,
        (ConfiguredPrevention::PreventionRequested, _) if !setting_conflicts.is_empty() => {
            OnAccessBlocking::PreventionConflictsWithMounts
        }
        (ConfiguredPrevention::PreventionRequested, KernelBlockingSupport::NotifyOnly) => {
            OnAccessBlocking::KernelCannotBlock
        }
        (
            ConfiguredPrevention::PreventionRequested,
            KernelBlockingSupport::KernelConfigUnreadable(read_failure),
        ) => OnAccessBlocking::KernelSupportUnknown(read_failure),
        (
            ConfiguredPrevention::PreventionRequested,
            KernelBlockingSupport::PermissionEventsSupported,
        ) => OnAccessBlocking::BlocksDetectedFiles,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OnAccessSetupFinding {
    MountWatchConflicts {
        setting_conflicts: Vec<OnAccessConflict>,
    },
    ClamdUserNotExcluded,
    WholeRootIncluded,
    WatchLimitLow {
        max_user_watches: u64,
        large_tree_path: String,
    },
    WatchLimitUnknown {
        read_failure: WatchLimitReadFailure,
        large_tree_path: String,
    },
}

impl OnAccessSetupFinding {
    pub const fn evidence_is_missing(&self) -> bool {
        match self {
            Self::WatchLimitUnknown { .. } => true,
            Self::MountWatchConflicts { .. }
            | Self::ClamdUserNotExcluded
            | Self::WholeRootIncluded
            | Self::WatchLimitLow { .. } => false,
        }
    }
}

fn is_whole_root(folder_path: &str) -> bool {
    Path::new(folder_path)
        .components()
        .all(|path_component| path_component == Component::RootDir)
        && folder_path.starts_with('/')
}

pub fn is_large_watched_tree(folder_path: &str) -> bool {
    let watched_path = Path::new(folder_path);
    let named_depth = watched_path
        .components()
        .filter(|path_component| matches!(path_component, Component::Normal(_)))
        .count();
    named_depth <= 1
        || watched_path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|parent_name| parent_name == "home")
}

fn watched_folder_paths(watch_scope: &WatchScope) -> Vec<&str> {
    watch_scope
        .watched_locations()
        .into_iter()
        .filter_map(|watched_location| match watched_location {
            WatchedLocation::WatchedFolder { folder_path } => Some(folder_path.as_str()),
            WatchedLocation::WatchedMount { .. } => None,
        })
        .collect()
}

fn watch_limit_finding(
    watched_folders: &[&str],
    inotify_watch_limit: InotifyWatchLimit,
) -> Option<OnAccessSetupFinding> {
    let large_tree_path = (*watched_folders
        .iter()
        .find(|folder_path| is_large_watched_tree(folder_path))?)
    .to_owned();
    match inotify_watch_limit {
        InotifyWatchLimit::LimitRead { max_user_watches }
            if max_user_watches <= DEFAULT_INOTIFY_WATCH_LIMIT =>
        {
            Some(OnAccessSetupFinding::WatchLimitLow {
                max_user_watches,
                large_tree_path,
            })
        }
        InotifyWatchLimit::LimitRead { .. } => None,
        InotifyWatchLimit::LimitUnreadable(read_failure) => {
            Some(OnAccessSetupFinding::WatchLimitUnknown {
                read_failure,
                large_tree_path,
            })
        }
    }
}

pub fn on_access_setup_findings(
    on_access_evidence: &OnAccessEvidence,
) -> Vec<OnAccessSetupFinding> {
    let OnAccessEvidence {
        on_access_scanner: OnAccessScanner::MonitorRunning,
        on_access_config:
            OnAccessConfig::ConfigRead {
                watch_scope,
                setting_conflicts,
                clamd_user_exclusion,
                ..
            },
        inotify_watch_limit,
        ..
    } = on_access_evidence
    else {
        return Vec::new();
    };
    let watched_folders = watched_folder_paths(watch_scope);
    let conflict_finding =
        (!setting_conflicts.is_empty()).then(|| OnAccessSetupFinding::MountWatchConflicts {
            setting_conflicts: setting_conflicts.clone(),
        });
    let exclusion_finding = match clamd_user_exclusion {
        ClamdUserExclusion::ClamdUserExcluded => None,
        ClamdUserExclusion::ClamdUserNotExcluded => {
            Some(OnAccessSetupFinding::ClamdUserNotExcluded)
        }
    };
    let root_finding = watched_folders
        .iter()
        .any(|folder_path| is_whole_root(folder_path))
        .then_some(OnAccessSetupFinding::WholeRootIncluded);
    [
        conflict_finding,
        exclusion_finding,
        root_finding,
        watch_limit_finding(&watched_folders, *inotify_watch_limit),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[cfg(test)]
mod on_access_setup_review_tests {
    use super::*;
    use crate::host_services::{
        clamav_config::clamav_host_config::ConfigSetting,
        protection_evidence::{
            host_protection_evidence::{OnAccessSizeLimit, on_access_config_from_settings},
            protection_evidence_fixtures::healthy_evidence,
        },
    };

    fn config_setting(setting_key: &str, setting_value: &str) -> ConfigSetting {
        ConfigSetting {
            setting_key: setting_key.to_owned(),
            setting_value: setting_value.to_owned(),
        }
    }

    fn evidence_with_settings(
        config_settings: &[ConfigSetting],
        inotify_watch_limit: InotifyWatchLimit,
    ) -> OnAccessEvidence {
        OnAccessEvidence {
            on_access_config: on_access_config_from_settings(config_settings),
            inotify_watch_limit,
            ..healthy_evidence().on_access_evidence
        }
    }

    const RAISED_LIMIT: InotifyWatchLimit = InotifyWatchLimit::LimitRead {
        max_user_watches: 524_288,
    };

    #[test]
    fn mount_watching_with_prevention_is_not_blocking_even_when_the_kernel_could_block() {
        let OnAccessConfig::ConfigRead {
            configured_prevention,
            setting_conflicts,
            ..
        } = on_access_config_from_settings(&[
            config_setting("OnAccessMountPath", "/media"),
            config_setting("OnAccessPrevention", "yes"),
        ])
        else {
            panic!("a read config was expected");
        };
        assert_eq!(
            on_access_blocking(
                configured_prevention,
                &setting_conflicts,
                KernelBlockingSupport::PermissionEventsSupported
            ),
            OnAccessBlocking::PreventionConflictsWithMounts
        );
    }

    #[test]
    fn blocking_is_claimed_only_when_prevention_has_no_conflict_and_the_kernel_supports_it() {
        let blocking_with = |kernel_support| {
            on_access_blocking(
                ConfiguredPrevention::PreventionRequested,
                &[],
                kernel_support,
            )
        };
        assert_eq!(
            blocking_with(KernelBlockingSupport::PermissionEventsSupported),
            OnAccessBlocking::BlocksDetectedFiles
        );
        assert_eq!(
            blocking_with(KernelBlockingSupport::NotifyOnly),
            OnAccessBlocking::KernelCannotBlock
        );
        assert_eq!(
            blocking_with(KernelBlockingSupport::KernelConfigUnreadable(
                KernelConfigReadFailure::NoKernelConfigFound
            )),
            OnAccessBlocking::KernelSupportUnknown(KernelConfigReadFailure::NoKernelConfigFound)
        );
        assert_eq!(
            on_access_blocking(
                ConfiguredPrevention::PreventionOff,
                &[],
                KernelBlockingSupport::PermissionEventsSupported
            ),
            OnAccessBlocking::PreventionOff
        );
    }

    #[test]
    fn every_option_combined_with_a_mount_path_is_named_as_a_conflict() {
        let on_access_evidence = evidence_with_settings(
            &[
                config_setting("OnAccessMountPath", "/media"),
                config_setting("OnAccessIncludePath", "/srv/inbox"),
                config_setting("OnAccessExcludePath", "/srv/inbox/cache"),
                config_setting("OnAccessExtraScanning", "yes"),
                config_setting("OnAccessPrevention", "no"),
                config_setting("OnAccessExcludeUname", "clamav"),
            ],
            RAISED_LIMIT,
        );
        assert_eq!(
            on_access_setup_findings(&on_access_evidence),
            vec![OnAccessSetupFinding::MountWatchConflicts {
                setting_conflicts: vec![
                    OnAccessConflict::IncludePathWithMountPath,
                    OnAccessConflict::ExcludePathWithMountPath,
                    OnAccessConflict::ExtraScanningWithMountPath,
                ],
            }]
        );
        assert_eq!(
            on_access_setup_findings(&evidence_with_settings(
                &[
                    config_setting("OnAccessIncludePath", "/srv/inbox"),
                    config_setting("OnAccessExcludePath", "/srv/inbox/cache"),
                    config_setting("OnAccessPrevention", "yes"),
                    config_setting("OnAccessExcludeUname", "clamav"),
                ],
                RAISED_LIMIT,
            )),
            Vec::new()
        );
    }

    #[test]
    fn a_running_monitor_without_a_clamd_exclusion_risks_a_scan_loop() {
        let included_folder = config_setting("OnAccessIncludePath", "/srv/inbox");
        assert_eq!(
            on_access_setup_findings(&evidence_with_settings(
                std::slice::from_ref(&included_folder),
                RAISED_LIMIT
            )),
            vec![OnAccessSetupFinding::ClamdUserNotExcluded]
        );
        assert_eq!(
            on_access_setup_findings(&evidence_with_settings(
                &[
                    included_folder.clone(),
                    config_setting("OnAccessExcludeUID", "112")
                ],
                RAISED_LIMIT
            )),
            Vec::new()
        );
        assert_eq!(
            on_access_setup_findings(&OnAccessEvidence {
                on_access_scanner: OnAccessScanner::NeverSetUp,
                ..evidence_with_settings(&[included_folder], RAISED_LIMIT)
            }),
            Vec::new()
        );
    }

    #[test]
    fn including_the_whole_root_is_flagged() {
        let findings = on_access_setup_findings(&evidence_with_settings(
            &[
                config_setting("OnAccessIncludePath", "/"),
                config_setting("OnAccessExcludeUname", "clamav"),
            ],
            RAISED_LIMIT,
        ));
        assert_eq!(findings, vec![OnAccessSetupFinding::WholeRootIncluded]);
        assert!(!is_whole_root("/home"));
    }

    #[test]
    fn a_whole_home_or_larger_tree_counts_as_large_but_its_subfolders_do_not() {
        assert!(is_large_watched_tree("/"));
        assert!(is_large_watched_tree("/home"));
        assert!(is_large_watched_tree("/srv"));
        assert!(is_large_watched_tree("/home/alice"));
        assert!(is_large_watched_tree("/home/alice/"));
        assert!(is_large_watched_tree("/var/home/alice"));
        assert!(!is_large_watched_tree("/home/alice/Downloads"));
        assert!(!is_large_watched_tree("/srv/inbox"));
    }

    #[test]
    fn the_default_watch_limit_is_flagged_only_for_large_watched_folders() {
        let large_folder = [
            config_setting("OnAccessIncludePath", "/home/alice"),
            config_setting("OnAccessExcludeUname", "clamav"),
        ];
        let default_limit = InotifyWatchLimit::LimitRead {
            max_user_watches: DEFAULT_INOTIFY_WATCH_LIMIT,
        };
        assert_eq!(
            on_access_setup_findings(&evidence_with_settings(&large_folder, default_limit)),
            vec![OnAccessSetupFinding::WatchLimitLow {
                max_user_watches: DEFAULT_INOTIFY_WATCH_LIMIT,
                large_tree_path: "/home/alice".to_owned(),
            }]
        );
        assert_eq!(
            on_access_setup_findings(&evidence_with_settings(&large_folder, RAISED_LIMIT)),
            Vec::new()
        );
        assert_eq!(
            on_access_setup_findings(&evidence_with_settings(
                &[
                    config_setting("OnAccessIncludePath", "/home/alice/Downloads"),
                    config_setting("OnAccessExcludeUname", "clamav"),
                ],
                default_limit
            )),
            Vec::new()
        );
        assert_eq!(
            on_access_setup_findings(&evidence_with_settings(
                &[
                    config_setting("OnAccessMountPath", "/home"),
                    config_setting("OnAccessExcludeUname", "clamav"),
                ],
                default_limit
            )),
            Vec::new()
        );
    }

    #[test]
    fn an_unreadable_watch_limit_is_unknown_rather_than_fine() {
        let findings = on_access_setup_findings(&evidence_with_settings(
            &[
                config_setting("OnAccessIncludePath", "/home"),
                config_setting("OnAccessExcludeUname", "clamav"),
            ],
            InotifyWatchLimit::LimitUnreadable(WatchLimitReadFailure::LimitNotANumber),
        ));
        assert_eq!(
            findings,
            vec![OnAccessSetupFinding::WatchLimitUnknown {
                read_failure: WatchLimitReadFailure::LimitNotANumber,
                large_tree_path: "/home".to_owned(),
            }]
        );
        assert!(findings[0].evidence_is_missing());
    }

    #[test]
    fn the_size_limit_is_unaffected_by_the_review() {
        assert!(matches!(
            on_access_config_from_settings(&[]),
            OnAccessConfig::ConfigRead {
                size_limit: OnAccessSizeLimit::DefaultLimit,
                ..
            }
        ));
    }
}

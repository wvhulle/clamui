use std::{
    collections::{HashSet, VecDeque},
    env,
    ffi::OsString,
    fs, io,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

use rustix::fs::Access;

use crate::desktop_integration::flatpak_sandbox::{
    host_program_search_directories, readable_host_path, running_in_flatpak,
};

const SYSTEM_PROGRAM_DIRECTORIES: [&str; 3] = ["/usr/local/sbin", "/usr/sbin", "/sbin"];
const MAXIMUM_SYMLINK_HOPS: usize = 40;
const STICKY_MODE_BIT: u32 = 0o1000;
const EXECUTE_MODE_BITS: u32 = 0o111;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClamavProgram {
    ClamdClient,
    StandaloneScanner,
    SignatureUpdater,
}

impl ClamavProgram {
    pub const fn program_name(self) -> &'static str {
        match self {
            Self::ClamdClient => "clamdscan",
            Self::StandaloneScanner => "clamscan",
            Self::SignatureUpdater => "freshclam",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplaceableCandidate {
    pub candidate_path: PathBuf,
    pub replaceable_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgramLocation {
    TrustedProgram {
        program_path: PathBuf,
    },
    ShadowedTrustedProgram {
        program_path: PathBuf,
        ignored_candidates: Vec<ReplaceableCandidate>,
    },
    OnlyReplaceableCandidates {
        replaceable_candidates: Vec<ReplaceableCandidate>,
    },
    ProgramNotFound,
}

#[derive(Debug, thiserror::Error)]
pub enum ProgramRefusal {
    #[error("the program is not installed")]
    ProgramMissing,
    #[error("the program at {} can be replaced by your account through {}", .candidate_path.display(), .replaceable_path.display())]
    ProgramReplaceable {
        candidate_path: PathBuf,
        replaceable_path: PathBuf,
    },
}

impl ProgramLocation {
    pub fn runnable_path(&self) -> Result<&Path, ProgramRefusal> {
        match self {
            Self::TrustedProgram { program_path }
            | Self::ShadowedTrustedProgram { program_path, .. } => Ok(program_path),
            Self::OnlyReplaceableCandidates {
                replaceable_candidates,
            } => Err(replaceable_candidates.first().map_or(
                ProgramRefusal::ProgramMissing,
                |first_candidate| ProgramRefusal::ProgramReplaceable {
                    candidate_path: first_candidate.candidate_path.clone(),
                    replaceable_path: first_candidate.replaceable_path.clone(),
                },
            )),
            Self::ProgramNotFound => Err(ProgramRefusal::ProgramMissing),
        }
    }

    pub fn replaceable_candidates(&self) -> &[ReplaceableCandidate] {
        match self {
            Self::ShadowedTrustedProgram {
                ignored_candidates: replaceable_candidates,
                ..
            }
            | Self::OnlyReplaceableCandidates {
                replaceable_candidates,
            } => replaceable_candidates,
            Self::TrustedProgram { .. } | Self::ProgramNotFound => &[],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    Directory,
    SymbolicLink,
    RegularFile,
    OtherEntry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryFacts {
    pub entry_kind: EntryKind,
    pub owner_uid: u32,
    pub mode_bits: u32,
    pub writable_by_user: bool,
}

pub trait FilesystemInspector {
    fn current_user_id(&self) -> u32;
    fn root_directory_facts(&self) -> io::Result<EntryFacts>;
    fn entry_facts(&self, host_path: &Path) -> io::Result<EntryFacts>;
    fn link_target(&self, host_path: &Path) -> io::Result<PathBuf>;
}

pub struct HostFilesystemInspector;

const TRUSTED_SANDBOX_HOST_ROOT: EntryFacts = EntryFacts {
    entry_kind: EntryKind::Directory,
    owner_uid: 0,
    mode_bits: 0o755,
    writable_by_user: false,
};

impl FilesystemInspector for HostFilesystemInspector {
    fn current_user_id(&self) -> u32 {
        rustix::process::getuid().as_raw()
    }

    fn root_directory_facts(&self) -> io::Result<EntryFacts> {
        if running_in_flatpak() {
            Ok(TRUSTED_SANDBOX_HOST_ROOT)
        } else {
            self.entry_facts(Path::new("/"))
        }
    }

    fn entry_facts(&self, host_path: &Path) -> io::Result<EntryFacts> {
        let readable_path = readable_host_path(host_path);
        let entry_metadata = fs::symlink_metadata(&readable_path)?;
        let entry_type = entry_metadata.file_type();
        let entry_kind = if entry_type.is_symlink() {
            EntryKind::SymbolicLink
        } else if entry_type.is_dir() {
            EntryKind::Directory
        } else if entry_type.is_file() {
            EntryKind::RegularFile
        } else {
            EntryKind::OtherEntry
        };
        Ok(EntryFacts {
            entry_kind,
            owner_uid: entry_metadata.uid(),
            mode_bits: entry_metadata.mode(),
            writable_by_user: entry_kind != EntryKind::SymbolicLink
                && rustix::fs::access(&readable_path, Access::WRITE_OK).is_ok(),
        })
    }

    fn link_target(&self, host_path: &Path) -> io::Result<PathBuf> {
        fs::read_link(readable_host_path(host_path))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CandidateVerdict {
    NotRunnable,
    Trusted { resolved_path: PathBuf },
    Replaceable { replaceable_path: PathBuf },
}

fn directory_lets_user_replace(
    directory_facts: &EntryFacts,
    entry_facts: &EntryFacts,
    user_id: u32,
) -> bool {
    let sticky_protects_entry =
        directory_facts.mode_bits & STICKY_MODE_BIT != 0 && entry_facts.owner_uid != user_id;
    directory_facts.owner_uid == user_id
        || (directory_facts.writable_by_user && !sticky_protects_entry)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ReplaceableSoFar {
    NoReplaceableComponent,
    FirstReplaceableComponent { replaceable_path: PathBuf },
}

impl ReplaceableSoFar {
    fn noting(self, replaceable_path: PathBuf) -> Self {
        match self {
            Self::NoReplaceableComponent => Self::FirstReplaceableComponent { replaceable_path },
            earlier_component @ Self::FirstReplaceableComponent { .. } => earlier_component,
        }
    }
}

fn final_file_verdict(
    inspector: &impl FilesystemInspector,
    resolved_path: PathBuf,
    replaceable_so_far: ReplaceableSoFar,
) -> CandidateVerdict {
    match inspector.entry_facts(&resolved_path) {
        Ok(file_facts)
            if file_facts.entry_kind == EntryKind::RegularFile
                && file_facts.mode_bits & EXECUTE_MODE_BITS != 0 =>
        {
            let file_replaceable =
                file_facts.owner_uid == inspector.current_user_id() || file_facts.writable_by_user;
            match replaceable_so_far {
                ReplaceableSoFar::FirstReplaceableComponent { replaceable_path } => {
                    CandidateVerdict::Replaceable { replaceable_path }
                }
                ReplaceableSoFar::NoReplaceableComponent if file_replaceable => {
                    CandidateVerdict::Replaceable {
                        replaceable_path: resolved_path,
                    }
                }
                ReplaceableSoFar::NoReplaceableComponent => {
                    CandidateVerdict::Trusted { resolved_path }
                }
            }
        }
        Ok(_) | Err(_) => CandidateVerdict::NotRunnable,
    }
}

fn path_names(followed_path: &Path) -> VecDeque<OsString> {
    followed_path
        .components()
        .filter_map(|path_component| match path_component {
            Component::Normal(component_name) => Some(component_name.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
        })
        .collect()
}

struct PathWalk {
    current_directory: PathBuf,
    remaining_names: VecDeque<OsString>,
    symlink_hops: usize,
    replaceable_so_far: ReplaceableSoFar,
}

fn walk_remaining_names(
    inspector: &impl FilesystemInspector,
    path_walk: PathWalk,
) -> CandidateVerdict {
    let PathWalk {
        current_directory,
        mut remaining_names,
        symlink_hops,
        replaceable_so_far,
    } = path_walk;
    let Some(next_name) = remaining_names.pop_front() else {
        return final_file_verdict(inspector, current_directory, replaceable_so_far);
    };
    if next_name == ".." {
        let parent_directory = current_directory
            .parent()
            .map_or_else(|| PathBuf::from("/"), Path::to_path_buf);
        return walk_remaining_names(
            inspector,
            PathWalk {
                current_directory: parent_directory,
                remaining_names,
                symlink_hops,
                replaceable_so_far,
            },
        );
    }
    let entry_path = current_directory.join(&next_name);
    let directory_facts = if current_directory == Path::new("/") {
        inspector.root_directory_facts()
    } else {
        inspector.entry_facts(&current_directory)
    };
    let (Ok(directory_facts), Ok(entry_facts)) =
        (directory_facts, inspector.entry_facts(&entry_path))
    else {
        return CandidateVerdict::NotRunnable;
    };
    let replaceable_so_far =
        if directory_lets_user_replace(&directory_facts, &entry_facts, inspector.current_user_id())
        {
            replaceable_so_far.noting(entry_path.clone())
        } else {
            replaceable_so_far
        };
    if entry_facts.entry_kind != EntryKind::SymbolicLink {
        return walk_remaining_names(
            inspector,
            PathWalk {
                current_directory: entry_path,
                remaining_names,
                symlink_hops,
                replaceable_so_far,
            },
        );
    }
    if symlink_hops >= MAXIMUM_SYMLINK_HOPS {
        return CandidateVerdict::NotRunnable;
    }
    let Ok(link_target) = inspector.link_target(&entry_path) else {
        return CandidateVerdict::NotRunnable;
    };
    let target_start = if link_target.is_absolute() {
        PathBuf::from("/")
    } else {
        current_directory
    };
    walk_remaining_names(
        inspector,
        PathWalk {
            current_directory: target_start,
            remaining_names: path_names(&link_target)
                .into_iter()
                .chain(remaining_names)
                .collect(),
            symlink_hops: symlink_hops + 1,
            replaceable_so_far,
        },
    )
}

fn inspect_candidate(
    inspector: &impl FilesystemInspector,
    candidate_path: &Path,
) -> CandidateVerdict {
    if !candidate_path.is_absolute() {
        return match final_file_verdict(
            inspector,
            candidate_path.to_path_buf(),
            ReplaceableSoFar::NoReplaceableComponent,
        ) {
            CandidateVerdict::NotRunnable => CandidateVerdict::NotRunnable,
            CandidateVerdict::Trusted { .. } | CandidateVerdict::Replaceable { .. } => {
                CandidateVerdict::Replaceable {
                    replaceable_path: candidate_path.to_path_buf(),
                }
            }
        };
    }
    let Ok(root_facts) = inspector.root_directory_facts() else {
        return CandidateVerdict::NotRunnable;
    };
    let replaceable_so_far =
        if root_facts.owner_uid == inspector.current_user_id() || root_facts.writable_by_user {
            ReplaceableSoFar::FirstReplaceableComponent {
                replaceable_path: PathBuf::from("/"),
            }
        } else {
            ReplaceableSoFar::NoReplaceableComponent
        };
    walk_remaining_names(
        inspector,
        PathWalk {
            current_directory: PathBuf::from("/"),
            remaining_names: path_names(candidate_path),
            symlink_hops: 0,
            replaceable_so_far,
        },
    )
}

pub fn locate_program_among(
    inspector: &impl FilesystemInspector,
    program_name: &str,
    search_directories: impl IntoIterator<Item = PathBuf>,
) -> ProgramLocation {
    let mut seen_directories = HashSet::new();
    let found_candidates: Vec<(PathBuf, CandidateVerdict)> = search_directories
        .into_iter()
        .filter(|search_directory| seen_directories.insert(search_directory.clone()))
        .map(|search_directory| search_directory.join(program_name))
        .map(|candidate_path| {
            let candidate_verdict = inspect_candidate(inspector, &candidate_path);
            (candidate_path, candidate_verdict)
        })
        .filter(|(_candidate_path, candidate_verdict)| {
            *candidate_verdict != CandidateVerdict::NotRunnable
        })
        .collect();
    let trusted_position =
        found_candidates
            .iter()
            .position(|(_candidate_path, candidate_verdict)| {
                matches!(candidate_verdict, CandidateVerdict::Trusted { .. })
            });
    let replaceable_before = |candidate_limit: usize| {
        found_candidates
            .iter()
            .take(candidate_limit)
            .filter_map(
                |(candidate_path, candidate_verdict)| match candidate_verdict {
                    CandidateVerdict::Replaceable { replaceable_path } => {
                        Some(ReplaceableCandidate {
                            candidate_path: candidate_path.clone(),
                            replaceable_path: replaceable_path.clone(),
                        })
                    }
                    CandidateVerdict::NotRunnable | CandidateVerdict::Trusted { .. } => None,
                },
            )
            .collect::<Vec<_>>()
    };
    match trusted_position {
        Some(trusted_index) => {
            let (candidate_path, _trusted_verdict) = &found_candidates[trusted_index];
            let ignored_candidates = replaceable_before(trusted_index);
            if ignored_candidates.is_empty() {
                ProgramLocation::TrustedProgram {
                    program_path: candidate_path.clone(),
                }
            } else {
                ProgramLocation::ShadowedTrustedProgram {
                    program_path: candidate_path.clone(),
                    ignored_candidates,
                }
            }
        }
        None if found_candidates.is_empty() => ProgramLocation::ProgramNotFound,
        None => ProgramLocation::OnlyReplaceableCandidates {
            replaceable_candidates: replaceable_before(found_candidates.len()),
        },
    }
}

fn program_search_directories() -> Vec<PathBuf> {
    host_program_search_directories().unwrap_or_else(|| {
        env::var_os("PATH")
            .map(|search_path| env::split_paths(&search_path).collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .chain(SYSTEM_PROGRAM_DIRECTORIES.map(PathBuf::from))
            .collect()
    })
}

pub fn locate_trusted_program(clamav_program: ClamavProgram) -> ProgramLocation {
    locate_program_among(
        &HostFilesystemInspector,
        clamav_program.program_name(),
        program_search_directories(),
    )
}

#[cfg(test)]
mod trusted_program_lookup_tests {
    use std::collections::HashMap;

    use super::*;

    const DESKTOP_USER: u32 = 1000;
    const ROOT_USER: u32 = 0;

    struct FixtureFilesystem {
        entries: HashMap<PathBuf, EntryFacts>,
        links: HashMap<PathBuf, PathBuf>,
    }

    fn root_directory() -> EntryFacts {
        EntryFacts {
            entry_kind: EntryKind::Directory,
            owner_uid: ROOT_USER,
            mode_bits: 0o755,
            writable_by_user: false,
        }
    }

    fn user_directory() -> EntryFacts {
        EntryFacts {
            entry_kind: EntryKind::Directory,
            owner_uid: DESKTOP_USER,
            mode_bits: 0o755,
            writable_by_user: true,
        }
    }

    fn root_program() -> EntryFacts {
        EntryFacts {
            entry_kind: EntryKind::RegularFile,
            owner_uid: ROOT_USER,
            mode_bits: 0o555,
            writable_by_user: false,
        }
    }

    fn user_program() -> EntryFacts {
        EntryFacts {
            entry_kind: EntryKind::RegularFile,
            owner_uid: DESKTOP_USER,
            mode_bits: 0o755,
            writable_by_user: true,
        }
    }

    fn symbolic_link(owner_uid: u32) -> EntryFacts {
        EntryFacts {
            entry_kind: EntryKind::SymbolicLink,
            owner_uid,
            mode_bits: 0o777,
            writable_by_user: false,
        }
    }

    impl FixtureFilesystem {
        fn with_system_layout() -> Self {
            let entries = [
                ("/usr", root_directory()),
                ("/usr/bin", root_directory()),
                ("/usr/bin/clamdscan", root_program()),
                ("/home", root_directory()),
                ("/home/desktop", user_directory()),
                ("/home/desktop/.local", user_directory()),
                ("/home/desktop/.local/bin", user_directory()),
                ("/home/desktop/.local/bin/clamdscan", user_program()),
                ("/nix", root_directory()),
                (
                    "/nix/store",
                    EntryFacts {
                        mode_bits: 0o1775,
                        writable_by_user: true,
                        ..root_directory()
                    },
                ),
                ("/nix/store/clamav", root_directory()),
                ("/nix/store/clamav/bin", root_directory()),
                ("/nix/store/clamav/bin/clamscan", root_program()),
                ("/run", root_directory()),
                ("/run/system", root_directory()),
                ("/run/system/bin", root_directory()),
                ("/run/system/bin/clamscan", symbolic_link(ROOT_USER)),
                ("/home/desktop/.nix-profile", symbolic_link(DESKTOP_USER)),
                (
                    "/tmp",
                    EntryFacts {
                        mode_bits: 0o1777,
                        writable_by_user: true,
                        ..root_directory()
                    },
                ),
                (
                    "/tmp/planted",
                    EntryFacts {
                        owner_uid: DESKTOP_USER,
                        ..root_directory()
                    },
                ),
                ("/tmp/planted/clamscan", root_program()),
                ("bin/clamscan", root_program()),
            ]
            .into_iter()
            .map(|(entry_path, entry_facts)| (PathBuf::from(entry_path), entry_facts))
            .collect();
            let links = [
                (
                    "/run/system/bin/clamscan",
                    "../../../nix/store/clamav/bin/clamscan",
                ),
                ("/home/desktop/.nix-profile", "/nix/store/clamav"),
            ]
            .into_iter()
            .map(|(link_path, link_target)| (PathBuf::from(link_path), PathBuf::from(link_target)))
            .collect();
            Self { entries, links }
        }
    }

    impl FilesystemInspector for FixtureFilesystem {
        fn current_user_id(&self) -> u32 {
            DESKTOP_USER
        }

        fn root_directory_facts(&self) -> io::Result<EntryFacts> {
            Ok(root_directory())
        }

        fn entry_facts(&self, host_path: &Path) -> io::Result<EntryFacts> {
            self.entries
                .get(host_path)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }

        fn link_target(&self, host_path: &Path) -> io::Result<PathBuf> {
            self.links
                .get(host_path)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
        }
    }

    fn directories(directory_paths: &[&str]) -> Vec<PathBuf> {
        directory_paths.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn user_directory_without_the_program_is_not_reported() {
        assert_eq!(
            locate_program_among(
                &FixtureFilesystem::with_system_layout(),
                "clamscan",
                directories(&["/home/desktop/.local/bin", "/run/system/bin"]),
            ),
            ProgramLocation::TrustedProgram {
                program_path: PathBuf::from("/run/system/bin/clamscan")
            }
        );
    }

    #[test]
    fn root_owned_program_is_trusted() {
        assert_eq!(
            locate_program_among(
                &FixtureFilesystem::with_system_layout(),
                "clamdscan",
                directories(&["/usr/bin"]),
            ),
            ProgramLocation::TrustedProgram {
                program_path: PathBuf::from("/usr/bin/clamdscan")
            }
        );
    }

    #[test]
    fn program_in_user_directory_shadowing_system_program_is_skipped_and_reported() {
        assert_eq!(
            locate_program_among(
                &FixtureFilesystem::with_system_layout(),
                "clamdscan",
                directories(&["/home/desktop/.local/bin", "/usr/bin"]),
            ),
            ProgramLocation::ShadowedTrustedProgram {
                program_path: PathBuf::from("/usr/bin/clamdscan"),
                ignored_candidates: vec![ReplaceableCandidate {
                    candidate_path: PathBuf::from("/home/desktop/.local/bin/clamdscan"),
                    replaceable_path: PathBuf::from("/home/desktop/.local"),
                }],
            }
        );
    }

    #[test]
    fn only_user_controlled_program_is_refused() {
        let program_location = locate_program_among(
            &FixtureFilesystem::with_system_layout(),
            "clamdscan",
            directories(&["/home/desktop/.local/bin"]),
        );
        assert!(matches!(
            program_location.runnable_path(),
            Err(ProgramRefusal::ProgramReplaceable { .. })
        ));
    }

    #[test]
    fn root_owned_symlink_into_sticky_store_is_trusted() {
        assert_eq!(
            locate_program_among(
                &FixtureFilesystem::with_system_layout(),
                "clamscan",
                directories(&["/run/system/bin"]),
            ),
            ProgramLocation::TrustedProgram {
                program_path: PathBuf::from("/run/system/bin/clamscan")
            }
        );
    }

    #[test]
    fn user_owned_profile_symlink_is_replaceable_even_when_target_is_trusted() {
        assert_eq!(
            locate_program_among(
                &FixtureFilesystem::with_system_layout(),
                "clamscan",
                directories(&["/home/desktop/.nix-profile/bin"]),
            ),
            ProgramLocation::OnlyReplaceableCandidates {
                replaceable_candidates: vec![ReplaceableCandidate {
                    candidate_path: PathBuf::from("/home/desktop/.nix-profile/bin/clamscan"),
                    replaceable_path: PathBuf::from("/home/desktop/.nix-profile"),
                }],
            }
        );
    }

    #[test]
    fn user_owned_directory_inside_sticky_directory_is_replaceable() {
        assert!(matches!(
            locate_program_among(
                &FixtureFilesystem::with_system_layout(),
                "clamscan",
                directories(&["/tmp/planted"]),
            ),
            ProgramLocation::OnlyReplaceableCandidates { .. }
        ));
    }

    #[test]
    fn relative_search_directory_is_replaceable() {
        assert!(matches!(
            locate_program_among(
                &FixtureFilesystem::with_system_layout(),
                "clamscan",
                directories(&["bin"]),
            ),
            ProgramLocation::OnlyReplaceableCandidates { .. }
        ));
    }

    #[test]
    #[ignore = "reads the real host"]
    fn host_scanner_programs_are_trusted() {
        [ClamavProgram::ClamdClient, ClamavProgram::StandaloneScanner]
            .into_iter()
            .for_each(|clamav_program| {
                let program_location = locate_trusted_program(clamav_program);
                println!("{program_location:?}");
                assert!(program_location.runnable_path().is_ok());
            });
    }

    #[test]
    fn missing_program_is_not_found() {
        assert_eq!(
            locate_program_among(
                &FixtureFilesystem::with_system_layout(),
                "freshclam",
                directories(&["/usr/bin"]),
            ),
            ProgramLocation::ProgramNotFound
        );
    }
}

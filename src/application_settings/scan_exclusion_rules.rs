use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use regex::Regex;

pub const PRESET_DIRECTORY_NAMES: [&str; 6] = [
    "node_modules",
    ".git",
    ".venv",
    "build",
    "dist",
    "__pycache__",
];
const REGEX_METACHARACTERS: &str = ".[]()*+?{}|^$\\";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExclusionKind {
    DirectoryOnly,
    AnyMatchingPath,
}

impl ExclusionKind {
    pub const fn stored_text(self) -> &'static str {
        match self {
            Self::DirectoryOnly => "directory",
            Self::AnyMatchingPath => "pattern",
        }
    }

    pub fn from_stored_text(stored_text: &str) -> Self {
        if stored_text == "directory" {
            Self::DirectoryOnly
        } else {
            Self::AnyMatchingPath
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExclusionEntry {
    pub exclusion_pattern: String,
    pub exclusion_kind: ExclusionKind,
    pub is_enabled: bool,
}

impl ExclusionEntry {
    pub fn enabled_pattern(exclusion_pattern: String) -> Self {
        Self {
            exclusion_pattern,
            exclusion_kind: ExclusionKind::AnyMatchingPath,
            is_enabled: true,
        }
    }
}

fn push_escaped_character(regex_text: &mut String, pattern_character: char) {
    if REGEX_METACHARACTERS.contains(pattern_character) {
        regex_text.push('\\');
    }
    regex_text.push(pattern_character);
}

fn closing_bracket_position(pattern_characters: &[char], opening_position: usize) -> Option<usize> {
    let first_member = opening_position
        + 1
        + usize::from(pattern_characters.get(opening_position + 1) == Some(&'!'));
    let search_start = first_member + 1;
    pattern_characters
        .get(search_start..)?
        .iter()
        .position(|class_character| *class_character == ']')
        .map(|relative_position| search_start + relative_position)
}

fn glob_body_as_regex(glob_pattern: &str) -> String {
    let pattern_characters = glob_pattern.chars().collect::<Vec<_>>();
    let mut regex_text = String::new();
    let mut pattern_position = 0;
    while let Some(pattern_character) = pattern_characters.get(pattern_position) {
        match pattern_character {
            '*' => regex_text.push_str(".*"),
            '?' => regex_text.push('.'),
            '[' => match closing_bracket_position(&pattern_characters, pattern_position) {
                Some(closing_position) => {
                    let class_members = &pattern_characters[pattern_position + 1..closing_position];
                    let (negated, literal_members) = match class_members.split_first() {
                        Some((&'!', remaining_members)) => (true, remaining_members),
                        _other_members => (false, class_members),
                    };
                    regex_text.push('[');
                    if negated {
                        regex_text.push('^');
                    }
                    literal_members.iter().for_each(|class_member| {
                        if matches!(class_member, '\\' | '^' | '[') {
                            regex_text.push('\\');
                        }
                        regex_text.push(*class_member);
                    });
                    regex_text.push(']');
                    pattern_position = closing_position;
                }
                None => regex_text.push_str("\\["),
            },
            literal_character => push_escaped_character(&mut regex_text, *literal_character),
        }
        pattern_position += 1;
    }
    regex_text
}

fn expanded_home_pattern(exclusion_pattern: &str, home_directory: &Path) -> String {
    match exclusion_pattern.strip_prefix("~/") {
        Some(home_relative_pattern) => home_directory
            .join(home_relative_pattern)
            .to_string_lossy()
            .into_owned(),
        None => exclusion_pattern.to_owned(),
    }
}

fn exclusion_regex_text(expanded_pattern: &str, exclusion_kind: ExclusionKind) -> String {
    if expanded_pattern.starts_with('/') {
        return format!(
            "^{}(/|$)",
            glob_body_as_regex(expanded_pattern.trim_end_matches('/'))
        );
    }
    let regex_body = glob_body_as_regex(expanded_pattern);
    match exclusion_kind {
        ExclusionKind::DirectoryOnly => format!("(^|/){regex_body}(/|$)"),
        ExclusionKind::AnyMatchingPath => format!("(^|/){regex_body}$"),
    }
}

#[derive(Clone, Debug)]
struct CompiledExclusion {
    regex_text: String,
    compiled_regex: Regex,
}

fn compiled_exclusion(regex_text: String) -> Option<CompiledExclusion> {
    let compiled_regex = Regex::new(&regex_text).ok()?;
    Some(CompiledExclusion {
        regex_text,
        compiled_regex,
    })
}

#[derive(Clone, Debug, Default)]
pub struct ScanExclusions {
    directory_exclusions: Vec<CompiledExclusion>,
    file_exclusions: Vec<CompiledExclusion>,
}

fn path_matches_any(file_path: &Path, exclusions: &[CompiledExclusion]) -> bool {
    let path_text = file_path.to_string_lossy();
    exclusions
        .iter()
        .any(|exclusion| exclusion.compiled_regex.is_match(&path_text))
}

impl ScanExclusions {
    pub fn from_entries(exclusion_entries: &[ExclusionEntry], home_directory: &Path) -> Self {
        exclusion_entries
            .iter()
            .filter(|exclusion_entry| exclusion_entry.is_enabled)
            .fold(Self::default(), |mut scan_exclusions, exclusion_entry| {
                let expanded_pattern =
                    expanded_home_pattern(&exclusion_entry.exclusion_pattern, home_directory);
                let regex_text =
                    exclusion_regex_text(&expanded_pattern, exclusion_entry.exclusion_kind);
                if let Some(exclusion) = compiled_exclusion(regex_text) {
                    if exclusion_entry.exclusion_kind == ExclusionKind::DirectoryOnly
                        || expanded_pattern.starts_with('/')
                    {
                        scan_exclusions.directory_exclusions.push(exclusion.clone());
                    }
                    if exclusion_entry.exclusion_kind == ExclusionKind::AnyMatchingPath {
                        scan_exclusions.file_exclusions.push(exclusion);
                    }
                }
                scan_exclusions
            })
    }

    pub fn excludes_directory(&self, directory_path: &Path) -> bool {
        path_matches_any(directory_path, &self.directory_exclusions)
    }

    pub fn excludes_file(&self, file_path: &Path) -> bool {
        path_matches_any(file_path, &self.file_exclusions)
    }

    pub fn clamscan_arguments(&self) -> Vec<OsString> {
        self.directory_exclusions
            .iter()
            .map(|exclusion| OsString::from(format!("--exclude-dir={}", exclusion.regex_text)))
            .chain(
                self.file_exclusions
                    .iter()
                    .map(|exclusion| OsString::from(format!("--exclude={}", exclusion.regex_text))),
            )
            .collect()
    }
}

pub fn exclusion_entry_for_threat(threat_path: &Path) -> ExclusionEntry {
    ExclusionEntry::enabled_pattern(PathBuf::from(threat_path).to_string_lossy().into_owned())
}

#[cfg(test)]
mod scan_exclusion_rules_tests {
    use super::*;

    fn exclusions_of(exclusion_entries: &[ExclusionEntry]) -> ScanExclusions {
        ScanExclusions::from_entries(exclusion_entries, Path::new("/home/user"))
    }

    fn directory_entry(exclusion_pattern: &str) -> ExclusionEntry {
        ExclusionEntry {
            exclusion_pattern: exclusion_pattern.to_owned(),
            exclusion_kind: ExclusionKind::DirectoryOnly,
            is_enabled: true,
        }
    }

    fn pattern_entry(exclusion_pattern: &str) -> ExclusionEntry {
        ExclusionEntry::enabled_pattern(exclusion_pattern.to_owned())
    }

    #[test]
    fn directory_presets_never_exclude_a_file_with_the_same_name() {
        let scan_exclusions = exclusions_of(&[directory_entry("build")]);
        assert!(scan_exclusions.excludes_directory(Path::new("/repo/build")));
        assert!(!scan_exclusions.excludes_file(Path::new("/home/user/Downloads/build")));
        assert!(!scan_exclusions.excludes_directory(Path::new("/repo/rebuild")));
    }

    #[test]
    fn glob_patterns_match_names_without_matching_substrings() {
        let scan_exclusions = exclusions_of(&[pattern_entry("*.tmp")]);
        assert!(scan_exclusions.excludes_file(Path::new("/scan/a.tmp")));
        assert!(!scan_exclusions.excludes_file(Path::new("/scan/a.tmp.exe")));
    }

    #[test]
    fn absolute_paths_cover_their_contents_but_not_their_siblings() {
        let scan_exclusions = exclusions_of(&[pattern_entry("/scan/private")]);
        assert!(scan_exclusions.excludes_directory(Path::new("/scan/private")));
        assert!(scan_exclusions.excludes_file(Path::new("/scan/private/file")));
        assert!(!scan_exclusions.excludes_file(Path::new("/scan/private-notes")));
    }

    #[test]
    fn home_relative_patterns_are_expanded() {
        let scan_exclusions = exclusions_of(&[pattern_entry("~/Videos")]);
        assert!(scan_exclusions.excludes_file(Path::new("/home/user/Videos/film.mkv")));
    }

    #[test]
    fn disabled_entries_have_no_effect() {
        let scan_exclusions = exclusions_of(&[ExclusionEntry {
            is_enabled: false,
            ..pattern_entry("*.tmp")
        }]);
        assert!(!scan_exclusions.excludes_file(Path::new("/scan/a.tmp")));
        assert!(scan_exclusions.clamscan_arguments().is_empty());
    }

    #[test]
    fn regex_metacharacters_in_names_are_literal() {
        let scan_exclusions = exclusions_of(&[pattern_entry("/scan/a+b (1).txt")]);
        assert!(scan_exclusions.excludes_file(Path::new("/scan/a+b (1).txt")));
        assert!(!scan_exclusions.excludes_file(Path::new("/scan/aab (1).txt")));
    }

    #[test]
    fn character_classes_follow_glob_rules() {
        let scan_exclusions = exclusions_of(&[pattern_entry("sample[!a].txt")]);
        assert!(scan_exclusions.excludes_file(Path::new("/scan/sampleb.txt")));
        assert!(!scan_exclusions.excludes_file(Path::new("/scan/samplea.txt")));
        let unterminated = exclusions_of(&[pattern_entry("sample[a.txt")]);
        assert!(unterminated.excludes_file(Path::new("/scan/sample[a.txt")));
    }

    #[test]
    fn clamscan_receives_the_same_expressions() {
        let arguments =
            exclusions_of(&[directory_entry("build"), pattern_entry("*.tmp")]).clamscan_arguments();
        assert_eq!(
            arguments,
            vec![
                OsString::from("--exclude-dir=(^|/)build(/|$)"),
                OsString::from("--exclude=(^|/).*\\.tmp$"),
            ]
        );
    }
}

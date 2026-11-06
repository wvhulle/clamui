use std::{
    fs, io,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use crate::protection_change_rules::ProtectionReduction;

pub const TRUSTED_FILES_NAME: &str = "lazaret-local.sfp";
pub const IGNORED_SIGNATURES_NAME: &str = "lazaret-local.ign2";
const TRUSTED_FILE_LABEL: &str = "Lazaret.TrustedFile";
const SHA256_HEX_LENGTH: usize = 64;
const SIGNATURE_NAME_LENGTHS: std::ops::RangeInclusive<usize> = 3..=200;
const UNOFFICIAL_SUFFIX: &str = ".UNOFFICIAL";
const ENGINE_HEURISTIC_PREFIXES: [&str; 2] = ["Heuristics.", "Heuristic."];
const WORLD_READABLE_MODE: u32 = 0o644;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustRequest {
    TrustFile { sha256_hex: String, file_size: u64 },
    IgnoreSignature { signature_name: String },
    ForgetTrustedFile { sha256_hex: String },
    StopIgnoringSignature { signature_name: String },
}

#[derive(Debug, thiserror::Error)]
pub enum TrustRefusal {
    #[error("the SHA-256 hash must be 64 hexadecimal characters")]
    HashMalformed,
    #[error("an empty file can't be trusted")]
    EmptyFile,
    #[error("the signature name may only hold letters, digits, dots, dashes and underscores")]
    SignatureNameMalformed,
    #[error(
        "{0} is an engine heuristic that matches many unrelated files; trust the file by its hash \
         instead"
    )]
    HeuristicSignature(String),
    #[error("the trust list could not be updated: {0}")]
    FilesUnavailable(#[from] io::Error),
}

pub fn validated_sha256(hash_text: &str) -> Result<String, TrustRefusal> {
    let hash_text = hash_text.trim();
    if hash_text.len() == SHA256_HEX_LENGTH
        && hash_text
            .bytes()
            .all(|hash_byte| hash_byte.is_ascii_hexdigit())
    {
        Ok(hash_text.to_ascii_lowercase())
    } else {
        Err(TrustRefusal::HashMalformed)
    }
}

pub fn validated_signature_name(name_text: &str) -> Result<String, TrustRefusal> {
    let signature_name = name_text
        .trim()
        .strip_suffix(UNOFFICIAL_SUFFIX)
        .unwrap_or(name_text.trim());
    let well_formed = SIGNATURE_NAME_LENGTHS.contains(&signature_name.len())
        && signature_name
            .bytes()
            .all(|name_byte| name_byte.is_ascii_alphanumeric() || b"._-".contains(&name_byte))
        && signature_name
            .bytes()
            .next()
            .is_some_and(|first_byte| first_byte.is_ascii_alphanumeric())
        && !signature_name.contains("..");
    if !well_formed {
        return Err(TrustRefusal::SignatureNameMalformed);
    }
    if ENGINE_HEURISTIC_PREFIXES
        .iter()
        .any(|heuristic_prefix| signature_name.starts_with(heuristic_prefix))
    {
        return Err(TrustRefusal::HeuristicSignature(signature_name.to_owned()));
    }
    Ok(signature_name.to_owned())
}

pub fn validated_request(trust_request: TrustRequest) -> Result<TrustRequest, TrustRefusal> {
    Ok(match trust_request {
        TrustRequest::TrustFile {
            sha256_hex,
            file_size,
        } => {
            if file_size == 0 {
                return Err(TrustRefusal::EmptyFile);
            }
            TrustRequest::TrustFile {
                sha256_hex: validated_sha256(&sha256_hex)?,
                file_size,
            }
        }
        TrustRequest::IgnoreSignature { signature_name } => TrustRequest::IgnoreSignature {
            signature_name: validated_signature_name(&signature_name)?,
        },
        TrustRequest::ForgetTrustedFile { sha256_hex } => TrustRequest::ForgetTrustedFile {
            sha256_hex: validated_sha256(&sha256_hex)?,
        },
        TrustRequest::StopIgnoringSignature { signature_name } => {
            TrustRequest::StopIgnoringSignature {
                signature_name: validated_signature_name(&signature_name)?,
            }
        }
    })
}

pub fn request_summary(trust_request: &TrustRequest) -> String {
    match trust_request {
        TrustRequest::TrustFile {
            sha256_hex,
            file_size,
        } => format!("trust the file with SHA-256 {sha256_hex} ({file_size} bytes)"),
        TrustRequest::IgnoreSignature { signature_name } => {
            format!("ignore every detection named {signature_name}")
        }
        TrustRequest::ForgetTrustedFile { sha256_hex } => {
            format!("stop trusting the file with SHA-256 {sha256_hex}")
        }
        TrustRequest::StopIgnoringSignature { signature_name } => {
            format!("report detections named {signature_name} again")
        }
    }
}

pub const fn request_action_name(trust_request: &TrustRequest) -> &'static str {
    match trust_request {
        TrustRequest::TrustFile { .. } => "trust-file",
        TrustRequest::IgnoreSignature { .. } => "ignore-signature",
        TrustRequest::ForgetTrustedFile { .. } => "forget-trusted-file",
        TrustRequest::StopIgnoringSignature { .. } => "stop-ignoring-signature",
    }
}

pub const fn request_protection_reduction(trust_request: &TrustRequest) -> ProtectionReduction {
    match trust_request {
        TrustRequest::TrustFile { .. } | TrustRequest::IgnoreSignature { .. } => {
            ProtectionReduction::DetectionTrusted
        }
        TrustRequest::ForgetTrustedFile { .. } | TrustRequest::StopIgnoringSignature { .. } => {
            ProtectionReduction::NoReduction
        }
    }
}

fn list_lines(list_text: &str) -> impl Iterator<Item = &str> {
    list_text
        .lines()
        .map(str::trim)
        .filter(|list_line| !list_line.is_empty() && !list_line.starts_with('#'))
}

fn trusted_hash_of_line(list_line: &str) -> &str {
    list_line.split(':').next().unwrap_or_default()
}

fn is_trusted_file_line(list_line: &str) -> bool {
    let mut line_fields = list_line.split(':');
    matches!(
        (line_fields.next(), line_fields.next(), line_fields.next(), line_fields.next()),
        (Some(hash_field), Some(size_field), Some(label_field), None)
            if validated_sha256(hash_field).is_ok()
                && size_field.parse::<u64>().is_ok()
                && validated_signature_name(label_field).is_ok()
    )
}

fn line_fits_list(list_line: &str, trust_request: &TrustRequest) -> bool {
    match trust_request {
        TrustRequest::TrustFile { .. } | TrustRequest::ForgetTrustedFile { .. } => {
            is_trusted_file_line(list_line)
        }
        TrustRequest::IgnoreSignature { .. } | TrustRequest::StopIgnoringSignature { .. } => {
            validated_signature_name(list_line)
                .is_ok_and(|signature_name| signature_name == list_line)
        }
    }
}

fn lines_after_request(list_text: &str, trust_request: &TrustRequest) -> String {
    let kept_lines = list_lines(list_text)
        .filter(|list_line| line_fits_list(list_line, trust_request))
        .filter(|list_line| match trust_request {
            TrustRequest::TrustFile { sha256_hex, .. }
            | TrustRequest::ForgetTrustedFile { sha256_hex } => {
                !trusted_hash_of_line(list_line).eq_ignore_ascii_case(sha256_hex)
            }
            TrustRequest::IgnoreSignature { signature_name }
            | TrustRequest::StopIgnoringSignature { signature_name } => list_line != signature_name,
        });
    let added_line = match trust_request {
        TrustRequest::TrustFile {
            sha256_hex,
            file_size,
        } => vec![format!("{sha256_hex}:{file_size}:{TRUSTED_FILE_LABEL}")],
        TrustRequest::IgnoreSignature { signature_name } => vec![signature_name.clone()],
        TrustRequest::ForgetTrustedFile { .. } | TrustRequest::StopIgnoringSignature { .. } => {
            Vec::new()
        }
    };
    kept_lines
        .map(str::to_owned)
        .chain(added_line)
        .map(|list_line| format!("{list_line}\n"))
        .collect()
}

pub fn list_file_for_request(database_directory: &Path, trust_request: &TrustRequest) -> PathBuf {
    database_directory.join(match trust_request {
        TrustRequest::TrustFile { .. } | TrustRequest::ForgetTrustedFile { .. } => {
            TRUSTED_FILES_NAME
        }
        TrustRequest::IgnoreSignature { .. } | TrustRequest::StopIgnoringSignature { .. } => {
            IGNORED_SIGNATURES_NAME
        }
    })
}

fn read_list_or_empty(list_path: &Path) -> io::Result<String> {
    let opened_list = rustix::fs::open(
        list_path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    );
    match opened_list {
        Ok(list_descriptor) => {
            let mut list_text = String::new();
            fs::File::from(list_descriptor).read_to_string(&mut list_text)?;
            Ok(list_text)
        }
        Err(rustix::io::Errno::NOENT) => Ok(String::new()),
        Err(rustix::io::Errno::LOOP) => Err(io::Error::other(format!(
            "{} is a symbolic link, which Lazaret never follows",
            list_path.display()
        ))),
        Err(open_failure) => Err(open_failure.into()),
    }
}

fn replace_list_file(list_path: &Path, list_text: &str) -> io::Result<()> {
    let list_directory = list_path
        .parent()
        .ok_or_else(|| io::Error::other("the trust list has no directory"))?;
    let mut staged_list = tempfile::Builder::new()
        .prefix(".lazaret-trust-")
        .suffix(".staged")
        .tempfile_in(list_directory)?;
    staged_list.write_all(list_text.as_bytes())?;
    staged_list.as_file().sync_all()?;
    fs::set_permissions(
        staged_list.path(),
        fs::Permissions::from_mode(WORLD_READABLE_MODE),
    )?;
    staged_list
        .persist(list_path)
        .map_err(|persist_failure| persist_failure.error)?;
    Ok(())
}

pub fn apply_trust_request(
    database_directory: &Path,
    trust_request: &TrustRequest,
) -> Result<(), TrustRefusal> {
    let list_path = list_file_for_request(database_directory, trust_request);
    let updated_list = lines_after_request(&read_list_or_empty(&list_path)?, trust_request);
    if updated_list.is_empty() {
        return match fs::remove_file(&list_path) {
            Ok(()) => Ok(()),
            Err(remove_failure) if remove_failure.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(remove_failure) => Err(remove_failure.into()),
        };
    }
    replace_list_file(&list_path, &updated_list)?;
    Ok(())
}

#[cfg(test)]
mod detection_trust_files_tests {
    use super::*;

    const EICAR_SHA256: &str = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";

    fn trust_eicar() -> TrustRequest {
        TrustRequest::TrustFile {
            sha256_hex: EICAR_SHA256.to_owned(),
            file_size: 68,
        }
    }

    #[test]
    fn hashes_are_normalized_and_malformed_ones_refused() {
        assert_eq!(
            validated_sha256(EICAR_SHA256).unwrap(),
            EICAR_SHA256.to_ascii_lowercase()
        );
        assert!(validated_sha256("abc").is_err());
        assert!(validated_sha256(&format!("{}\nx", &EICAR_SHA256[..63])).is_err());
    }

    #[test]
    fn signature_names_cannot_inject_lines_or_paths() {
        assert_eq!(
            validated_signature_name("Win.Trojan.Agent-123.UNOFFICIAL").unwrap(),
            "Win.Trojan.Agent-123"
        );
        [
            "Win.Trojan\nEicar",
            "../etc",
            "a b c",
            "-rf",
            "x",
            "Win..Trojan",
        ]
        .into_iter()
        .for_each(|unsafe_name| assert!(validated_signature_name(unsafe_name).is_err()));
    }

    #[test]
    fn engine_heuristics_must_be_trusted_by_hash() {
        assert!(matches!(
            validated_signature_name("Heuristics.Encrypted.Zip"),
            Err(TrustRefusal::HeuristicSignature(_))
        ));
    }

    #[test]
    fn empty_files_are_never_trusted() {
        assert!(matches!(
            validated_request(TrustRequest::TrustFile {
                sha256_hex: EICAR_SHA256.to_owned(),
                file_size: 0,
            }),
            Err(TrustRefusal::EmptyFile)
        ));
    }

    #[test]
    fn trusting_twice_keeps_one_line_and_forgetting_removes_the_file() {
        let database_directory = tempfile::tempdir().unwrap();
        let trust_request = validated_request(trust_eicar()).unwrap();
        apply_trust_request(database_directory.path(), &trust_request).unwrap();
        apply_trust_request(database_directory.path(), &trust_request).unwrap();
        let list_path = database_directory.path().join(TRUSTED_FILES_NAME);
        assert_eq!(
            fs::read_to_string(&list_path).unwrap(),
            format!(
                "{}:68:{TRUSTED_FILE_LABEL}\n",
                EICAR_SHA256.to_ascii_lowercase()
            )
        );
        assert_eq!(
            fs::metadata(&list_path).unwrap().permissions().mode() & 0o777,
            WORLD_READABLE_MODE
        );
        apply_trust_request(
            database_directory.path(),
            &TrustRequest::ForgetTrustedFile {
                sha256_hex: EICAR_SHA256.to_ascii_lowercase(),
            },
        )
        .unwrap();
        assert!(!list_path.exists());
    }

    #[test]
    fn ignoring_keeps_other_signatures() {
        let database_directory = tempfile::tempdir().unwrap();
        ["Win.Test.First", "Win.Test.Second"]
            .into_iter()
            .for_each(|signature_name| {
                apply_trust_request(
                    database_directory.path(),
                    &TrustRequest::IgnoreSignature {
                        signature_name: signature_name.to_owned(),
                    },
                )
                .unwrap();
            });
        apply_trust_request(
            database_directory.path(),
            &TrustRequest::StopIgnoringSignature {
                signature_name: "Win.Test.First".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(database_directory.path().join(IGNORED_SIGNATURES_NAME)).unwrap(),
            "Win.Test.Second\n"
        );
    }

    #[test]
    fn a_planted_symlink_in_place_of_the_list_is_neither_read_nor_written() {
        let database_directory = tempfile::tempdir().unwrap();
        let victim_file = database_directory.path().join("victim");
        fs::write(&victim_file, "secret:line\n").unwrap();
        std::os::unix::fs::symlink(
            &victim_file,
            database_directory.path().join(TRUSTED_FILES_NAME),
        )
        .unwrap();
        assert!(
            apply_trust_request(
                database_directory.path(),
                &validated_request(trust_eicar()).unwrap(),
            )
            .is_err()
        );
        assert_eq!(fs::read_to_string(&victim_file).unwrap(), "secret:line\n");
    }

    #[test]
    fn foreign_lines_in_the_list_are_dropped() {
        let database_directory = tempfile::tempdir().unwrap();
        fs::write(
            database_directory.path().join(IGNORED_SIGNATURES_NAME),
            "Win.Test.Kept\nroot:x:0:0:root:/root:/bin/sh\n",
        )
        .unwrap();
        apply_trust_request(
            database_directory.path(),
            &TrustRequest::IgnoreSignature {
                signature_name: "Win.Test.Added".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(database_directory.path().join(IGNORED_SIGNATURES_NAME)).unwrap(),
            "Win.Test.Kept\nWin.Test.Added\n"
        );
    }
}

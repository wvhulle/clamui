use std::{env, fs, path::Path, process::Command};

use crate::{task_failure::TaskFailure, tool_commands::tool_stdout};

pub const APPLICATION_ID: &str = "page.codeberg.wvhulle.Lazaret";
const METAINFO_PATH: &str =
    "data/desktop_integration/page.codeberg.wvhulle.Lazaret.metainfo.xml.in";
const RELEASE_ELEMENT_PREFIX: &str = "<release version=";

fn stamped_metainfo(metainfo_text: &str, version: &str, release_date: &str) -> Option<String> {
    metainfo_text.contains(RELEASE_ELEMENT_PREFIX).then(|| {
        metainfo_text
            .split_inclusive('\n')
            .map(|metainfo_line| {
                let indentation_length = metainfo_line.len() - metainfo_line.trim_start().len();
                if metainfo_line
                    .trim_start()
                    .starts_with(RELEASE_ELEMENT_PREFIX)
                {
                    format!(
                        "{}<release version=\"{version}\" date=\"{release_date}\" \
                         type=\"stable\">\n",
                        &metainfo_line[..indentation_length]
                    )
                } else {
                    metainfo_line.to_owned()
                }
            })
            .collect()
    })
}

fn stamp_metainfo_with_release_tag(release_tag: &str) -> Result<(), TaskFailure> {
    let metainfo_path = Path::new(METAINFO_PATH);
    let metainfo_text = fs::read_to_string(metainfo_path)?;
    let version = release_tag.strip_prefix('v').unwrap_or(release_tag);
    let release_date = tool_stdout("date", Command::new("date").args(["--utc", "+%F"]))?;
    let stamped_text = stamped_metainfo(&metainfo_text, version, release_date.trim()).ok_or(
        TaskFailure::MetainfoReleaseMissing {
            metainfo_path: METAINFO_PATH,
        },
    )?;
    fs::write(metainfo_path, stamped_text)?;
    Ok(())
}

pub fn stamp_metainfo_for_ci_release() -> Result<(), TaskFailure> {
    match env::var("CI_COMMIT_TAG")
        .ok()
        .filter(|release_tag| !release_tag.is_empty())
    {
        Some(release_tag) => stamp_metainfo_with_release_tag(&release_tag),
        None => Ok(()),
    }
}

#[cfg(test)]
mod metainfo_release_stamp_tests {
    use super::*;

    #[test]
    fn stamps_version_and_date_keeping_other_lines() {
        let metainfo_text = "  <releases>\n    <release version=\"0.1.0\" date=\"2026-11-02\" \
                             type=\"stable\">\n      <description/>\n";
        assert_eq!(
            stamped_metainfo(metainfo_text, "0.2.0", "2026-12-01").as_deref(),
            Some(
                "  <releases>\n    <release version=\"0.2.0\" date=\"2026-12-01\" \
                 type=\"stable\">\n      <description/>\n"
            )
        );
    }

    #[test]
    fn reports_missing_release_entry() {
        assert_eq!(
            stamped_metainfo("<releases/>\n", "0.2.0", "2026-12-01"),
            None
        );
    }
}

use std::{
    env, fs,
    io::Write,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{fixture_clamav_programs::FIXTURE_PROGRAM_NAMES, task_failure::TaskFailure};

const QUARANTINE_FIXTURE_NAME: &str = "0123456789abcdef_invoice.pdf.exe";
const SCAN_FIXTURE_NAMES: [&str; 3] = [
    "eicar-test.txt",
    "eicar-<b>markup<i>&name.txt",
    "report.pdf",
];

pub struct ScreenshotFixtures {
    pub scan_directory: PathBuf,
    pub search_path: std::ffi::OsString,
}

const HISTORY_SCHEMA: &str = include_str!("../../data/database-schemas/history.sql");
const QUARANTINE_SCHEMA: &str = include_str!("../../data/database-schemas/quarantine.sql");

fn sql_text_literal(literal_text: &str) -> String {
    format!("'{}'", literal_text.replace('\'', "''"))
}

fn quarantine_seed_sql(payload_path: &str) -> String {
    QUARANTINE_SCHEMA.to_owned()
        + &include_str!("../assets/quarantine-seed.sql")
            .replace("@PAYLOAD_PATH@", &sql_text_literal(payload_path))
}

fn seed_quarantine_database(session_root: &Path) -> Result<(), TaskFailure> {
    let application_data = session_root.join("data/lazaret");
    let quarantine_directory = application_data.join("quarantine");
    fs::create_dir_all(&quarantine_directory)?;
    let payload_path = quarantine_directory.join(QUARANTINE_FIXTURE_NAME);
    fs::write(&payload_path, b"fixture payload")?;
    let mut sqlite_process = Command::new("sqlite3")
        .arg(application_data.join("quarantine.db"))
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|start_failure| TaskFailure::ToolNotStarted {
            tool_name: "sqlite3",
            start_failure,
        })?;
    if let Some(mut sqlite_input) = sqlite_process.stdin.take() {
        sqlite_input.write_all(quarantine_seed_sql(&payload_path.to_string_lossy()).as_bytes())?;
    }
    let exit_status = sqlite_process.wait()?;
    if exit_status.success() {
        Ok(())
    } else {
        Err(TaskFailure::ToolFailed {
            tool_name: "sqlite3",
            exit_status,
        })
    }
}

fn seed_detection_history(session_root: &Path) -> Result<(), TaskFailure> {
    let application_data = session_root.join("data/lazaret");
    let downloads_directory = session_root.join("home/Downloads");
    fs::create_dir_all(&downloads_directory)?;
    let unresolved_path = downloads_directory.join("invoice.pdf.exe");
    let scheduled_path = downloads_directory.join("setup-helper.bin");
    fs::write(&unresolved_path, b"fixture")?;
    fs::write(&scheduled_path, b"fixture")?;
    let mut sqlite_process = Command::new("sqlite3")
        .arg(application_data.join("history.db"))
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|start_failure| TaskFailure::ToolNotStarted {
            tool_name: "sqlite3",
            start_failure,
        })?;
    if let Some(mut sqlite_input) = sqlite_process.stdin.take() {
        sqlite_input.write_all(HISTORY_SCHEMA.as_bytes())?;
        sqlite_input.write_all(
            include_str!("../assets/detections-seed.sql")
                .replace(
                    "@UNRESOLVED_PATH@",
                    &sql_text_literal(&unresolved_path.to_string_lossy()),
                )
                .replace(
                    "@SCHEDULED_PATH@",
                    &sql_text_literal(&scheduled_path.to_string_lossy()),
                )
                .as_bytes(),
        )?;
    }
    let exit_status = sqlite_process.wait()?;
    if exit_status.success() {
        Ok(())
    } else {
        Err(TaskFailure::ToolFailed {
            tool_name: "sqlite3",
            exit_status,
        })
    }
}

const INSTALLED_FIXTURE_DIRECTORY_VARIABLE: &str = "LAZARET_FIXTURE_PROGRAM_DIRECTORY";

fn fixture_program_directory(session_root: &Path) -> Result<PathBuf, TaskFailure> {
    env::var_os(INSTALLED_FIXTURE_DIRECTORY_VARIABLE).map_or_else(
        || install_fixture_programs(session_root),
        |installed_directory| Ok(PathBuf::from(installed_directory)),
    )
}

fn install_fixture_programs(session_root: &Path) -> Result<PathBuf, TaskFailure> {
    let fixture_directory = session_root.join("fixture-programs");
    fs::create_dir_all(&fixture_directory)?;
    let xtask_executable = env::current_exe()?;
    FIXTURE_PROGRAM_NAMES.iter().try_for_each(|program_name| {
        symlink(&xtask_executable, fixture_directory.join(program_name))
    })?;
    Ok(fixture_directory)
}

pub fn prepare_screenshot_fixtures(session_root: &Path) -> Result<ScreenshotFixtures, TaskFailure> {
    seed_quarantine_database(session_root)?;
    seed_detection_history(session_root)?;
    let scan_directory = session_root.join("scan");
    fs::create_dir_all(&scan_directory)?;
    SCAN_FIXTURE_NAMES
        .iter()
        .try_for_each(|fixture_name| fs::write(scan_directory.join(fixture_name), b"fixture"))?;
    let fixture_directory = fixture_program_directory(session_root)?;
    let inherited_paths = env::var_os("PATH").unwrap_or_default();
    let search_path = env::join_paths(
        std::iter::once(fixture_directory).chain(env::split_paths(&inherited_paths)),
    )
    .unwrap_or(inherited_paths);
    Ok(ScreenshotFixtures {
        scan_directory,
        search_path,
    })
}

#[cfg(test)]
mod screenshot_fixtures_tests {
    use super::*;

    #[test]
    fn sql_literals_escape_single_quotes() {
        assert_eq!(sql_text_literal("/tmp/it's"), "'/tmp/it''s'");
    }

    #[test]
    fn scan_fixtures_exercise_detection_and_markup_escaping() {
        assert!(
            SCAN_FIXTURE_NAMES
                .iter()
                .any(|fixture_name| fixture_name.contains("<b>"))
        );
        assert!(
            SCAN_FIXTURE_NAMES
                .iter()
                .any(|fixture_name| !fixture_name.contains("eicar"))
        );
    }
}

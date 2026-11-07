use std::{
    env, fs,
    io::Write,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{
    embedded_migration_lists::{EmbeddedMigration, LAZARET_MIGRATIONS},
    fixture_clamav_programs::FIXTURE_PROGRAM_NAMES,
    task_failure::TaskFailure,
};

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

fn sql_identifier(identifier_text: &str) -> String {
    format!("\"{}\"", identifier_text.replace('"', "\"\""))
}

fn versioned_schema_sql(ordered_migrations: &[EmbeddedMigration]) -> String {
    ordered_migrations
        .iter()
        .zip(1..)
        .map(|(embedded_migration, reached_version)| {
            let savepoint_name = sql_identifier(embedded_migration.migration_name);
            format!(
                "SAVEPOINT {savepoint_name};\n{}\nPRAGMA user_version = \
                 {reached_version};\nRELEASE {savepoint_name};\n",
                embedded_migration.migration_sql
            )
        })
        .collect()
}

fn sql_text_literal(literal_text: &str) -> String {
    format!("'{}'", literal_text.replace('\'', "''"))
}

struct SeededFixturePaths {
    payload_path: PathBuf,
    unresolved_path: PathBuf,
    scheduled_path: PathBuf,
}

fn fixture_database_sql(seeded_paths: &SeededFixturePaths) -> String {
    versioned_schema_sql(LAZARET_MIGRATIONS)
        + &include_str!("../assets/quarantine-seed.sql").replace(
            "@PAYLOAD_PATH@",
            &sql_text_literal(&seeded_paths.payload_path.to_string_lossy()),
        )
        + &include_str!("../assets/detections-seed.sql")
            .replace(
                "@UNRESOLVED_PATH@",
                &sql_text_literal(&seeded_paths.unresolved_path.to_string_lossy()),
            )
            .replace(
                "@SCHEDULED_PATH@",
                &sql_text_literal(&seeded_paths.scheduled_path.to_string_lossy()),
            )
}

fn seed_lazaret_database(session_root: &Path) -> Result<(), TaskFailure> {
    let application_data = session_root.join("data/lazaret");
    let quarantine_directory = application_data.join("quarantine");
    fs::create_dir_all(&quarantine_directory)?;
    let downloads_directory = session_root.join("home/Downloads");
    fs::create_dir_all(&downloads_directory)?;
    let seeded_paths = SeededFixturePaths {
        payload_path: quarantine_directory.join(QUARANTINE_FIXTURE_NAME),
        unresolved_path: downloads_directory.join("invoice.pdf.exe"),
        scheduled_path: downloads_directory.join("setup-helper.bin"),
    };
    fs::write(&seeded_paths.payload_path, b"fixture payload")?;
    fs::write(&seeded_paths.unresolved_path, b"fixture")?;
    fs::write(&seeded_paths.scheduled_path, b"fixture")?;
    let mut sqlite_process = Command::new("sqlite3")
        .arg(application_data.join("lazaret.db"))
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|start_failure| TaskFailure::ToolNotStarted {
            tool_name: "sqlite3",
            start_failure,
        })?;
    if let Some(mut sqlite_input) = sqlite_process.stdin.take() {
        sqlite_input.write_all(fixture_database_sql(&seeded_paths).as_bytes())?;
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
    seed_lazaret_database(session_root)?;
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
    fn the_fixture_database_reaches_the_latest_migration_version() {
        let fixture_sql = fixture_database_sql(&SeededFixturePaths {
            payload_path: PathBuf::from("/data/quarantine/payload"),
            unresolved_path: PathBuf::from("/home/Downloads/invoice.pdf.exe"),
            scheduled_path: PathBuf::from("/home/Downloads/setup-helper.bin"),
        });
        assert!(fixture_sql.contains("CREATE TABLE activity_entries"));
        assert!(fixture_sql.contains("CREATE TABLE file_contents"));
        assert!(fixture_sql.contains(&format!(
            "PRAGMA user_version = {};\nRELEASE \"0001_baseline\";\n",
            LAZARET_MIGRATIONS.len()
        )));
        assert!(!fixture_sql.contains("@PAYLOAD_PATH@"));
    }

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

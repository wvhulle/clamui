use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

const READINESS_ARGUMENT: &str = "--fixture-readiness-probe";
const READINESS_TIMEOUT: Duration = Duration::from_secs(10);
const READINESS_RETRY_DELAY: Duration = Duration::from_millis(10);

pub fn write_executable_fixture(fixture_path: &Path, fixture_script: &str) {
    let script_body = fixture_script
        .strip_prefix("#!/bin/sh\n")
        .expect("fixture scripts start with a shebang");
    let readiness_guarded_script =
        format!("#!/bin/sh\n[ \"$1\" = \"{READINESS_ARGUMENT}\" ] && exit 0\n{script_body}");
    fs::write(fixture_path, readiness_guarded_script).expect("fixture script");
    fs::set_permissions(fixture_path, fs::Permissions::from_mode(0o700)).expect("fixture mode");
    wait_until_fixture_executes(fixture_path);
}

fn wait_until_fixture_executes(fixture_path: &Path) {
    let started_at = Instant::now();
    loop {
        match Command::new(fixture_path)
            .arg(READINESS_ARGUMENT)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Err(spawn_failure) if spawn_failure.kind() == io::ErrorKind::ExecutableFileBusy => {
                assert!(
                    started_at.elapsed() < READINESS_TIMEOUT,
                    "fixture stayed busy: {}",
                    fixture_path.display()
                );
                sleep(READINESS_RETRY_DELAY);
            }
            Err(spawn_failure) => panic!("fixture failed to start: {spawn_failure}"),
            Ok(_readiness_status) => return,
        }
    }
}

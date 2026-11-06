use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;

use crate::{scene_capture_failure::SceneCaptureFailure, virtual_pointer_input::ScreenSize};

const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(200);
const READINESS_TIMEOUT: Duration = Duration::from_secs(30);
const SWAY_BASE_CONFIG: &str = "default_border none\nfocus_follows_mouse no\n";
const GTK_SETTINGS: &str = "[Settings]\ngtk-enable-animations=false\n";
const FIXED_ENVIRONMENT: [FixedVariable; 9] = [
    FixedVariable::new("WLR_BACKENDS", "headless"),
    FixedVariable::new("WLR_RENDERER", "pixman"),
    FixedVariable::new("WLR_LIBINPUT_NO_DEVICES", "1"),
    FixedVariable::new("GDK_BACKEND", "wayland"),
    FixedVariable::new("GSK_RENDERER", "cairo"),
    FixedVariable::new("GTK_USE_PORTAL", "0"),
    FixedVariable::new("ADW_DEBUG_COLOR_SCHEME", "prefer-dark"),
    FixedVariable::new("GTK_A11Y", "atspi"),
    FixedVariable::new("LANG", "C.UTF-8"),
];

fn isolated_bus_config(bus_address: &str) -> String {
    include_str!("../assets/isolated-session-bus.conf").replace("@BUS_ADDRESS@", bus_address)
}

fn start_isolated_bus(session_root: &Path) -> Result<Child, SceneCaptureFailure> {
    let bus_socket = session_subdirectory(session_root, "runtime/bus");
    let bus_config_path = session_subdirectory(session_root, "bus.conf");
    fs::write(
        &bus_config_path,
        isolated_bus_config(&session_bus_address(session_root)),
    )?;
    let bus_process = Command::new("dbus-daemon")
        .arg("--nofork")
        .arg(format!("--config-file={}", bus_config_path.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|start_failure| SceneCaptureFailure::ToolNotStarted {
            tool_name: "dbus-daemon",
            start_failure,
        })?;
    let waiting_since = Instant::now();
    while !bus_socket.exists() {
        if waiting_since.elapsed() > READINESS_TIMEOUT {
            return Err(SceneCaptureFailure::NeverReady {
                awaited_condition: "the isolated session bus",
            });
        }
        thread::sleep(READINESS_POLL_INTERVAL);
    }
    Ok(bus_process)
}

fn session_bus_address(session_root: &Path) -> String {
    format!(
        "unix:path={}",
        session_subdirectory(session_root, "runtime/bus").display()
    )
}

struct FixedVariable {
    variable_name: &'static str,
    variable_value: &'static str,
}

impl FixedVariable {
    const fn new(variable_name: &'static str, variable_value: &'static str) -> Self {
        Self {
            variable_name,
            variable_value,
        }
    }
}

pub struct HeadlessSwaySession {
    session_directory: TempDir,
    wayland_display: OsString,
    sway_process: Child,
    bus_process: Child,
    accessibility_bus_process: Child,
    accessibility_registry_process: Child,
    screen_size: ScreenSize,
}

fn accessibility_bus_is_published(session_bus_address: &str) -> bool {
    zbus::blocking::connection::Builder::address(session_bus_address)
        .and_then(zbus::blocking::connection::Builder::build)
        .and_then(|session_bus| {
            session_bus.call_method(
                Some("org.a11y.Bus"),
                "/org/a11y/bus",
                Some("org.a11y.Bus"),
                "GetAddress",
                &(),
            )
        })
        .is_ok()
}

fn start_accessibility_registry(session_root: &Path) -> Result<Child, SceneCaptureFailure> {
    let session_bus_address = session_bus_address(session_root);
    let waiting_since = Instant::now();
    while !accessibility_bus_is_published(&session_bus_address) {
        if waiting_since.elapsed() > READINESS_TIMEOUT {
            return Err(SceneCaptureFailure::NeverReady {
                awaited_condition: "the accessibility bus launcher",
            });
        }
        thread::sleep(READINESS_POLL_INTERVAL);
    }
    let mut registry_command = Command::new("at-spi2-registryd");
    apply_session_environment(session_root, &mut registry_command);
    registry_command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|start_failure| SceneCaptureFailure::ToolNotStarted {
            tool_name: "at-spi2-registryd",
            start_failure,
        })
}

fn sway_config(screen_size: ScreenSize) -> String {
    format!(
        "output * resolution {}x{} scale 1\n{SWAY_BASE_CONFIG}",
        screen_size.logical_width, screen_size.logical_height
    )
}

fn start_accessibility_bus(session_root: &Path) -> Result<Child, SceneCaptureFailure> {
    let mut launcher_command = Command::new("at-spi-bus-launcher");
    apply_session_environment(session_root, &mut launcher_command);
    launcher_command
        .arg("--launch-immediately")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|start_failure| SceneCaptureFailure::ToolNotStarted {
            tool_name: "at-spi-bus-launcher",
            start_failure,
        })
}

fn session_subdirectory(session_directory: &Path, subdirectory_name: &str) -> PathBuf {
    session_directory.join(subdirectory_name)
}

fn apply_session_environment(session_directory: &Path, session_command: &mut Command) {
    session_command
        .env_remove("DISPLAY")
        .env_remove("SWAYSOCK")
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            session_bus_address(session_directory),
        )
        .env(
            "DBUS_SYSTEM_BUS_ADDRESS",
            session_bus_address(session_directory),
        )
        .env("HOME", session_subdirectory(session_directory, "home"))
        .env(
            "XDG_RUNTIME_DIR",
            session_subdirectory(session_directory, "runtime"),
        )
        .env(
            "XDG_CONFIG_HOME",
            session_subdirectory(session_directory, "config"),
        )
        .env(
            "XDG_DATA_HOME",
            session_subdirectory(session_directory, "data"),
        )
        .env(
            "XDG_CACHE_HOME",
            session_subdirectory(session_directory, "cache"),
        );
    FIXED_ENVIRONMENT.iter().for_each(|fixed_variable| {
        session_command.env(fixed_variable.variable_name, fixed_variable.variable_value);
    });
}

fn find_wayland_display(runtime_directory: &Path) -> Option<OsString> {
    fs::read_dir(runtime_directory)
        .ok()?
        .filter_map(Result::ok)
        .map(|runtime_entry| runtime_entry.file_name())
        .find(|entry_name| {
            let entry_text = entry_name.to_string_lossy();
            entry_text.starts_with("wayland-") && !entry_text.ends_with(".lock")
        })
}

fn wait_for_wayland_display(
    runtime_directory: &Path,
    sway_process: &mut Child,
) -> Result<OsString, SceneCaptureFailure> {
    let waiting_since = Instant::now();
    loop {
        if let Some(wayland_display) = find_wayland_display(runtime_directory) {
            return Ok(wayland_display);
        }
        if let Some(exit_status) = sway_process.try_wait()? {
            return Err(SceneCaptureFailure::ToolFailed {
                tool_name: "sway",
                exit_status,
            });
        }
        if waiting_since.elapsed() > READINESS_TIMEOUT {
            return Err(SceneCaptureFailure::NeverReady {
                awaited_condition: "the headless sway display",
            });
        }
        thread::sleep(READINESS_POLL_INTERVAL);
    }
}

impl HeadlessSwaySession {
    pub fn start_session(screen_size: ScreenSize) -> Result<Self, SceneCaptureFailure> {
        let session_directory = tempfile::tempdir()?;
        let session_root = session_directory.path();
        ["home", "cache", "data", "config/gtk-4.0"]
            .iter()
            .try_for_each(|subdirectory_name| {
                fs::create_dir_all(session_subdirectory(session_root, subdirectory_name))
            })?;
        let runtime_directory = session_subdirectory(session_root, "runtime");
        fs::create_dir_all(&runtime_directory)?;
        fs::set_permissions(&runtime_directory, fs::Permissions::from_mode(0o700))?;
        fs::write(
            session_subdirectory(session_root, "config/gtk-4.0/settings.ini"),
            GTK_SETTINGS,
        )?;
        let sway_config_path = session_subdirectory(session_root, "sway_config");
        fs::write(&sway_config_path, sway_config(screen_size))?;

        let bus_process = start_isolated_bus(session_root)?;
        let accessibility_bus_process = start_accessibility_bus(session_root)?;
        let accessibility_registry_process = start_accessibility_registry(session_root)?;
        let sway_log_path = session_subdirectory(session_root, "sway.log");
        let mut sway_command = Command::new("sway");
        apply_session_environment(session_root, &mut sway_command);
        let mut sway_process = sway_command
            .env_remove("WAYLAND_DISPLAY")
            .arg("--config")
            .arg(&sway_config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(File::create(&sway_log_path)?)
            .spawn()
            .map_err(|start_failure| SceneCaptureFailure::ToolNotStarted {
                tool_name: "sway",
                start_failure,
            })?;
        let wayland_display = wait_for_wayland_display(&runtime_directory, &mut sway_process)
            .inspect_err(|_startup_failure| {
                let sway_log = fs::read_to_string(&sway_log_path).unwrap_or_default();
                eprintln!("{sway_log}");
            })?;
        Ok(Self {
            session_directory,
            wayland_display,
            sway_process,
            bus_process,
            accessibility_bus_process,
            accessibility_registry_process,
            screen_size,
        })
    }

    pub const fn screen_size(&self) -> ScreenSize {
        self.screen_size
    }

    pub fn session_root(&self) -> &Path {
        self.session_directory.path()
    }

    pub fn bus_address(&self) -> String {
        session_bus_address(self.session_root())
    }

    pub fn wayland_socket_path(&self) -> PathBuf {
        session_subdirectory(self.session_root(), "runtime").join(&self.wayland_display)
    }

    pub fn session_command(&self, program_name: impl AsRef<OsStr>) -> Command {
        let mut session_command = Command::new(program_name);
        apply_session_environment(self.session_root(), &mut session_command);
        session_command.env("WAYLAND_DISPLAY", &self.wayland_display);
        session_command
    }
}

impl Drop for HeadlessSwaySession {
    fn drop(&mut self) {
        let _already_exited = self.sway_process.kill();
        let _exit_status = self.sway_process.wait();
        let _registry_already_exited = self.accessibility_registry_process.kill();
        let _registry_exit_status = self.accessibility_registry_process.wait();
        let _launcher_already_exited = self.accessibility_bus_process.kill();
        let _launcher_exit_status = self.accessibility_bus_process.wait();
        let _bus_already_exited = self.bus_process.kill();
        let _bus_exit_status = self.bus_process.wait();
    }
}

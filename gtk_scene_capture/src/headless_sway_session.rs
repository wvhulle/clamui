use std::{
    cell::{Cell, RefCell},
    ffi::{OsStr, OsString},
    fs::{self, File},
    io,
    os::unix::{fs::PermissionsExt, process::CommandExt},
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

struct SessionProcesses {
    started_processes: Vec<Child>,
}

impl SessionProcesses {
    const fn new() -> Self {
        Self {
            started_processes: Vec::new(),
        }
    }

    fn spawn_tied(
        &mut self,
        tool_name: &'static str,
        tool_command: &mut Command,
    ) -> Result<&mut Child, SceneCaptureFailure> {
        let started_process = die_with_parent(tool_command)
            .process_group(0)
            .spawn()
            .map_err(|start_failure| SceneCaptureFailure::ToolNotStarted {
                tool_name,
                start_failure,
            })?;
        self.started_processes.push(started_process);
        Ok(self
            .started_processes
            .last_mut()
            .expect("a process was just pushed"))
    }
}

impl Drop for SessionProcesses {
    fn drop(&mut self) {
        self.started_processes
            .iter_mut()
            .rev()
            .for_each(|started_process| {
                kill_process_group(started_process);
                let _already_exited = started_process.kill();
                let _exit_status = started_process.wait();
            });
    }
}

fn kill_process_group(started_process: &Child) {
    if let Ok(group_leader) = i32::try_from(started_process.id()) {
        unsafe {
            libc::kill(-group_leader, libc::SIGKILL);
        }
    }
}

fn die_with_parent(tool_command: &mut Command) -> &mut Command {
    unsafe {
        tool_command.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AccessibilityStack {
    NotStarted,
    Running,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IsolatedBus {
    SessionBus,
    AccessibilityBus,
}

impl IsolatedBus {
    const fn socket_name(self) -> &'static str {
        match self {
            Self::SessionBus => "runtime/bus",
            Self::AccessibilityBus => "runtime/accessibility-bus",
        }
    }

    const fn file_stem(self) -> &'static str {
        match self {
            Self::SessionBus => "session-bus",
            Self::AccessibilityBus => "accessibility-bus",
        }
    }

    const fn readiness_condition(self) -> &'static str {
        match self {
            Self::SessionBus => "the isolated session bus",
            Self::AccessibilityBus => "the isolated accessibility bus",
        }
    }

    fn bus_address(self, session_root: &Path) -> String {
        format!(
            "unix:path={}",
            session_subdirectory(session_root, self.socket_name()).display()
        )
    }
}

fn start_isolated_bus(
    session_root: &Path,
    isolated_bus: IsolatedBus,
    session_processes: &mut SessionProcesses,
) -> Result<(), SceneCaptureFailure> {
    let bus_socket = session_subdirectory(session_root, isolated_bus.socket_name());
    let bus_config_path =
        session_subdirectory(session_root, &format!("{}.conf", isolated_bus.file_stem()));
    fs::write(
        &bus_config_path,
        isolated_bus_config(&isolated_bus.bus_address(session_root)),
    )?;
    session_processes.spawn_tied(
        "dbus-daemon",
        Command::new("dbus-daemon")
            .arg("--nofork")
            .arg(format!("--config-file={}", bus_config_path.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(File::create(session_subdirectory(
                session_root,
                &format!("{}.log", isolated_bus.file_stem()),
            ))?),
    )?;
    let waiting_since = Instant::now();
    while !bus_socket.exists() {
        if waiting_since.elapsed() > READINESS_TIMEOUT {
            return Err(SceneCaptureFailure::NeverReady {
                awaited_condition: isolated_bus.readiness_condition(),
            });
        }
        thread::sleep(READINESS_POLL_INTERVAL);
    }
    Ok(())
}

fn session_bus_address(session_root: &Path) -> String {
    IsolatedBus::SessionBus.bus_address(session_root)
}

fn accessibility_bus_address(session_root: &Path) -> String {
    IsolatedBus::AccessibilityBus.bus_address(session_root)
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
    session_processes: RefCell<SessionProcesses>,
    accessibility_stack: Cell<AccessibilityStack>,
    session_directory: TempDir,
    wayland_display: OsString,
    screen_size: ScreenSize,
}

fn start_accessibility_registry(
    session_root: &Path,
    session_processes: &mut SessionProcesses,
) -> Result<(), SceneCaptureFailure> {
    let mut registry_command = Command::new("at-spi2-registryd");
    apply_session_environment(session_root, &mut registry_command);
    session_processes.spawn_tied(
        "at-spi2-registryd",
        registry_command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )?;
    Ok(())
}

fn sway_config(screen_size: ScreenSize) -> String {
    format!(
        "output * resolution {}x{} scale 1\n{SWAY_BASE_CONFIG}",
        screen_size.logical_width, screen_size.logical_height
    )
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
        .env(
            "AT_SPI_BUS_ADDRESS",
            accessibility_bus_address(session_directory),
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

        let mut session_processes = SessionProcesses::new();
        start_isolated_bus(
            session_root,
            IsolatedBus::SessionBus,
            &mut session_processes,
        )?;
        let sway_log_path = session_subdirectory(session_root, "sway.log");
        let mut sway_command = Command::new("sway");
        apply_session_environment(session_root, &mut sway_command);
        let sway_process = session_processes.spawn_tied(
            "sway",
            sway_command
                .env_remove("WAYLAND_DISPLAY")
                .arg("--config")
                .arg(&sway_config_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(File::create(&sway_log_path)?),
        )?;
        let wayland_display = wait_for_wayland_display(&runtime_directory, sway_process)
            .inspect_err(|_startup_failure| {
                let sway_log = fs::read_to_string(&sway_log_path).unwrap_or_default();
                eprintln!("{sway_log}");
            })?;
        Ok(Self {
            session_processes: RefCell::new(session_processes),
            accessibility_stack: Cell::new(AccessibilityStack::NotStarted),
            session_directory,
            wayland_display,
            screen_size,
        })
    }

    pub fn start_accessibility(&self) -> Result<(), SceneCaptureFailure> {
        if self.accessibility_stack.get() == AccessibilityStack::Running {
            return Ok(());
        }
        let mut session_processes = self.session_processes.borrow_mut();
        start_isolated_bus(
            self.session_root(),
            IsolatedBus::AccessibilityBus,
            &mut session_processes,
        )?;
        start_accessibility_registry(self.session_root(), &mut session_processes)?;
        self.accessibility_stack.set(AccessibilityStack::Running);
        Ok(())
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

    pub fn accessibility_bus_address(&self) -> String {
        accessibility_bus_address(self.session_root())
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

use zbus::{proxy, zvariant::OwnedObjectPath};

pub type ExecCommandRecord = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

pub type UnitFileChange = (String, String, String);

#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
pub trait SystemdManager {
    fn load_unit(&self, unit_name: &str) -> zbus::Result<OwnedObjectPath>;

    fn subscribe(&self) -> zbus::Result<()>;

    fn reload(&self) -> zbus::Result<()>;

    fn start_unit(&self, unit_name: &str, job_mode: &str) -> zbus::Result<OwnedObjectPath>;

    fn stop_unit(&self, unit_name: &str, job_mode: &str) -> zbus::Result<OwnedObjectPath>;

    fn enable_unit_files(
        &self,
        unit_files: &[&str],
        runtime_only: bool,
        force_replace: bool,
    ) -> zbus::Result<(bool, Vec<UnitFileChange>)>;

    fn disable_unit_files(
        &self,
        unit_files: &[&str],
        runtime_only: bool,
    ) -> zbus::Result<Vec<UnitFileChange>>;

    #[zbus(signal)]
    fn job_removed(
        &self,
        job_id: u32,
        job_path: OwnedObjectPath,
        unit_name: String,
        job_result: String,
    ) -> zbus::Result<()>;

    #[zbus(property)]
    fn version(&self) -> zbus::Result<String>;
}

#[proxy(
    interface = "org.freedesktop.systemd1.Unit",
    default_service = "org.freedesktop.systemd1"
)]
pub trait SystemdUnit {
    #[zbus(property)]
    fn load_state(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn active_state(&self) -> zbus::Result<String>;
}

#[proxy(
    interface = "org.freedesktop.systemd1.Service",
    default_service = "org.freedesktop.systemd1"
)]
pub trait SystemdService {
    #[zbus(property)]
    fn result(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn exec_main_status(&self) -> zbus::Result<i32>;

    #[zbus(property)]
    fn exec_start(&self) -> zbus::Result<Vec<ExecCommandRecord>>;
}

#[proxy(
    interface = "org.freedesktop.systemd1.Timer",
    default_service = "org.freedesktop.systemd1"
)]
pub trait SystemdTimer {
    #[zbus(property, name = "NextElapseUSecRealtime")]
    fn next_elapse_microseconds(&self) -> zbus::Result<u64>;

    #[zbus(property, name = "LastTriggerUSec")]
    fn last_trigger_microseconds(&self) -> zbus::Result<u64>;
}

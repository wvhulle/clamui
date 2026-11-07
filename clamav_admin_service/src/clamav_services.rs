use std::{io, path::Path};

use futures::StreamExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use zbus::{proxy, zvariant::OwnedObjectPath};

const PING_REQUEST: &[u8] = b"zPING\0";
const RELOAD_REQUEST: &[u8] = b"zRELOAD\0";
const RELOADING_ANSWER_PREFIX: &[u8] = b"RELOADING";
const PONG_ANSWER_PREFIX: &[u8] = b"PONG";
const DAEMON_UNIT: &str = "clamav-daemon.service";
const ON_ACCESS_UNIT: &str = "clamav-clamonacc.service";
const SUCCESSFUL_JOB_RESULT: &str = "done";
const REPLACING_JOB_MODE: &str = "replace";

#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
trait SystemdManager {
    fn load_unit(&self, unit_name: &str) -> zbus::Result<OwnedObjectPath>;

    fn subscribe(&self) -> zbus::Result<()>;

    fn restart_unit(&self, unit_name: &str, job_mode: &str) -> zbus::Result<OwnedObjectPath>;

    fn reset_failed_unit(&self, unit_name: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn job_removed(
        &self,
        job_id: u32,
        job_path: OwnedObjectPath,
        unit_name: String,
        job_result: String,
    ) -> zbus::Result<()>;
}

#[proxy(
    interface = "org.freedesktop.systemd1.Unit",
    default_service = "org.freedesktop.systemd1"
)]
trait SystemdUnit {
    #[zbus(property)]
    fn load_state(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn active_state(&self) -> zbus::Result<String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServicesReadiness {
    ServicesReady,
    ServiceNotReady { unit_name: &'static str },
}

pub trait ClamavServices {
    async fn restart_until_ready(&mut self) -> io::Result<ServicesReadiness>;
}

pub struct SystemClamavServices<'socket> {
    pub local_socket: &'socket Path,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnitActivity {
    RunningOrStarting,
    StoppedOnPurpose,
    NotInstalled,
}

fn unit_activity(load_state: &str, active_state: &str) -> UnitActivity {
    match (load_state, active_state) {
        ("loaded", "active" | "activating" | "failed" | "reloading") => {
            UnitActivity::RunningOrStarting
        }
        ("loaded", _stopped_state) => UnitActivity::StoppedOnPurpose,
        (_missing_state, _any_state) => UnitActivity::NotInstalled,
    }
}

const fn unit_has_stopped(active_state: &str) -> bool {
    matches!(
        active_state.as_bytes(),
        b"failed" | b"inactive" | b"deactivating"
    )
}

fn dbus_failure(bus_failure: zbus::Error) -> io::Error {
    io::Error::other(bus_failure)
}

async fn clamd_answer(local_socket: &Path, clamd_request: &[u8]) -> io::Result<Vec<u8>> {
    let mut socket_stream = UnixStream::connect(local_socket).await?;
    socket_stream.write_all(clamd_request).await?;
    let mut answer_bytes = Vec::new();
    socket_stream.read_to_end(&mut answer_bytes).await?;
    Ok(answer_bytes)
}

pub async fn clamd_reloads_signatures(local_socket: &Path) -> bool {
    clamd_answer(local_socket, RELOAD_REQUEST)
        .await
        .is_ok_and(|answer_bytes| answer_bytes.starts_with(RELOADING_ANSWER_PREFIX))
}

async fn restart_unit_and_wait_for_job(
    systemd_manager: &SystemdManagerProxy<'_>,
    unit_name: &'static str,
) -> io::Result<ServicesReadiness> {
    let mut removed_jobs = systemd_manager
        .receive_job_removed()
        .await
        .map_err(dbus_failure)?;
    systemd_manager
        .reset_failed_unit(unit_name)
        .await
        .map_err(dbus_failure)?;
    let restart_job = systemd_manager
        .restart_unit(unit_name, REPLACING_JOB_MODE)
        .await
        .map_err(dbus_failure)?;
    while let Some(removed_job) = removed_jobs.next().await {
        let job_arguments = removed_job.args().map_err(dbus_failure)?;
        if job_arguments.job_path == restart_job {
            return Ok(if job_arguments.job_result == SUCCESSFUL_JOB_RESULT {
                ServicesReadiness::ServicesReady
            } else {
                ServicesReadiness::ServiceNotReady { unit_name }
            });
        }
    }
    Err(io::Error::other("systemd stopped reporting finished jobs"))
}

async fn unit_stops(unit_proxy: &SystemdUnitProxy<'_>) -> io::Result<()> {
    let mut state_changes = unit_proxy.receive_active_state_changed().await;
    if unit_has_stopped(&unit_proxy.active_state().await.map_err(dbus_failure)?) {
        return Ok(());
    }
    while let Some(state_change) = state_changes.next().await {
        if unit_has_stopped(&state_change.get().await.map_err(dbus_failure)?) {
            return Ok(());
        }
    }
    Err(io::Error::other("systemd stopped reporting unit states"))
}

async fn clamd_answers_ping_unless_unit_stops(
    local_socket: &Path,
    daemon_proxy: &SystemdUnitProxy<'_>,
) -> io::Result<ServicesReadiness> {
    tokio::select! {
        ping_answer = clamd_answer(local_socket, PING_REQUEST) => Ok(
            if ping_answer.is_ok_and(|answer_bytes| answer_bytes.starts_with(PONG_ANSWER_PREFIX)) {
                ServicesReadiness::ServicesReady
            } else {
                ServicesReadiness::ServiceNotReady { unit_name: DAEMON_UNIT }
            }
        ),
        unit_stopped = unit_stops(daemon_proxy) => unit_stopped.map(|()| {
            ServicesReadiness::ServiceNotReady { unit_name: DAEMON_UNIT }
        }),
    }
}

async fn unit_proxy_for<'bus>(
    bus_connection: &'bus zbus::Connection,
    systemd_manager: &SystemdManagerProxy<'_>,
    unit_name: &str,
) -> io::Result<SystemdUnitProxy<'bus>> {
    let unit_path = systemd_manager
        .load_unit(unit_name)
        .await
        .map_err(dbus_failure)?;
    SystemdUnitProxy::builder(bus_connection)
        .path(unit_path)
        .map_err(dbus_failure)?
        .build()
        .await
        .map_err(dbus_failure)
}

async fn current_activity(unit_proxy: &SystemdUnitProxy<'_>) -> io::Result<UnitActivity> {
    Ok(unit_activity(
        &unit_proxy.load_state().await.map_err(dbus_failure)?,
        &unit_proxy.active_state().await.map_err(dbus_failure)?,
    ))
}

impl ClamavServices for SystemClamavServices<'_> {
    async fn restart_until_ready(&mut self) -> io::Result<ServicesReadiness> {
        let bus_connection = zbus::Connection::system().await.map_err(dbus_failure)?;
        let systemd_manager = SystemdManagerProxy::new(&bus_connection)
            .await
            .map_err(dbus_failure)?;
        systemd_manager.subscribe().await.map_err(dbus_failure)?;
        let daemon_proxy = unit_proxy_for(&bus_connection, &systemd_manager, DAEMON_UNIT).await?;
        let on_access_proxy =
            unit_proxy_for(&bus_connection, &systemd_manager, ON_ACCESS_UNIT).await?;
        let on_access_activity = current_activity(&on_access_proxy).await?;
        if current_activity(&daemon_proxy).await? == UnitActivity::RunningOrStarting {
            let daemon_readiness =
                restart_unit_and_wait_for_job(&systemd_manager, DAEMON_UNIT).await?;
            if daemon_readiness != ServicesReadiness::ServicesReady {
                return Ok(daemon_readiness);
            }
            let daemon_readiness =
                clamd_answers_ping_unless_unit_stops(self.local_socket, &daemon_proxy).await?;
            if daemon_readiness != ServicesReadiness::ServicesReady {
                return Ok(daemon_readiness);
            }
        }
        if on_access_activity == UnitActivity::RunningOrStarting {
            return restart_unit_and_wait_for_job(&systemd_manager, ON_ACCESS_UNIT).await;
        }
        Ok(ServicesReadiness::ServicesReady)
    }
}

#[cfg(test)]
mod clamav_services_tests {
    use super::*;

    #[test]
    fn a_failed_unit_is_restarted_but_one_stopped_on_purpose_is_left_alone() {
        assert_eq!(
            unit_activity("loaded", "active"),
            UnitActivity::RunningOrStarting
        );
        assert_eq!(
            unit_activity("loaded", "failed"),
            UnitActivity::RunningOrStarting
        );
        assert_eq!(
            unit_activity("loaded", "inactive"),
            UnitActivity::StoppedOnPurpose
        );
    }

    #[test]
    fn only_loaded_units_are_restarted() {
        assert_eq!(
            unit_activity("not-found", "inactive"),
            UnitActivity::NotInstalled
        );
        assert_eq!(
            unit_activity("masked", "inactive"),
            UnitActivity::NotInstalled
        );
    }

    #[test]
    fn a_unit_that_failed_or_went_inactive_has_stopped() {
        assert!(unit_has_stopped("failed"));
        assert!(unit_has_stopped("inactive"));
        assert!(!unit_has_stopped("activating"));
        assert!(!unit_has_stopped("active"));
    }
}

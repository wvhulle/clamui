use futures::{
    Stream, StreamExt,
    future::{join_all, ready},
    stream::{self, BoxStream},
};
use jiff::Timestamp;
use tokio::sync::OnceCell;
use zbus::{Connection, proxy::MethodFlags, zvariant::OwnedObjectPath};

use crate::host_services::systemd_bus::systemd_unit_proxies::{
    ExecCommandRecord, SystemdManagerProxy, SystemdServiceProxy, SystemdTimerProxy,
    SystemdUnitProxy,
};

const SERVICE_SUCCESS_RESULT: &str = "success";
const JOB_DONE_RESULT: &str = "done";
const JOB_REPLACE_MODE: &str = "replace";
const START_UNIT_METHOD: &str = "StartUnit";
const ALREADY_SUBSCRIBED_FAILURE: &str = "org.freedesktop.systemd1.AlreadySubscribed";
const KILL_UNIT_METHOD: &str = "KillUnit";
const KILL_EVERY_PROCESS: &str = "all";

static SYSTEM_BUS_CONNECTION: OnceCell<Connection> = OnceCell::const_new();
static USER_BUS_CONNECTION: OnceCell<Connection> = OnceCell::const_new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnitActivity {
    UnitActive,
    UnitInactive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnitState {
    UnitLoaded(UnitActivity),
    UnitNotFound,
    SystemdUnavailable,
}

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum SystemdBusFailure {
    #[error("the systemd bus call failed: {0}")]
    BusCallFailed(#[from] zbus::Error),
    #[error("systemd reported a unit load state that is not recognized")]
    UnrecognizedLoadState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnitTimestamp {
    NeverRecorded,
    RecordedAt { recorded_at: Timestamp },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceLastResult {
    ResultSucceeded,
    ExitedWithStatus { exit_status: i32 },
    FailedWithResult { result_name: String },
}

#[derive(Clone, Debug, PartialEq)]
pub enum ServiceUnitSnapshot {
    LoadedService {
        unit_activity: UnitActivity,
        last_result: ServiceLastResult,
        program_arguments: Vec<String>,
    },
    ServiceNotFound,
    SystemdUnreachable(SystemdBusFailure),
}

#[derive(Clone, Debug, PartialEq)]
pub enum TimerUnitSnapshot {
    LoadedTimer {
        unit_activity: UnitActivity,
        next_run: UnitTimestamp,
        last_trigger: UnitTimestamp,
    },
    TimerNotFound,
    SystemdUnreachable(SystemdBusFailure),
}

#[derive(Clone, Debug, PartialEq)]
pub enum UnitStartOutcome {
    UnitFinished,
    JobEnded { job_result: String },
    AuthorizationRefused,
    BusFailure(SystemdBusFailure),
}

async fn system_bus() -> zbus::Result<&'static Connection> {
    SYSTEM_BUS_CONNECTION
        .get_or_try_init(Connection::system)
        .await
}

pub fn parse_unit_state(load_state: &str, active_state: &str) -> UnitState {
    match load_state {
        "loaded" if active_state == "active" || active_state == "reloading" => {
            UnitState::UnitLoaded(UnitActivity::UnitActive)
        }
        "loaded" | "masked" => UnitState::UnitLoaded(UnitActivity::UnitInactive),
        "not-found" => UnitState::UnitNotFound,
        _other_state => UnitState::SystemdUnavailable,
    }
}

pub fn timestamp_from_microseconds(unit_microseconds: u64) -> UnitTimestamp {
    if unit_microseconds == 0 || unit_microseconds == u64::MAX {
        return UnitTimestamp::NeverRecorded;
    }
    i64::try_from(unit_microseconds)
        .ok()
        .and_then(|signed_microseconds| Timestamp::from_microsecond(signed_microseconds).ok())
        .map_or(UnitTimestamp::NeverRecorded, |recorded_at| {
            UnitTimestamp::RecordedAt { recorded_at }
        })
}

pub fn classify_service_result(result_name: &str, exit_status: i32) -> ServiceLastResult {
    match result_name {
        SERVICE_SUCCESS_RESULT => ServiceLastResult::ResultSucceeded,
        "exit-code" => ServiceLastResult::ExitedWithStatus { exit_status },
        other_result => ServiceLastResult::FailedWithResult {
            result_name: other_result.to_owned(),
        },
    }
}

fn first_command_arguments(exec_commands: Vec<ExecCommandRecord>) -> Vec<String> {
    exec_commands
        .into_iter()
        .next()
        .map(|exec_command| exec_command.1)
        .unwrap_or_default()
}

async fn user_bus() -> zbus::Result<&'static Connection> {
    USER_BUS_CONNECTION
        .get_or_try_init(Connection::session)
        .await
}

fn subscription_failure_is_harmless(failure_name: &str) -> bool {
    failure_name == ALREADY_SUBSCRIBED_FAILURE
}

async fn subscribe_to_manager_signals(manager_proxy: &SystemdManagerProxy<'_>) -> zbus::Result<()> {
    match manager_proxy.subscribe().await {
        Err(zbus::Error::MethodError(failure_name, _failure_text, _reply))
            if subscription_failure_is_harmless(failure_name.as_str()) =>
        {
            Ok(())
        }
        subscribe_outcome => subscribe_outcome,
    }
}

async fn unit_object_path(unit_name: &str) -> zbus::Result<OwnedObjectPath> {
    let system_connection = system_bus().await?;
    SystemdManagerProxy::new(system_connection)
        .await?
        .load_unit(unit_name)
        .await
}

async fn read_unit_state(unit_path: &OwnedObjectPath) -> zbus::Result<UnitState> {
    read_unit_state_on(system_bus().await?, unit_path).await
}

async fn read_unit_state_on(
    bus_connection: &Connection,
    unit_path: &OwnedObjectPath,
) -> zbus::Result<UnitState> {
    let unit_proxy = SystemdUnitProxy::builder(bus_connection)
        .path(unit_path)?
        .build()
        .await?;
    Ok(parse_unit_state(
        &unit_proxy.load_state().await?,
        &unit_proxy.active_state().await?,
    ))
}

pub async fn systemd_is_available() -> bool {
    let Ok(system_connection) = system_bus().await else {
        return false;
    };
    let Ok(manager_proxy) = SystemdManagerProxy::new(system_connection).await else {
        return false;
    };
    manager_proxy.version().await.is_ok()
}

pub async fn probe_unit_state(unit_name: &str) -> UnitState {
    let Ok(unit_path) = unit_object_path(unit_name).await else {
        return UnitState::SystemdUnavailable;
    };
    read_unit_state(&unit_path)
        .await
        .unwrap_or(UnitState::SystemdUnavailable)
}

pub async fn first_active_unit(unit_names: &[&'static str]) -> Option<&'static str> {
    let unit_states = join_all(
        unit_names
            .iter()
            .map(|unit_name| probe_unit_state(unit_name)),
    )
    .await;
    unit_names
        .iter()
        .zip(unit_states)
        .find(|named_state| named_state.1 == UnitState::UnitLoaded(UnitActivity::UnitActive))
        .map(|named_state| *named_state.0)
}

async fn read_loaded_service(
    unit_path: &OwnedObjectPath,
    unit_activity: UnitActivity,
) -> zbus::Result<ServiceUnitSnapshot> {
    let service_proxy = SystemdServiceProxy::builder(system_bus().await?)
        .path(unit_path)?
        .build()
        .await?;
    Ok(ServiceUnitSnapshot::LoadedService {
        unit_activity,
        last_result: classify_service_result(
            &service_proxy.result().await?,
            service_proxy.exec_main_status().await?,
        ),
        program_arguments: first_command_arguments(service_proxy.exec_start().await?),
    })
}

async fn read_service_snapshot(
    service_unit: &str,
) -> Result<ServiceUnitSnapshot, SystemdBusFailure> {
    let unit_path = unit_object_path(service_unit).await?;
    match read_unit_state(&unit_path).await? {
        UnitState::UnitLoaded(unit_activity) => {
            Ok(read_loaded_service(&unit_path, unit_activity).await?)
        }
        UnitState::UnitNotFound => Ok(ServiceUnitSnapshot::ServiceNotFound),
        UnitState::SystemdUnavailable => Err(SystemdBusFailure::UnrecognizedLoadState),
    }
}

pub async fn service_unit_snapshot(service_unit: &str) -> ServiceUnitSnapshot {
    read_service_snapshot(service_unit)
        .await
        .unwrap_or_else(ServiceUnitSnapshot::SystemdUnreachable)
}

async fn read_loaded_timer(
    bus_connection: &Connection,
    unit_path: &OwnedObjectPath,
    unit_activity: UnitActivity,
) -> zbus::Result<TimerUnitSnapshot> {
    let timer_proxy = SystemdTimerProxy::builder(bus_connection)
        .path(unit_path)?
        .build()
        .await?;
    Ok(TimerUnitSnapshot::LoadedTimer {
        unit_activity,
        next_run: timestamp_from_microseconds(timer_proxy.next_elapse_microseconds().await?),
        last_trigger: timestamp_from_microseconds(timer_proxy.last_trigger_microseconds().await?),
    })
}

async fn read_timer_snapshot_on(
    bus_connection: &Connection,
    timer_unit: &str,
) -> Result<TimerUnitSnapshot, SystemdBusFailure> {
    let unit_path = SystemdManagerProxy::new(bus_connection)
        .await?
        .load_unit(timer_unit)
        .await?;
    match read_unit_state_on(bus_connection, &unit_path).await? {
        UnitState::UnitLoaded(unit_activity) => {
            Ok(read_loaded_timer(bus_connection, &unit_path, unit_activity).await?)
        }
        UnitState::UnitNotFound => Ok(TimerUnitSnapshot::TimerNotFound),
        UnitState::SystemdUnavailable => Err(SystemdBusFailure::UnrecognizedLoadState),
    }
}

pub async fn timer_unit_snapshot(timer_unit: &str) -> TimerUnitSnapshot {
    let timer_read = async { read_timer_snapshot_on(system_bus().await?, timer_unit).await };
    timer_read
        .await
        .unwrap_or_else(TimerUnitSnapshot::SystemdUnreachable)
}

fn start_failure_outcome(start_failure: zbus::Error) -> UnitStartOutcome {
    let failure_description = start_failure.to_string();
    if failure_description.contains("AccessDenied")
        || failure_description.contains("InteractiveAuthorizationRequired")
        || failure_description.contains("NotAuthorized")
    {
        UnitStartOutcome::AuthorizationRefused
    } else {
        UnitStartOutcome::BusFailure(SystemdBusFailure::BusCallFailed(start_failure))
    }
}

async fn start_unit_and_wait(unit_name: &str) -> zbus::Result<UnitStartOutcome> {
    let system_connection = system_bus().await?;
    let manager_proxy = SystemdManagerProxy::new(system_connection).await?;
    subscribe_to_manager_signals(&manager_proxy).await?;
    let mut removed_jobs = manager_proxy.receive_job_removed().await?;
    let started_job: OwnedObjectPath = manager_proxy
        .inner()
        .call_with_flags(
            START_UNIT_METHOD,
            MethodFlags::AllowInteractiveAuth.into(),
            &(unit_name, JOB_REPLACE_MODE),
        )
        .await?
        .ok_or(zbus::Error::InvalidReply)?;
    while let Some(removed_job) = removed_jobs.next().await {
        let removed_arguments = removed_job.args()?;
        if *removed_arguments.job_path() == started_job {
            return Ok(if removed_arguments.job_result() == JOB_DONE_RESULT {
                UnitStartOutcome::UnitFinished
            } else {
                UnitStartOutcome::JobEnded {
                    job_result: removed_arguments.job_result().clone(),
                }
            });
        }
    }
    Err(zbus::Error::InvalidReply)
}

pub async fn start_system_unit(unit_name: &str) -> UnitStartOutcome {
    start_unit_and_wait(unit_name)
        .await
        .unwrap_or_else(start_failure_outcome)
}

async fn signal_unit(unit_name: &str, signal_number: i32) -> zbus::Result<()> {
    let manager_proxy = SystemdManagerProxy::new(system_bus().await?).await?;
    let _no_reply_body: Option<()> = manager_proxy
        .inner()
        .call_with_flags(
            KILL_UNIT_METHOD,
            MethodFlags::AllowInteractiveAuth.into(),
            &(unit_name, KILL_EVERY_PROCESS, signal_number),
        )
        .await?;
    Ok(())
}

pub async fn signal_system_unit(unit_name: &str, signal_number: i32) -> UnitStartOutcome {
    signal_unit(unit_name, signal_number)
        .await
        .map_or_else(start_failure_outcome, |()| UnitStartOutcome::UnitFinished)
}

pub async fn enable_user_timer(timer_unit: &str) -> zbus::Result<()> {
    let manager_proxy = SystemdManagerProxy::new(user_bus().await?).await?;
    manager_proxy.reload().await?;
    let _changed_files = manager_proxy
        .enable_unit_files(&[timer_unit], false, true)
        .await?;
    manager_proxy.reload().await?;
    let _started_job = manager_proxy
        .start_unit(timer_unit, JOB_REPLACE_MODE)
        .await?;
    Ok(())
}

pub async fn disable_user_timer(timer_unit: &str) -> zbus::Result<()> {
    let manager_proxy = SystemdManagerProxy::new(user_bus().await?).await?;
    let _timer_not_running = manager_proxy.stop_unit(timer_unit, JOB_REPLACE_MODE).await;
    let _timer_not_enabled = manager_proxy.disable_unit_files(&[timer_unit], false).await;
    Ok(())
}

pub async fn reload_user_manager() -> zbus::Result<()> {
    SystemdManagerProxy::new(user_bus().await?)
        .await?
        .reload()
        .await
}

pub async fn probe_user_unit_state(unit_name: &str) -> UnitState {
    let read_state = async {
        let bus_connection = user_bus().await?;
        let unit_path = SystemdManagerProxy::new(bus_connection)
            .await?
            .load_unit(unit_name)
            .await?;
        read_unit_state_on(bus_connection, &unit_path).await
    };
    read_state.await.unwrap_or(UnitState::SystemdUnavailable)
}

pub async fn user_timer_snapshot(timer_unit: &str) -> TimerUnitSnapshot {
    let timer_read = async { read_timer_snapshot_on(user_bus().await?, timer_unit).await };
    timer_read
        .await
        .unwrap_or_else(TimerUnitSnapshot::SystemdUnreachable)
}

async fn active_state_changes_of_unit(
    unit_name: &'static str,
) -> zbus::Result<BoxStream<'static, ()>> {
    let unit_path = unit_object_path(unit_name).await?;
    let unit_proxy = SystemdUnitProxy::builder(system_bus().await?)
        .path(unit_path)?
        .build()
        .await?;
    Ok(unit_proxy
        .receive_active_state_changed()
        .await
        .map(drop)
        .boxed())
}

async fn watched_job_completions(
    watched_units: &'static [&'static str],
) -> zbus::Result<BoxStream<'static, ()>> {
    let manager_proxy = SystemdManagerProxy::new(system_bus().await?).await?;
    subscribe_to_manager_signals(&manager_proxy).await?;
    Ok(manager_proxy
        .receive_job_removed()
        .await?
        .filter(move |removed_job| {
            ready(removed_job.args().is_ok_and(|removed_arguments| {
                watched_units.contains(&removed_arguments.unit_name().as_str())
            }))
        })
        .map(drop)
        .boxed())
}

pub fn watched_unit_changes(
    watched_units: &'static [&'static str],
) -> impl Stream<Item = ()> + Send + 'static {
    stream::once(async move {
        let unit_changes = join_all(
            watched_units
                .iter()
                .map(|unit_name| active_state_changes_of_unit(unit_name)),
        )
        .await;
        let job_completions = watched_job_completions(watched_units).await;
        stream::select_all(
            unit_changes
                .into_iter()
                .chain(std::iter::once(job_completions))
                .filter_map(Result::ok),
        )
    })
    .flatten()
}

#[cfg(test)]
mod host_systemd_units_tests {
    use super::*;

    #[test]
    fn unit_states_distinguish_missing_units_from_an_unreachable_systemd() {
        assert_eq!(
            parse_unit_state("loaded", "active"),
            UnitState::UnitLoaded(UnitActivity::UnitActive)
        );
        assert_eq!(
            parse_unit_state("loaded", "inactive"),
            UnitState::UnitLoaded(UnitActivity::UnitInactive)
        );
        assert_eq!(
            parse_unit_state("masked", "inactive"),
            UnitState::UnitLoaded(UnitActivity::UnitInactive)
        );
        assert_eq!(
            parse_unit_state("not-found", "inactive"),
            UnitState::UnitNotFound
        );
        assert_eq!(parse_unit_state("", ""), UnitState::SystemdUnavailable);
    }

    #[test]
    fn refused_authorization_is_told_apart_from_other_bus_failures() {
        assert_eq!(
            start_failure_outcome(zbus::Error::Failure(
                "org.freedesktop.DBus.Error.AccessDenied".to_owned()
            )),
            UnitStartOutcome::AuthorizationRefused
        );
        assert_eq!(
            start_failure_outcome(zbus::Error::InvalidReply),
            UnitStartOutcome::BusFailure(SystemdBusFailure::BusCallFailed(
                zbus::Error::InvalidReply
            ))
        );
    }

    #[test]
    fn subscribing_twice_on_a_shared_connection_is_not_a_failure() {
        assert!(subscription_failure_is_harmless(
            "org.freedesktop.systemd1.AlreadySubscribed"
        ));
        assert!(!subscription_failure_is_harmless(
            "org.freedesktop.DBus.Error.AccessDenied"
        ));
    }

    #[test]
    fn unset_timer_values_are_never_recorded() {
        assert_eq!(timestamp_from_microseconds(0), UnitTimestamp::NeverRecorded);
        assert_eq!(
            timestamp_from_microseconds(u64::MAX),
            UnitTimestamp::NeverRecorded
        );
        assert_eq!(
            timestamp_from_microseconds(1_794_223_800_000_000),
            UnitTimestamp::RecordedAt {
                recorded_at: Timestamp::constant(1_794_223_800, 0)
            }
        );
    }

    #[test]
    fn exit_codes_keep_their_status_and_other_results_their_name() {
        assert_eq!(
            classify_service_result("success", 0),
            ServiceLastResult::ResultSucceeded
        );
        assert_eq!(
            classify_service_result("exit-code", 2),
            ServiceLastResult::ExitedWithStatus { exit_status: 2 }
        );
        assert_eq!(
            classify_service_result("timeout", 0),
            ServiceLastResult::FailedWithResult {
                result_name: "timeout".to_owned()
            }
        );
    }

    #[test]
    fn only_the_first_command_supplies_program_arguments() {
        assert_eq!(
            first_command_arguments(vec![(
                "/bin/clamdscan".to_owned(),
                vec!["/bin/clamdscan".to_owned(), "/home/my files".to_owned()],
                false,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            )]),
            vec!["/bin/clamdscan", "/home/my files"]
        );
        assert!(first_command_arguments(Vec::new()).is_empty());
    }

    #[tokio::test]
    #[ignore = "reads the real host"]
    async fn host_bus_reports_real_units() {
        assert!(systemd_is_available().await);
        assert_eq!(
            probe_unit_state("no-such-lazaret-unit.service").await,
            UnitState::UnitNotFound
        );
        println!("{:?}", service_unit_snapshot("clamdscan.service").await);
        println!("{:?}", timer_unit_snapshot("clamdscan.timer").await);
        assert_eq!(
            user_timer_snapshot("no-such-lazaret-unit.timer").await,
            TimerUnitSnapshot::TimerNotFound
        );
    }
}

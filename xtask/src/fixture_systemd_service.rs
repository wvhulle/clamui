use std::collections::BTreeMap;

use zbus::{
    blocking::{Connection, connection::Builder},
    interface,
    object_server::SignalEmitter,
    zvariant::{ObjectPath, OwnedObjectPath},
};

const SYSTEMD_BUS_NAME: &str = "org.freedesktop.systemd1";
const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const UNIT_PATH_PREFIX: &str = "/org/freedesktop/systemd1/unit/";
const NEXT_SCAN_MICROSECONDS: u64 = 1_794_223_800_000_000;

const SERVICE_UNITS: [FixtureServiceUnit; 5] = [
    FixtureServiceUnit {
        unit_name: "clamav-daemon.service",
        active_state: "active",
        program_arguments: &["/bin/clamd"],
    },
    FixtureServiceUnit {
        unit_name: "clamav-clamonacc.service",
        active_state: "active",
        program_arguments: &["/bin/clamonacc", "-F", "--fdpass"],
    },
    FixtureServiceUnit {
        unit_name: "clamav-freshclam.service",
        active_state: "inactive",
        program_arguments: &["/bin/freshclam"],
    },
    FixtureServiceUnit {
        unit_name: "clamav-fangfrisch.service",
        active_state: "inactive",
        program_arguments: &["/bin/fangfrisch", "refresh"],
    },
    FixtureServiceUnit {
        unit_name: "clamdscan.service",
        active_state: "inactive",
        program_arguments: &[
            "/bin/clamdscan",
            "--multiscan",
            "--fdpass",
            "/home/alex/Downloads",
            "/tmp",
            "/var/tmp",
        ],
    },
];
const TIMER_UNITS: [&str; 2] = ["clamdscan.timer", "clamav-freshclam.timer"];

type ExecCommandRecord = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

#[derive(Clone, Copy)]
struct FixtureServiceUnit {
    unit_name: &'static str,
    active_state: &'static str,
    program_arguments: &'static [&'static str],
}

fn escaped_unit_path(unit_name: &str) -> OwnedObjectPath {
    let escaped_name = unit_name
        .bytes()
        .map(|name_byte| {
            if name_byte.is_ascii_alphanumeric() {
                char::from(name_byte).to_string()
            } else {
                format!("_{name_byte:02x}")
            }
        })
        .collect::<String>();
    ObjectPath::try_from(format!("{UNIT_PATH_PREFIX}{escaped_name}")).map_or_else(
        |_invalid_path| OwnedObjectPath::default(),
        OwnedObjectPath::from,
    )
}

struct FixtureManager {
    known_unit_paths: BTreeMap<String, OwnedObjectPath>,
}

#[interface(name = "org.freedesktop.systemd1.Manager")]
impl FixtureManager {
    fn load_unit(&self, unit_name: &str) -> OwnedObjectPath {
        self.known_unit_paths
            .get(unit_name)
            .cloned()
            .unwrap_or_else(|| escaped_unit_path("not-found.unit"))
    }

    fn subscribe(&self) {}

    #[zbus(signal)]
    async fn job_removed(
        signal_emitter: &SignalEmitter<'_>,
        job_id: u32,
        job_path: OwnedObjectPath,
        unit_name: &str,
        job_result: &str,
    ) -> zbus::Result<()>;

    #[zbus(property)]
    fn version(&self) -> String {
        "fixture".to_owned()
    }
}

struct FixtureUnit {
    load_state: &'static str,
    active_state: &'static str,
}

#[interface(name = "org.freedesktop.systemd1.Unit")]
impl FixtureUnit {
    #[zbus(property)]
    fn load_state(&self) -> String {
        self.load_state.to_owned()
    }

    #[zbus(property)]
    fn active_state(&self) -> String {
        self.active_state.to_owned()
    }
}

struct FixtureService {
    program_arguments: &'static [&'static str],
}

#[interface(name = "org.freedesktop.systemd1.Service")]
impl FixtureService {
    #[zbus(property)]
    fn result(&self) -> String {
        "success".to_owned()
    }

    #[zbus(property)]
    fn exec_main_status(&self) -> i32 {
        0
    }

    #[zbus(property)]
    fn exec_start(&self) -> Vec<ExecCommandRecord> {
        vec![(
            self.program_arguments[0].to_owned(),
            self.program_arguments
                .iter()
                .map(|program_argument| (*program_argument).to_owned())
                .collect(),
            false,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )]
    }
}

struct FixtureTimer;

#[interface(name = "org.freedesktop.systemd1.Timer")]
impl FixtureTimer {
    #[zbus(property, name = "NextElapseUSecRealtime")]
    fn next_elapse_microseconds(&self) -> u64 {
        NEXT_SCAN_MICROSECONDS
    }

    #[zbus(property, name = "LastTriggerUSec")]
    fn last_trigger_microseconds(&self) -> u64 {
        0
    }
}

pub fn serve_fixture_systemd(bus_address: &str) -> zbus::Result<Connection> {
    let service_paths = SERVICE_UNITS.map(|service_unit| {
        (
            service_unit.unit_name.to_owned(),
            escaped_unit_path(service_unit.unit_name),
        )
    });
    let timer_paths =
        TIMER_UNITS.map(|timer_unit| (timer_unit.to_owned(), escaped_unit_path(timer_unit)));
    let known_unit_paths = service_paths.into_iter().chain(timer_paths).collect();
    let connection = Builder::address(bus_address)?
        .name(SYSTEMD_BUS_NAME)?
        .serve_at(SYSTEMD_MANAGER_PATH, FixtureManager { known_unit_paths })?
        .serve_at(
            escaped_unit_path("not-found.unit"),
            FixtureUnit {
                load_state: "not-found",
                active_state: "inactive",
            },
        )?
        .build()?;
    SERVICE_UNITS.iter().try_for_each(|service_unit| {
        let unit_path = escaped_unit_path(service_unit.unit_name);
        connection.object_server().at(
            &unit_path,
            FixtureUnit {
                load_state: "loaded",
                active_state: service_unit.active_state,
            },
        )?;
        connection.object_server().at(
            &unit_path,
            FixtureService {
                program_arguments: service_unit.program_arguments,
            },
        )?;
        Ok::<(), zbus::Error>(())
    })?;
    TIMER_UNITS.iter().try_for_each(|timer_unit| {
        let unit_path = escaped_unit_path(timer_unit);
        connection.object_server().at(
            &unit_path,
            FixtureUnit {
                load_state: "loaded",
                active_state: "active",
            },
        )?;
        connection.object_server().at(&unit_path, FixtureTimer)?;
        Ok::<(), zbus::Error>(())
    })?;
    Ok(connection)
}

#[cfg(test)]
mod fixture_systemd_service_tests {
    use super::*;

    #[test]
    fn unit_paths_use_the_systemd_escaping() {
        assert_eq!(
            escaped_unit_path("clamav-daemon.service").as_str(),
            "/org/freedesktop/systemd1/unit/clamav_2ddaemon_2eservice"
        );
    }
}

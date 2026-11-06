use crate::application_window::system_tray_menu::{SystemTrayMenu, spawn_system_tray};

#[derive(Clone)]
pub struct RunningTrayHandle(ksni::Handle<SystemTrayMenu>);

impl std::fmt::Debug for RunningTrayHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RunningTrayHandle")
    }
}

pub enum TrayConnection {
    Starting,
    Running(RunningTrayHandle),
    Unavailable,
}

#[derive(Debug, thiserror::Error)]
pub enum TrayStartFailure {
    #[error("the system tray could not be started: {0}")]
    TraySpawnFailed(#[from] ksni::Error),
}

pub async fn start_system_tray() -> Result<RunningTrayHandle, TrayStartFailure> {
    Ok(RunningTrayHandle(spawn_system_tray().await?))
}

pub async fn show_unresolved_detections(
    tray_handle: RunningTrayHandle,
    unresolved_detections: usize,
) {
    let _tray_stopped = tray_handle
        .0
        .update(move |tray_menu: &mut SystemTrayMenu| {
            tray_menu.unresolved_detections = unresolved_detections;
        })
        .await;
}

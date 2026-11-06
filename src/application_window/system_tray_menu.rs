use gettextrs::gettext;
use ksni::{TrayMethods, menu::StandardItem};
use relm4::gtk::{gio::prelude::ActionGroupExt, glib};

use crate::{
    APPLICATION_ID, TRAY_ATTENTION_ICON_NAME, TRAY_ICON_NAME,
    detections_page::detection_alerts::OPEN_DETECTIONS_ACTION,
};

#[derive(Default)]
pub struct SystemTrayMenu {
    pub unresolved_detections: usize,
}

fn activate_application_action(action_name: &'static str) {
    glib::MainContext::default().invoke(move || {
        relm4::main_application().activate_action(action_name, None);
    });
}

fn tray_menu_item(item_label: String, action_name: &'static str) -> ksni::MenuItem<SystemTrayMenu> {
    StandardItem {
        label: item_label,
        activate: Box::new(move |_tray_menu: &mut SystemTrayMenu| {
            activate_application_action(action_name);
        }),
        ..Default::default()
    }
    .into()
}

pub async fn spawn_system_tray() -> Result<ksni::Handle<SystemTrayMenu>, ksni::Error> {
    SystemTrayMenu::default()
        .assume_sni_available(true)
        .spawn()
        .await
}

impl ksni::Tray for SystemTrayMenu {
    fn id(&self) -> String {
        APPLICATION_ID.to_owned()
    }

    fn title(&self) -> String {
        "Lazaret".to_owned()
    }

    fn icon_name(&self) -> String {
        TRAY_ICON_NAME.to_owned()
    }

    fn status(&self) -> ksni::Status {
        if self.unresolved_detections > 0 {
            ksni::Status::NeedsAttention
        } else {
            ksni::Status::Active
        }
    }

    fn attention_icon_name(&self) -> String {
        TRAY_ATTENTION_ICON_NAME.to_owned()
    }

    fn activate(&mut self, _horizontal: i32, _vertical: i32) {
        activate_application_action("show-window");
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        vec![
            tray_menu_item(gettext("Show Lazaret"), "show-window"),
            tray_menu_item(gettext("Show Detections"), OPEN_DETECTIONS_ACTION),
            tray_menu_item(gettext("Quick Scan"), "quick-scan"),
            tray_menu_item(gettext("Update Definitions"), "update-definitions"),
            ksni::MenuItem::Separator,
            tray_menu_item(gettext("Quit"), "quit"),
        ]
    }
}

#[cfg(test)]
mod system_tray_menu_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "needs a real desktop session with a tray host"]
    async fn host_tray_registers_on_the_session_bus() {
        let tray_handle = spawn_system_tray().await;
        println!(
            "tray spawn: {:?}",
            tray_handle.as_ref().map(|_handle| "registered")
        );
        assert!(tray_handle.is_ok());
    }
}

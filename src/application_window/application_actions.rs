use relm4::{
    actions::{ActionName, RelmAction},
    adw,
    gtk::{gio, prelude::*},
};

use crate::{
    findings::detections_page::detection_alerts::{OPEN_DETECTION_ACTION, OPEN_DETECTIONS_ACTION},
    host_services::desktop::running_instance_forwarding::{SCAN_PATHS_ACTION, SHOW_WINDOW_ACTION},
};

relm4::new_action_group!(pub ApplicationActionGroup, "app");
relm4::new_action_group!(pub WindowActionGroup, "win");

relm4::new_stateless_action!(pub AboutAction, ApplicationActionGroup, "about");
relm4::new_stateless_action!(pub PreferencesAction, ApplicationActionGroup, "preferences");
relm4::new_stateless_action!(pub QuitAction, ApplicationActionGroup, "quit");
relm4::new_stateless_action!(pub QuickScanAction, ApplicationActionGroup, "quick-scan");
relm4::new_stateless_action!(
    pub UpdateDefinitionsAction,
    ApplicationActionGroup,
    "update-definitions"
);
relm4::new_stateless_action!(pub ShowWindowAction, ApplicationActionGroup, SHOW_WINDOW_ACTION);
relm4::new_stateless_action!(
    pub OpenDetectionsAction,
    ApplicationActionGroup,
    OPEN_DETECTIONS_ACTION
);
relm4::new_stateful_action!(
    pub OpenDetectionAction,
    ApplicationActionGroup,
    OPEN_DETECTION_ACTION,
    Vec<u8>,
    ()
);
relm4::new_stateful_action!(
    pub ScanPathsAction,
    ApplicationActionGroup,
    SCAN_PATHS_ACTION,
    Vec<Vec<u8>>,
    ()
);

relm4::new_stateful_action!(pub ShowPageAction, WindowActionGroup, "show-page", String, ());

pub fn register_application_action<Action>(registered_action: RelmAction<Action>)
where
    Action: ActionName<Group = ApplicationActionGroup>,
{
    relm4::main_application().add_action(&gio::SimpleAction::from(registered_action));
}

pub fn register_window_action<Action>(
    window_root: &adw::ApplicationWindow,
    registered_action: RelmAction<Action>,
) where
    Action: ActionName<Group = WindowActionGroup>,
{
    window_root.add_action(&gio::SimpleAction::from(registered_action));
}

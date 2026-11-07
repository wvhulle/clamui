use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, adw,
    adw::prelude::*,
    gtk,
    gtk::{gio, gio::prelude::SettingsExtManual},
};

use crate::{
    host_services::desktop::{
        stored_settings::application_settings, stored_settings_watch::forward_setting_changes,
    },
    scans::removable_drives_page::drive_mount_checks::{
        DEVICE_SCAN_ENABLED_KEY, DEVICE_SCAN_MAX_GIGABYTES_KEY, DEVICE_SCAN_SETTING_KEYS,
        DEVICE_SCAN_SKIP_BATTERY_KEY, DeviceAutoScanSettings,
    },
};

pub struct DeviceAutoScanSection {
    stored_settings: gio::Settings,
    auto_scan_settings: DeviceAutoScanSettings,
}

#[derive(Debug)]
pub enum DeviceAutoScanSectionInput {
    AutoScanToggled(bool),
    MaximumSizeChanged(f64),
    BatterySkipToggled(bool),
    StoredSettingChanged,
}

#[derive(Debug)]
pub enum DeviceAutoScanSectionOutput {
    SettingsChanged(DeviceAutoScanSettings),
}

#[relm4::component(pub)]
impl Component for DeviceAutoScanSection {
    type Init = ();
    type Input = DeviceAutoScanSectionInput;
    type Output = DeviceAutoScanSectionOutput;
    type CommandOutput = ();

    view! {
        adw::PreferencesGroup {
                set_title: &gettext("Device Auto-Scan"),
                set_description: Some(&gettext(
                    "Automatically scan removable and external drives when they are connected.",
                )),

                adw::SwitchRow {
                    set_title: &gettext("Enable Device Auto-Scan"),
                    #[watch]
                    #[block_signal(auto_scan_handler)]
                    set_active: model.auto_scan_settings.auto_scan_enabled,
                    connect_active_notify[sender] => move |changed_row| {
                        sender.input(DeviceAutoScanSectionInput::AutoScanToggled(changed_row.is_active()));
                    } @auto_scan_handler,
                },

                adw::SpinRow {
                    set_title: &gettext("Max Device Size (GB)"),
                    set_subtitle: &gettext("0 means no size limit."),
                    set_adjustment: Some(&gtk::Adjustment::new(32.0, 0.0, 10_000.0, 1.0, 10.0, 0.0)),
                    #[watch]
                    #[block_signal(maximum_size_handler)]
                    set_value: f64::from(model.auto_scan_settings.maximum_gigabytes),
                    connect_value_notify[sender] => move |changed_row| {
                        sender.input(DeviceAutoScanSectionInput::MaximumSizeChanged(changed_row.value()));
                    } @maximum_size_handler,
                },

                adw::SwitchRow {
                    set_title: &gettext("Skip on Battery"),
                    #[watch]
                    #[block_signal(battery_skip_handler)]
                    set_active: model.auto_scan_settings.skip_on_battery,
                    connect_active_notify[sender] => move |changed_row| {
                        sender.input(DeviceAutoScanSectionInput::BatterySkipToggled(changed_row.is_active()));
                    } @battery_skip_handler,
                },
        }
    }

    fn init(
        _page_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let stored_settings = application_settings();
        forward_setting_changes(
            &stored_settings,
            &DEVICE_SCAN_SETTING_KEYS,
            sender.input_sender(),
            |_changed_settings, _changed_key| DeviceAutoScanSectionInput::StoredSettingChanged,
        );
        let model = Self {
            auto_scan_settings: DeviceAutoScanSettings::read_from(&stored_settings),
            stored_settings,
        };
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        section_input: DeviceAutoScanSectionInput,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match section_input {
            DeviceAutoScanSectionInput::AutoScanToggled(auto_scan_enabled) => {
                self.auto_scan_settings.auto_scan_enabled = auto_scan_enabled;
                let _read_only_settings = self
                    .stored_settings
                    .set(DEVICE_SCAN_ENABLED_KEY, auto_scan_enabled);
            }
            DeviceAutoScanSectionInput::MaximumSizeChanged(spin_value) => {
                let maximum_gigabytes = spin_value.clamp(0.0, f64::from(u32::MAX)) as u32;
                self.auto_scan_settings.maximum_gigabytes = maximum_gigabytes;
                let _read_only_settings = self
                    .stored_settings
                    .set(DEVICE_SCAN_MAX_GIGABYTES_KEY, maximum_gigabytes);
            }
            DeviceAutoScanSectionInput::BatterySkipToggled(skip_on_battery) => {
                self.auto_scan_settings.skip_on_battery = skip_on_battery;
                let _read_only_settings = self
                    .stored_settings
                    .set(DEVICE_SCAN_SKIP_BATTERY_KEY, skip_on_battery);
            }
            DeviceAutoScanSectionInput::StoredSettingChanged => {
                self.auto_scan_settings = DeviceAutoScanSettings::read_from(&self.stored_settings);
                let _page_closed = sender.output(DeviceAutoScanSectionOutput::SettingsChanged(
                    self.auto_scan_settings,
                ));
            }
        }
    }
}

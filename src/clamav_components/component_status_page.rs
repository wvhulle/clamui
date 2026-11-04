use futures::future::join_all;
use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::clamav_components::{
    clamav_component_row::{
        ClamavComponentRow, ClamavComponentRowInit, ClamavComponentRowInput,
        ClamavComponentRowOutput,
    },
    component_availability::{
        ALL_CLAMAV_COMPONENTS, ComponentAvailability, probe_component_availability,
    },
    distribution_install_guides::detect_distribution_family,
};

pub struct ComponentStatusPage {
    component_rows: FactoryVecDeque<ClamavComponentRow>,
    probe_in_progress: bool,
}

#[derive(Debug)]
pub enum ComponentStatusPageInput {
    RefreshRequested,
    CopyCommandRequested(String),
}

#[derive(Debug)]
pub enum ComponentStatusPageCommand {
    ProbesFinished(Vec<ComponentAvailability>),
}

impl ComponentStatusPage {
    fn start_probes(&mut self, sender: &ComponentSender<Self>) {
        self.probe_in_progress = true;
        (0..self.component_rows.len()).for_each(|row_position| {
            self.component_rows.send(
                row_position,
                ClamavComponentRowInput::AvailabilityChanged(
                    ComponentAvailability::CheckingAvailability,
                ),
            );
        });
        sender.oneshot_command(async {
            ComponentStatusPageCommand::ProbesFinished(
                join_all(ALL_CLAMAV_COMPONENTS.map(probe_component_availability)).await,
            )
        });
    }
}

#[relm4::component(pub)]
impl Component for ComponentStatusPage {
    type Init = ();
    type Input = ComponentStatusPageInput;
    type Output = ();
    type CommandOutput = ComponentStatusPageCommand;

    view! {
        adw::ToastOverlay {
            #[wrap(Some)]
            set_child = &adw::PreferencesPage {
                set_title: &gettext("ClamAV components"),

                add = &adw::PreferencesGroup {
                    set_title: &gettext("ClamAV components"),
                    set_description: Some(&gettext("Setup instructions are copy-only. ClamUI never installs packages or starts services for you.")),
                    #[wrap(Some)]
                    set_header_suffix = &gtk::Button {
                        set_icon_name: "view-refresh-symbolic",
                        set_tooltip_text: Some(&gettext("Refresh status")),
                        set_valign: gtk::Align::Center,
                        add_css_class: "flat",
                        #[watch]
                        set_sensitive: !model.probe_in_progress,
                        connect_clicked => ComponentStatusPageInput::RefreshRequested,
                    },
                },

                #[local_ref]
                add = component_group -> adw::PreferencesGroup {},
            },
        }
    }

    fn init(
        _page_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let distribution_family = detect_distribution_family();
        let mut component_rows = FactoryVecDeque::builder()
            .launch(adw::PreferencesGroup::default())
            .forward(sender.input_sender(), |row_output| match row_output {
                ClamavComponentRowOutput::CopyCommandRequested(install_command) => {
                    ComponentStatusPageInput::CopyCommandRequested(install_command)
                }
            });
        ALL_CLAMAV_COMPONENTS
            .into_iter()
            .for_each(|clamav_component| {
                component_rows.guard().push_back(ClamavComponentRowInit {
                    clamav_component,
                    distribution_family,
                });
            });
        let mut model = Self {
            component_rows,
            probe_in_progress: false,
        };
        model.start_probes(&sender);
        let component_group = model.component_rows.widget();
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: ComponentStatusPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            ComponentStatusPageInput::RefreshRequested => self.start_probes(&sender),
            ComponentStatusPageInput::CopyCommandRequested(install_command) => {
                root.clipboard().set_text(&install_command);
                root.add_toast(adw::Toast::new(&gettext("Command copied to clipboard")));
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: ComponentStatusPageCommand,
        _sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            ComponentStatusPageCommand::ProbesFinished(probed_availabilities) => {
                self.probe_in_progress = false;
                probed_availabilities
                    .into_iter()
                    .enumerate()
                    .for_each(|positioned_availability| {
                        self.component_rows.send(
                            positioned_availability.0,
                            ClamavComponentRowInput::AvailabilityChanged(positioned_availability.1),
                        );
                    });
            }
        }
    }
}

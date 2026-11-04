use gettextrs::gettext;
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::{
    clamav_components::{
        component_availability::{ClamavComponent, ComponentAvailability},
        distribution_install_guides::{
            DistributionFamily, DistributionInstallGuide, component_install_guides,
        },
    },
    malware_scan::scanner_output_parser::sanitize_scanner_line,
};

pub struct ClamavComponentRowInit {
    pub clamav_component: ClamavComponent,
    pub distribution_family: DistributionFamily,
}

pub struct ClamavComponentRow {
    clamav_component: ClamavComponent,
    distribution_family: DistributionFamily,
    component_availability: ComponentAvailability,
}

#[derive(Debug)]
pub enum ClamavComponentRowInput {
    AvailabilityChanged(ComponentAvailability),
}

#[derive(Debug)]
pub enum ClamavComponentRowOutput {
    CopyCommandRequested(String),
}

fn component_title(component: ClamavComponent) -> String {
    match component {
        ClamavComponent::ClamscanScanner => gettext("Virus Scanner"),
        ClamavComponent::FreshclamUpdater => gettext("Database Updater"),
        ClamavComponent::ClamdscanClient => gettext("Daemon Scanner Client"),
        ClamavComponent::ClamdDaemon => gettext("Scanner Daemon"),
    }
}

fn component_icon(component: ClamavComponent) -> &'static str {
    match component {
        ClamavComponent::ClamscanScanner => "system-search-symbolic",
        ClamavComponent::FreshclamUpdater => "software-update-available-symbolic",
        ClamavComponent::ClamdscanClient => "utilities-terminal-symbolic",
        ClamavComponent::ClamdDaemon => "emblem-system-symbolic",
    }
}

fn component_description(component: ClamavComponent) -> String {
    match component {
        ClamavComponent::ClamscanScanner => gettext("clamscan performs on-demand virus scans."),
        ClamavComponent::FreshclamUpdater => {
            gettext("freshclam downloads current virus definitions.")
        }
        ClamavComponent::ClamdscanClient => {
            gettext("clamdscan uses the clamd daemon for faster scanning.")
        }
        ClamavComponent::ClamdDaemon => gettext("clamd is the ClamAV daemon for faster scans."),
    }
}

fn availability_label(component_availability: &ComponentAvailability) -> String {
    match component_availability {
        ComponentAvailability::CheckingAvailability => gettext("Checking…"),
        ComponentAvailability::Installed { .. } => gettext("Installed"),
        ComponentAvailability::Running { .. } => gettext("Running"),
        ComponentAvailability::Stopped { .. } => gettext("Stopped"),
        ComponentAvailability::NotInstalled => gettext("Not installed"),
        ComponentAvailability::ProbeFailed { .. } => gettext("Unknown"),
    }
}

fn availability_style_class(component_availability: &ComponentAvailability) -> &'static str {
    match component_availability {
        ComponentAvailability::CheckingAvailability => "dim-label",
        ComponentAvailability::Installed { .. } | ComponentAvailability::Running { .. } => {
            "success"
        }
        ComponentAvailability::Stopped { .. } | ComponentAvailability::ProbeFailed { .. } => {
            "warning"
        }
        ComponentAvailability::NotInstalled => "error",
    }
}

impl ClamavComponentRow {
    fn row_subtitle(&self) -> String {
        let program_name = self.clamav_component.program_name();
        match &self.component_availability {
            ComponentAvailability::Installed { version_text }
            | ComponentAvailability::Running { version_text }
            | ComponentAvailability::Stopped { version_text } => {
                format!("{program_name} · {}", sanitize_scanner_line(version_text))
            }
            ComponentAvailability::ProbeFailed { failure_text } => {
                format!("{program_name} · {}", sanitize_scanner_line(failure_text))
            }
            ComponentAvailability::CheckingAvailability | ComponentAvailability::NotInstalled => {
                program_name.to_owned()
            }
        }
    }

    fn guide_row(
        &self,
        install_guide: &DistributionInstallGuide,
        sender: &FactorySender<Self>,
    ) -> adw::ActionRow {
        let guide_title = if install_guide.distribution_family == self.distribution_family {
            gettext("{distribution} (this system)")
                .replace("{distribution}", install_guide.distribution_label)
        } else {
            install_guide.distribution_label.to_owned()
        };
        let copy_button = gtk::Button::builder()
            .icon_name("edit-copy-symbolic")
            .tooltip_text(gettext("Copy"))
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .build();
        let row_sender = sender.clone();
        let install_command = install_guide.install_command;
        copy_button.connect_clicked(move |_clicked_button| {
            let _parent_gone = row_sender.output(ClamavComponentRowOutput::CopyCommandRequested(
                install_command.to_owned(),
            ));
        });
        let guide_row = adw::ActionRow::builder()
            .use_markup(false)
            .title(guide_title)
            .subtitle(install_guide.install_command)
            .subtitle_selectable(true)
            .subtitle_lines(0)
            .css_classes(["property"])
            .build();
        guide_row.add_suffix(&copy_button);
        guide_row
    }
}

#[relm4::factory(pub)]
impl FactoryComponent for ClamavComponentRow {
    type Init = ClamavComponentRowInit;
    type Input = ClamavComponentRowInput;
    type Output = ClamavComponentRowOutput;
    type CommandOutput = ();
    type ParentWidget = adw::PreferencesGroup;

    view! {
        #[root]
        adw::ExpanderRow {
            set_use_markup: false,
            set_title: &component_title(self.clamav_component),
            #[watch]
            set_subtitle: &self.row_subtitle(),

            add_prefix = &gtk::Image {
                set_icon_name: Some(component_icon(self.clamav_component)),
            },

            #[name = "availability_status_label"]
            add_suffix = &gtk::Label {
                #[watch]
                set_label: &availability_label(&self.component_availability),
                #[watch]
                set_css_classes: &[availability_style_class(&self.component_availability)],
            },

            add_row = &adw::ActionRow {
                set_use_markup: false,
                set_title: &component_description(self.clamav_component),
                set_title_lines: 0,
            },
        }
    }

    fn init_model(
        row_init: ClamavComponentRowInit,
        _row_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self {
            clamav_component: row_init.clamav_component,
            distribution_family: row_init.distribution_family,
            component_availability: ComponentAvailability::CheckingAvailability,
        }
    }

    fn init_widgets(
        &mut self,
        _row_index: &DynamicIndex,
        root: Self::Root,
        _returned_widget: &<Self::ParentWidget as relm4::factory::FactoryView>::ReturnedWidget,
        sender: FactorySender<Self>,
    ) -> Self::Widgets {
        let widgets = view_output!();
        let (matching_guides, other_guides): (Vec<_>, Vec<_>) =
            component_install_guides(self.clamav_component)
                .iter()
                .partition(|install_guide| {
                    install_guide.distribution_family == self.distribution_family
                });
        matching_guides
            .into_iter()
            .chain(other_guides)
            .for_each(|install_guide| {
                root.add_row(&self.guide_row(install_guide, &sender));
            });
        widgets
    }

    fn update(&mut self, row_input: ClamavComponentRowInput, _sender: FactorySender<Self>) {
        match row_input {
            ClamavComponentRowInput::AvailabilityChanged(component_availability) => {
                self.component_availability = component_availability;
            }
        }
    }
}

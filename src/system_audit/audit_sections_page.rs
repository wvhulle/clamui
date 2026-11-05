use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk, gtk::gio,
    prelude::FactoryVecDeque,
};

use crate::{
    clamav_components::distribution_install_guides::{
        DistributionFamily, detect_distribution_family,
    },
    malware_scan::scanner_output_parser::sanitize_scanner_line,
    system_audit::{
        audit_report_model::{AuditCategory, AuditSection},
        audit_section_group::{AuditGuidanceRequest, AuditSectionGroup, AuditSectionGroupInput},
        security_audit_checks::gather_audit_section,
    },
};

pub struct AuditSectionsPage {
    section_groups: FactoryVecDeque<AuditSectionGroup>,
    audited_categories: &'static [AuditCategory],
    distribution_family: DistributionFamily,
}

pub struct AuditSectionsPageInit {
    pub page_title: String,
    pub page_description: String,
    pub audited_categories: &'static [AuditCategory],
}

#[derive(Debug)]
pub enum AuditSectionsPageInput {
    RefreshRequested,
    GuidanceRequested(AuditGuidanceRequest),
    DocumentationOpenFailed(String),
}

#[derive(Debug)]
pub enum AuditSectionsPageCommand {
    SectionFinished(AuditSection),
}

impl AuditSectionsPage {
    fn section_position(&self, audit_category: AuditCategory) -> usize {
        self.audited_categories
            .iter()
            .position(|audited_category| *audited_category == audit_category)
            .unwrap_or_default()
    }

    fn start_section_audit(&self, sender: &ComponentSender<Self>) {
        let distribution_family = self.distribution_family;
        self.audited_categories
            .iter()
            .copied()
            .for_each(|audit_category| {
                self.section_groups.send(
                    self.section_position(audit_category),
                    AuditSectionGroupInput::SectionChanged(AuditSection::awaiting_checks(
                        audit_category,
                    )),
                );
                sender.oneshot_command(async move {
                    AuditSectionsPageCommand::SectionFinished(
                        gather_audit_section(audit_category, distribution_family).await,
                    )
                });
            });
    }

    fn open_documentation(
        documentation_url: &str,
        sender: &ComponentSender<Self>,
        root: &adw::ToastOverlay,
    ) {
        let failure_sender = sender.clone();
        let parent_window = root.root().and_downcast::<gtk::Window>();
        gtk::UriLauncher::new(documentation_url).launch(
            parent_window.as_ref(),
            gio::Cancellable::NONE,
            move |launch_outcome| {
                if let Err(launch_failure) = launch_outcome {
                    failure_sender.input(AuditSectionsPageInput::DocumentationOpenFailed(
                        launch_failure.message().to_owned(),
                    ));
                }
            },
        );
    }
}

#[relm4::component(pub)]
impl Component for AuditSectionsPage {
    type Init = AuditSectionsPageInit;
    type Input = AuditSectionsPageInput;
    type Output = ();
    type CommandOutput = AuditSectionsPageCommand;

    view! {
        adw::ToastOverlay {
            #[wrap(Some)]
            #[local_ref]
            set_child = sections_preferences_page -> adw::PreferencesPage {
                add = &adw::PreferencesGroup {
                    set_title: &gtk::glib::markup_escape_text(&page_init.page_title),
                    set_description: Some(&gtk::glib::markup_escape_text(&page_init.page_description)),
                    #[wrap(Some)]
                    set_header_suffix = &gtk::Button {
                        set_icon_name: "view-refresh-symbolic",
                        set_tooltip_text: Some(&gettext("Check again")),
                        set_valign: gtk::Align::Center,
                        add_css_class: "flat",
                        connect_clicked => AuditSectionsPageInput::RefreshRequested,
                    },
                },
            },
        }
    }

    fn init(
        page_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let section_groups = FactoryVecDeque::builder()
            .launch(adw::PreferencesPage::default())
            .forward(
                sender.input_sender(),
                AuditSectionsPageInput::GuidanceRequested,
            );
        let mut model = Self {
            section_groups,
            audited_categories: page_init.audited_categories,
            distribution_family: detect_distribution_family(),
        };
        let sections_preferences_page = &model.section_groups.widget().clone();
        let widgets = view_output!();
        model
            .audited_categories
            .iter()
            .copied()
            .for_each(|audit_category| {
                model.section_groups.guard().push_back(audit_category);
            });
        model.start_section_audit(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: AuditSectionsPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            AuditSectionsPageInput::RefreshRequested => self.start_section_audit(&sender),
            AuditSectionsPageInput::GuidanceRequested(
                AuditGuidanceRequest::CopyCommandRequested(copied_command),
            ) => {
                root.clipboard().set_text(&copied_command);
                root.add_toast(adw::Toast::new(&gettext("Command copied to clipboard")));
            }
            AuditSectionsPageInput::GuidanceRequested(
                AuditGuidanceRequest::OpenDocumentationRequested(documentation_url),
            ) => Self::open_documentation(documentation_url, &sender, root),
            AuditSectionsPageInput::DocumentationOpenFailed(failure_text) => {
                root.add_toast(
                    adw::Toast::builder()
                        .title(
                            gettext("Could not open documentation: {error}")
                                .replace("{error}", &sanitize_scanner_line(&failure_text)),
                        )
                        .use_markup(false)
                        .build(),
                );
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: AuditSectionsPageCommand,
        _sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            AuditSectionsPageCommand::SectionFinished(audit_section) => {
                self.section_groups.send(
                    self.section_position(audit_section.audit_category),
                    AuditSectionGroupInput::SectionChanged(audit_section),
                );
            }
        }
    }
}

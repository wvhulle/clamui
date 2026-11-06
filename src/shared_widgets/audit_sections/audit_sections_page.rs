use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, abstractions::Toaster, adw, adw::prelude::*, gtk,
    gtk::gio, prelude::FactoryVecDeque,
};

use crate::{
    application_window::settings_navigation::{SettingsSubpage, system_settings_group},
    host_services::{
        clamav_programs::distribution_install_guides::{
            DistributionFamily, detect_distribution_family,
        },
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
    },
    shared_widgets::{
        audit_sections::{
            audit_category_section::{
                AuditCategorySection, AuditCategorySectionInput, AuditCategorySectionOutput,
            },
            audit_check_results::{AuditCategory, AuditSection},
            security_audit_checks::gather_audit_section,
        },
        loading_indicators::{BUSY_PAGE_NAME, IDLE_PAGE_NAME, busy_page_name},
    },
};

pub struct AuditSectionsPage {
    toaster: Toaster,
    section_groups: FactoryVecDeque<AuditCategorySection>,
    audited_categories: &'static [AuditCategory],
    distribution_family: DistributionFamily,
    running_checks: usize,
}

pub struct AuditSectionsPageInit {
    pub page_title: String,
    pub page_description: String,
    pub audited_categories: &'static [AuditCategory],
    pub settings_subpages: &'static [SettingsSubpage],
}

#[derive(Debug)]
pub enum AuditSectionsPageInput {
    RefreshRequested,
    GuidanceRequested(AuditCategorySectionOutput),
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

    fn start_section_audit(&mut self, sender: &ComponentSender<Self>) {
        let distribution_family = self.distribution_family;
        self.running_checks += self.audited_categories.len();
        self.audited_categories
            .iter()
            .copied()
            .for_each(|audit_category| {
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
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    #[wrap(Some)]
                    set_title_widget = &adw::WindowTitle {
                        set_title: &page_init.page_title,
                    },

                    pack_end = &gtk::Stack {
                        add_named[Some(IDLE_PAGE_NAME)] = &gtk::Button {
                            set_icon_name: "view-refresh-symbolic",
                            set_tooltip_text: Some(&gettext("Check again")),
                            connect_clicked => AuditSectionsPageInput::RefreshRequested,
                        },
                        add_named[Some(BUSY_PAGE_NAME)] = &adw::Spinner {
                            set_tooltip_text: Some(&gettext("Checking")),
                        },
                        #[watch]
                        set_visible_child_name: busy_page_name(model.running_checks > 0),
                    },
                },

                #[wrap(Some)]
                #[local_ref]
                set_content = sections_preferences_page -> adw::PreferencesPage {
                    add = &adw::PreferencesGroup {
                        set_description: Some(&gtk::glib::markup_escape_text(&page_init.page_description)),
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
            toaster: Toaster::new(&root),
            section_groups,
            audited_categories: page_init.audited_categories,
            distribution_family: detect_distribution_family(),
            running_checks: 0,
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
        if !page_init.settings_subpages.is_empty() {
            sections_preferences_page.add(&system_settings_group(page_init.settings_subpages));
        }
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
                AuditCategorySectionOutput::CopyCommandRequested(copied_command),
            ) => {
                root.clipboard().set_text(&copied_command);
                self.toaster
                    .add_toast(adw::Toast::new(&gettext("Command copied to clipboard")));
            }
            AuditSectionsPageInput::GuidanceRequested(
                AuditCategorySectionOutput::OpenDocumentationRequested(documentation_url),
            ) => Self::open_documentation(documentation_url, &sender, root),
            AuditSectionsPageInput::DocumentationOpenFailed(failure_text) => {
                self.toaster.add_toast(
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
                self.running_checks = self.running_checks.saturating_sub(1);
                self.section_groups.send(
                    self.section_position(audit_section.audit_category),
                    AuditCategorySectionInput::SectionChanged(audit_section),
                );
            }
        }
    }
}

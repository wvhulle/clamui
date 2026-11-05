use gettextrs::{gettext, ngettext};
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
        audit_report_model::{ALL_AUDIT_CATEGORIES, AuditSection, AuditStatus, AuditStatusCounts},
        audit_section_group::{AuditGuidanceRequest, AuditSectionGroup, AuditSectionGroupInput},
        security_audit_checks::gather_audit_section,
    },
};

pub struct SystemAuditPage {
    section_groups: FactoryVecDeque<AuditSectionGroup>,
    distribution_family: DistributionFamily,
    audit_has_started: bool,
    pending_section_count: usize,
    status_counts: AuditStatusCounts,
}

#[derive(Debug)]
pub enum SystemAuditPageInput {
    PageBecameVisible,
    RefreshRequested,
    GuidanceRequested(AuditGuidanceRequest),
    DocumentationOpenFailed(String),
}

#[derive(Debug)]
pub enum SystemAuditPageCommand {
    SectionFinished(AuditSection),
}

fn plain_text_toast(toast_text: &str) -> adw::Toast {
    adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build()
}

fn summary_headline(status_counts: AuditStatusCounts, pending_section_count: usize) -> String {
    if pending_section_count > 0 {
        gettext("Auditing…")
    } else if status_counts.failed_count > 0 {
        ngettext(
            "{count} security issue needs attention",
            "{count} security issues need attention",
            status_counts.failed_count,
        )
        .replace("{count}", &status_counts.failed_count.to_string())
    } else if status_counts.review_count > 0 {
        ngettext(
            "{count} audit check needs review",
            "{count} audit checks need review",
            status_counts.review_count,
        )
        .replace("{count}", &status_counts.review_count.to_string())
    } else {
        gettext("Security audit completed")
    }
}

fn summary_status(status_counts: AuditStatusCounts, pending_section_count: usize) -> AuditStatus {
    if pending_section_count > 0 {
        AuditStatus::CheckInProgress
    } else if status_counts.failed_count > 0 {
        AuditStatus::CheckFailed
    } else if status_counts.review_count > 0 {
        AuditStatus::NeedsReview
    } else {
        AuditStatus::CheckPassed
    }
}

impl SystemAuditPage {
    fn start_audit(&mut self, sender: &ComponentSender<Self>) {
        self.audit_has_started = true;
        self.pending_section_count = ALL_AUDIT_CATEGORIES.len();
        self.status_counts = AuditStatusCounts::default();
        let distribution_family = self.distribution_family;
        ALL_AUDIT_CATEGORIES.into_iter().for_each(|audit_category| {
            self.section_groups.send(
                audit_category.section_position(),
                AuditSectionGroupInput::SectionChanged(AuditSection::awaiting_checks(
                    audit_category,
                )),
            );
            sender.oneshot_command(async move {
                SystemAuditPageCommand::SectionFinished(
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
                    failure_sender.input(SystemAuditPageInput::DocumentationOpenFailed(
                        launch_failure.message().to_owned(),
                    ));
                }
            },
        );
    }
}

#[relm4::component(pub)]
impl Component for SystemAuditPage {
    type Init = ();
    type Input = SystemAuditPageInput;
    type Output = ();
    type CommandOutput = SystemAuditPageCommand;

    view! {
        adw::ToastOverlay {
            #[wrap(Some)]
            #[local_ref]
            set_child = audit_preferences_page -> adw::PreferencesPage {
                set_title: &gettext("System security audit"),

                add = &adw::PreferencesGroup {
                    set_title: &gettext("System security audit"),
                    set_description: Some(&gettext("Inspect your security posture and copy recommendations. Audit checks never change system configuration.")),
                    #[wrap(Some)]
                    set_header_suffix = &gtk::Button {
                        set_icon_name: "view-refresh-symbolic",
                        set_tooltip_text: Some(&gettext("Refresh audit")),
                        set_valign: gtk::Align::Center,
                        add_css_class: "flat",
                        #[watch]
                        set_sensitive: model.pending_section_count == 0,
                        connect_clicked => SystemAuditPageInput::RefreshRequested,
                    },

                    add = &adw::ActionRow {
                        set_use_markup: false,
                        #[watch]
                        set_title: &summary_headline(model.status_counts, model.pending_section_count),

                        add_prefix = &gtk::Image {
                            #[watch]
                            set_icon_name: Some(summary_status(model.status_counts, model.pending_section_count).status_icon_name()),
                            #[watch]
                            set_css_classes: &[summary_status(model.status_counts, model.pending_section_count).status_style_class()],
                        },

                        add_suffix = &gtk::Box {
                            set_spacing: 6,
                            set_valign: gtk::Align::Center,
                            set_tooltip_text: Some(&gettext("Warning")),

                            gtk::Image {
                                set_icon_name: Some(AuditStatus::NeedsReview.status_icon_name()),
                                add_css_class: AuditStatus::NeedsReview.status_style_class(),
                            },
                            gtk::Label {
                                #[watch]
                                set_label: &model.status_counts.review_count.to_string(),
                            },
                        },

                        add_suffix = &gtk::Box {
                            set_spacing: 6,
                            set_valign: gtk::Align::Center,
                            set_tooltip_text: Some(&gettext("Pass")),

                            gtk::Image {
                                set_icon_name: Some(AuditStatus::CheckPassed.status_icon_name()),
                                add_css_class: AuditStatus::CheckPassed.status_style_class(),
                            },
                            gtk::Label {
                                #[watch]
                                set_label: &model.status_counts.passed_count.to_string(),
                            },
                        },

                        add_suffix = &gtk::Box {
                            set_spacing: 6,
                            set_valign: gtk::Align::Center,
                            set_tooltip_text: Some(&gettext("unavailable or skipped")),

                            gtk::Image {
                                set_icon_name: Some(AuditStatus::StatusUnknown.status_icon_name()),
                                add_css_class: AuditStatus::StatusUnknown.status_style_class(),
                            },
                            gtk::Label {
                                #[watch]
                                set_label: &model.status_counts.unverified_count.to_string(),
                            },
                        },
                    },
                },
            },
        }
    }

    fn init(
        _page_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let section_groups = FactoryVecDeque::builder()
            .launch(adw::PreferencesPage::default())
            .forward(
                sender.input_sender(),
                SystemAuditPageInput::GuidanceRequested,
            );
        let mut model = Self {
            section_groups,
            distribution_family: detect_distribution_family(),
            audit_has_started: false,
            pending_section_count: 0,
            status_counts: AuditStatusCounts::default(),
        };
        let audit_preferences_page = &model.section_groups.widget().clone();
        let widgets = view_output!();
        ALL_AUDIT_CATEGORIES.into_iter().for_each(|audit_category| {
            model.section_groups.guard().push_back(audit_category);
        });
        let visibility_sender = sender.clone();
        root.connect_map(move |_mapped_page| {
            visibility_sender.input(SystemAuditPageInput::PageBecameVisible);
        });
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: SystemAuditPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            SystemAuditPageInput::PageBecameVisible => {
                if !self.audit_has_started {
                    self.start_audit(&sender);
                }
            }
            SystemAuditPageInput::RefreshRequested => self.start_audit(&sender),
            SystemAuditPageInput::GuidanceRequested(
                AuditGuidanceRequest::CopyCommandRequested(suggested_command),
            ) => {
                root.clipboard().set_text(&suggested_command);
                root.add_toast(adw::Toast::new(&gettext("Command copied to clipboard")));
            }
            SystemAuditPageInput::GuidanceRequested(
                AuditGuidanceRequest::OpenDocumentationRequested(documentation_url),
            ) => Self::open_documentation(documentation_url, &sender, root),
            SystemAuditPageInput::DocumentationOpenFailed(failure_text) => {
                root.add_toast(plain_text_toast(
                    &gettext("Could not open documentation: {error}")
                        .replace("{error}", &sanitize_scanner_line(&failure_text)),
                ));
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: SystemAuditPageCommand,
        _sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            SystemAuditPageCommand::SectionFinished(audit_section) => {
                self.pending_section_count = self.pending_section_count.saturating_sub(1);
                self.status_counts = self.status_counts.including_section(&audit_section);
                self.section_groups.send(
                    audit_section.audit_category.section_position(),
                    AuditSectionGroupInput::SectionChanged(audit_section),
                );
            }
        }
    }
}

#[cfg(test)]
mod system_audit_page_tests {
    use super::*;

    #[test]
    fn the_summary_headlines_the_most_severe_outcome() {
        let mixed_counts = AuditStatusCounts {
            failed_count: 2,
            review_count: 1,
            passed_count: 4,
            unverified_count: 0,
        };
        assert_eq!(summary_headline(mixed_counts, 3), "Auditing…");
        assert_eq!(
            summary_headline(mixed_counts, 0),
            "2 security issues need attention"
        );
        assert_eq!(
            summary_headline(
                AuditStatusCounts {
                    failed_count: 0,
                    ..mixed_counts
                },
                0
            ),
            "1 audit check needs review"
        );
        assert_eq!(
            summary_headline(AuditStatusCounts::default(), 0),
            "Security audit completed"
        );
    }

    #[test]
    fn the_summary_icon_matches_the_headline_severity() {
        assert_eq!(
            summary_status(AuditStatusCounts::default(), 1),
            AuditStatus::CheckInProgress
        );
        assert_eq!(
            summary_status(
                AuditStatusCounts {
                    failed_count: 1,
                    ..AuditStatusCounts::default()
                },
                0
            ),
            AuditStatus::CheckFailed
        );
    }
}

use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, abstractions::Toaster, adw, adw::prelude::*, gtk,
    gtk::gio, prelude::FactoryVecDeque,
};

use crate::{
    application_window::{
        application_actions::ONLINE_SERVICES_ACTION,
        protection_evidence_refresh::{EvidenceRefresh, GatheredEvidence},
    },
    host_services::{
        clamav_programs::distribution_install_guides::{
            DistributionFamily, detect_distribution_family,
        },
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
    },
    shared_widgets::loading_indicators::{BUSY_PAGE_NAME, IDLE_PAGE_NAME, busy_page_name},
    signatures::signature_sources_page::{
        signature_source_checks::gather_signature_source_checks,
        signature_sources_presentation::{
            SourceChecks, abuse_ch_key_needs_attention, abuse_ch_key_subtitle,
        },
        source_check_results::AuditCheck,
        source_check_row::{AuditCheckRow, AuditCheckRowOutput},
    },
};

pub struct SignatureSourcesPage {
    toaster: Toaster,
    check_rows: FactoryVecDeque<AuditCheckRow>,
    source_checks: SourceChecks,
    distribution_family: DistributionFamily,
    evidence_refresh: EvidenceRefresh,
    gathered_evidence: GatheredEvidence,
}

#[derive(Debug)]
pub enum SignatureSourcesPageInput {
    RefreshRequested,
    EvidenceRefreshChanged(EvidenceRefresh),
    EvidenceGathered(GatheredEvidence),
    GuidanceRequested(AuditCheckRowOutput),
    DocumentationOpenFailed(gtk::glib::Error),
}

#[derive(Debug)]
pub enum SignatureSourcesPageCommand {
    SourceChecksFinished(Vec<AuditCheck>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureSourcesPageOutput {
    EvidenceRefreshRequested,
}

impl SignatureSourcesPage {
    fn start_source_checks(&mut self, sender: &ComponentSender<Self>) {
        self.source_checks = SourceChecks::ChecksRunning;
        let distribution_family = self.distribution_family;
        sender.oneshot_command(async move {
            SignatureSourcesPageCommand::SourceChecksFinished(
                gather_signature_source_checks(distribution_family).await,
            )
        });
    }

    fn show_check_rows(&mut self, shown_rows: Vec<AuditCheckRow>) {
        let mut row_guard = self.check_rows.guard();
        row_guard.clear();
        shown_rows.into_iter().for_each(|check_row| {
            row_guard.push_back(check_row);
        });
    }

    fn page_busy(&self) -> bool {
        self.source_checks.checks_running() || self.evidence_refresh.is_running()
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
                    failure_sender.input(SignatureSourcesPageInput::DocumentationOpenFailed(
                        launch_failure,
                    ));
                }
            },
        );
    }
}

#[relm4::component(pub)]
impl Component for SignatureSourcesPage {
    type Init = ();
    type Input = SignatureSourcesPageInput;
    type Output = SignatureSourcesPageOutput;
    type CommandOutput = SignatureSourcesPageCommand;

    view! {
        adw::ToastOverlay {
            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    pack_end = &gtk::Stack {
                        add_named[Some(IDLE_PAGE_NAME)] = &gtk::Button {
                            set_icon_name: "view-refresh-symbolic",
                            set_tooltip_text: Some(&gettext("Check again")),
                            connect_clicked => SignatureSourcesPageInput::RefreshRequested,
                        },
                        add_named[Some(BUSY_PAGE_NAME)] = &adw::Spinner {
                            set_tooltip_text: Some(&gettext("Checking")),
                        },
                        #[watch]
                        set_visible_child_name: busy_page_name(model.page_busy()),
                    },
                },

                #[wrap(Some)]
                set_content = &adw::PreferencesPage {
                    add = &adw::PreferencesGroup {
                        set_description: Some(&gettext(
                            "Where ClamAV's malware signatures come from, and which other \
                             sources you could add.",
                        )),
                    },

                    #[local_ref]
                    add = source_group -> adw::PreferencesGroup {
                        set_title: &gettext("Signature Sources"),
                        #[wrap(Some)]
                        set_header_suffix = &gtk::Image {
                            set_valign: gtk::Align::Center,
                            #[watch]
                            set_icon_name: Some(model.source_checks.overall_status().status_icon_name()),
                            #[watch]
                            set_tooltip_text: Some(&model.source_checks.overall_status().status_label()),
                            #[watch]
                            set_css_classes: &[model.source_checks.overall_status().status_style_class()],
                        },
                    },

                    add = &adw::PreferencesGroup {
                        set_title: &gettext("abuse.ch Key"),

                        adw::ActionRow {
                            set_title: &gettext("abuse.ch Auth-Key"),
                            set_subtitle_lines: 0,
                            set_use_markup: false,
                            #[watch]
                            set_subtitle: &abuse_ch_key_subtitle(&model.gathered_evidence),
                            set_activatable: true,
                            set_action_name: Some(ONLINE_SERVICES_ACTION),
                            add_suffix = &gtk::Image {
                                set_icon_name: Some("dialog-warning-symbolic"),
                                add_css_class: "warning",
                                #[watch]
                                set_visible: abuse_ch_key_needs_attention(&model.gathered_evidence),
                            },
                            add_suffix = &gtk::Image { set_icon_name: Some("go-next-symbolic") },
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
        let mut model = Self {
            toaster: Toaster::new(&root),
            check_rows: FactoryVecDeque::builder()
                .launch(adw::PreferencesGroup::default())
                .forward(
                    sender.input_sender(),
                    SignatureSourcesPageInput::GuidanceRequested,
                ),
            source_checks: SourceChecks::ChecksRunning,
            distribution_family: detect_distribution_family(),
            evidence_refresh: EvidenceRefresh::NothingRunning,
            gathered_evidence: GatheredEvidence::NotGatheredYet,
        };
        model.show_check_rows(vec![AuditCheckRow::CheckingPlaceholder]);
        model.start_source_checks(&sender);
        let source_group = &model.check_rows.widget().clone();
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: SignatureSourcesPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            SignatureSourcesPageInput::RefreshRequested => {
                self.start_source_checks(&sender);
                let _shell_closed =
                    sender.output(SignatureSourcesPageOutput::EvidenceRefreshRequested);
            }
            SignatureSourcesPageInput::EvidenceRefreshChanged(evidence_refresh) => {
                self.evidence_refresh = evidence_refresh;
            }
            SignatureSourcesPageInput::EvidenceGathered(gathered_evidence) => {
                self.gathered_evidence = gathered_evidence;
            }
            SignatureSourcesPageInput::GuidanceRequested(
                AuditCheckRowOutput::CopyCommandRequested(copied_command),
            ) => {
                root.clipboard().set_text(&copied_command);
                self.toaster
                    .add_toast(adw::Toast::new(&gettext("Command copied to clipboard")));
            }
            SignatureSourcesPageInput::GuidanceRequested(
                AuditCheckRowOutput::DocumentationRequested(documentation_url),
            ) => Self::open_documentation(documentation_url, &sender, root),
            SignatureSourcesPageInput::DocumentationOpenFailed(launch_failure) => {
                self.toaster.add_toast(
                    adw::Toast::builder()
                        .title(
                            gettext("Could not open documentation: {error}").replace(
                                "{error}",
                                &sanitize_scanner_line(launch_failure.message()),
                            ),
                        )
                        .use_markup(false)
                        .build(),
                );
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: SignatureSourcesPageCommand,
        _sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            SignatureSourcesPageCommand::SourceChecksFinished(finished_checks) => {
                self.show_check_rows(
                    finished_checks
                        .iter()
                        .cloned()
                        .map(AuditCheckRow::CheckShown)
                        .collect(),
                );
                self.source_checks = SourceChecks::ChecksFinished(finished_checks);
            }
        }
    }
}

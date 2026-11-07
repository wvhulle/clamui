use gettextrs::{gettext, ngettext};
use relm4::{
    Component, ComponentParts, ComponentSender, abstractions::Toaster, actions::ActionName, adw,
    adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    application_window::{
        application_actions::ShowPageAction,
        application_pages::ApplicationPage,
        page_links::system_settings_group,
        protection_evidence_refresh::{EvidenceRefresh, GatheredEvidence},
    },
    findings::detections_page::alert_delivery_presentation::AlertReadiness,
    host_services::{
        clamav_programs::distribution_install_guides::{
            DistributionFamily, detect_distribution_family,
        },
        desktop::locale_formatting::host_moment_formatters,
        detection_journal::detection_journal_follower::JournalAccess,
        protection_evidence::host_protection_evidence::detection_notifications_are_enabled,
    },
    protection_page::protection_timeline_presentation::{
        ProtectionActivity, ProtectionStepAction, protection_timeline,
    },
    shared_widgets::{
        loading_indicators::{
            BUSY_PAGE_NAME, FirstLoad, IDLE_PAGE_NAME, LOADED_PAGE_NAME, LOADING_PAGE_NAME,
            busy_page_name, loading_status_page,
        },
        step_timeline::{
            timeline_step_contents::TimelineStepRowOutput,
            timeline_step_row::{TimelineStepRow, show_timeline_steps},
        },
    },
};

pub struct ProtectionTimelinePage {
    toaster: Toaster,
    protection_rows: FactoryVecDeque<TimelineStepRow<ProtectionStepAction>>,
    engine_rows: FactoryVecDeque<TimelineStepRow<ProtectionStepAction>>,
    review_rows: FactoryVecDeque<TimelineStepRow<ProtectionStepAction>>,
    distribution_family: DistributionFamily,
    evidence_refresh: EvidenceRefresh,
    coverage_summary: String,
    unresolved_detections: usize,
    journal_access: JournalAccess,
    gathered_evidence: GatheredEvidence,
}

#[derive(Debug)]
pub enum ProtectionTimelinePageInput {
    RefreshRequested,
    EvidenceRefreshChanged(EvidenceRefresh),
    EvidenceGathered(GatheredEvidence),
    UnresolvedDetectionsChanged(usize),
    JournalAccessChanged(JournalAccess),
    StepRequested(TimelineStepRowOutput<ProtectionStepAction>),
}

#[derive(Debug)]
pub enum ProtectionTimelinePageOutput {
    EvidenceRefreshRequested,
}

pub fn decision_headline(unresolved_detections: usize) -> String {
    if unresolved_detections == 0 {
        return gettext("Nothing needs your decision");
    }
    ngettext(
        "{count} detection needs your decision",
        "{count} detections need your decision",
        u32::try_from(unresolved_detections).unwrap_or(u32::MAX),
    )
    .replace("{count}", &unresolved_detections.to_string())
}

pub fn shown_coverage_text(coverage_summary: &str, home_directory: &str) -> String {
    if home_directory.is_empty() || home_directory == "/" {
        return coverage_summary.to_owned();
    }
    coverage_summary
        .replace(&format!("{home_directory}/"), "~/")
        .replace(&format!("{home_directory},"), "~,")
}

fn show_application_page(root: &adw::ToastOverlay, application_page: ApplicationPage) {
    let _action_missing = root.activate_action(
        &ShowPageAction::action_name(),
        Some(&application_page.page_name().to_variant()),
    );
}

fn launched_step_group(
    step_group: adw::PreferencesGroup,
    sender: &ComponentSender<ProtectionTimelinePage>,
) -> FactoryVecDeque<TimelineStepRow<ProtectionStepAction>> {
    FactoryVecDeque::builder().launch(step_group).forward(
        sender.input_sender(),
        ProtectionTimelinePageInput::StepRequested,
    )
}

fn titled_group(group_title: &str) -> adw::PreferencesGroup {
    adw::PreferencesGroup::builder().title(group_title).build()
}

fn described_group(group_title: &str, group_description: &str) -> adw::PreferencesGroup {
    adw::PreferencesGroup::builder()
        .title(group_title)
        .description(group_description)
        .build()
}

impl ProtectionTimelinePage {
    const fn first_load(&self) -> FirstLoad {
        match self.gathered_evidence {
            GatheredEvidence::NotGatheredYet => FirstLoad::StillLoading,
            GatheredEvidence::Gathered { .. } => FirstLoad::LoadFinished,
        }
    }

    fn request_evidence_refresh(sender: &ComponentSender<Self>) {
        let _shell_closed = sender.output(ProtectionTimelinePageOutput::EvidenceRefreshRequested);
    }

    fn show_timeline(&mut self) {
        let GatheredEvidence::Gathered {
            protection_evidence,
            gathered_at,
        } = &self.gathered_evidence
        else {
            return;
        };
        let gathered_timeline = protection_timeline(
            protection_evidence,
            &AlertReadiness {
                journal_access: self.journal_access.clone(),
                notifications_enabled: detection_notifications_are_enabled(),
            },
            &ProtectionActivity {
                observed_at: *gathered_at,
                moment_formatters: host_moment_formatters(),
            },
            self.distribution_family,
        );
        self.coverage_summary = gathered_timeline.coverage_summary;
        show_timeline_steps(
            &mut self.protection_rows,
            gathered_timeline.protection_steps,
        );
        show_timeline_steps(&mut self.engine_rows, gathered_timeline.engine_steps);
        show_timeline_steps(&mut self.review_rows, gathered_timeline.review_steps);
    }

    fn run_step_action(chosen_action: ProtectionStepAction, root: &adw::ToastOverlay) {
        match chosen_action {
            ProtectionStepAction::OpenDatabaseUpdates => {
                show_application_page(root, ApplicationPage::DatabaseUpdates);
            }
            ProtectionStepAction::OpenScanEngine => {
                show_application_page(root, ApplicationPage::ScanEngine);
            }
            ProtectionStepAction::OpenOnAccessScanning => {
                show_application_page(root, ApplicationPage::OnAccessScanning);
            }
            ProtectionStepAction::OpenScheduledScans => {
                show_application_page(root, ApplicationPage::ScheduledScans);
            }
            ProtectionStepAction::OpenManualScan => {
                show_application_page(root, ApplicationPage::Scan);
            }
            ProtectionStepAction::OpenDetections => {
                show_application_page(root, ApplicationPage::Detections);
            }
            ProtectionStepAction::OpenTrustedDetections => {
                show_application_page(root, ApplicationPage::TrustedDetections);
            }
        }
    }
}

#[relm4::component(pub)]
impl Component for ProtectionTimelinePage {
    type Init = ();
    type Input = ProtectionTimelinePageInput;
    type Output = ProtectionTimelinePageOutput;
    type CommandOutput = ();

    view! {
        adw::ToastOverlay {
            #[wrap(Some)]
            set_child = &adw::ToolbarView {
            add_top_bar = &adw::HeaderBar {
                #[wrap(Some)]
                set_title_widget = &adw::WindowTitle {
                    set_title: &gettext("Protection"),
                },

                pack_end = &gtk::Stack {
                    add_named[Some(IDLE_PAGE_NAME)] = &gtk::Button {
                        set_icon_name: "view-refresh-symbolic",
                        set_tooltip_text: Some(&gettext("Check again")),
                        connect_clicked => ProtectionTimelinePageInput::RefreshRequested,
                    },
                    add_named[Some(BUSY_PAGE_NAME)] = &adw::Spinner {
                        set_tooltip_text: Some(&gettext("Checking")),
                    },
                    #[watch]
                    set_visible_child_name: busy_page_name(model.evidence_refresh.is_running()),
                },
            },

            #[wrap(Some)]
            set_content = &gtk::Stack {
            #[local_ref]
            add_named[Some(LOADING_PAGE_NAME)] = protection_loading_page -> adw::StatusPage {},
            add_named[Some(LOADED_PAGE_NAME)] = &adw::PreferencesPage {
                add = &adw::PreferencesGroup {
                    #[watch]
                    set_title: &gtk::glib::markup_escape_text(&decision_headline(model.unresolved_detections)),
                    #[watch]
                    set_description: Some(&gtk::glib::markup_escape_text(&shown_coverage_text(
                        &model.coverage_summary,
                        &gtk::glib::home_dir().to_string_lossy(),
                    ))),
                    #[wrap(Some)]
                    set_header_suffix = &gtk::Button {
                        set_label: &gettext("Review"),
                        set_valign: gtk::Align::Center,
                        set_action_name: Some("win.show-page"),
                        set_action_target_value: Some(&"detections".to_variant()),
                        add_css_class: "suggested-action",
                        #[watch]
                        set_visible: model.unresolved_detections > 0,
                    },
                },

                add: protection_group,

                add: engine_group,

                #[local_ref]
                add = review_group -> adw::PreferencesGroup {
                    #[watch]
                    set_visible: !model.review_rows.is_empty(),
                },

                add = &system_settings_group(&[
                    ApplicationPage::OnAccessScanning,
                    ApplicationPage::TrustedDetections,
                ]),
            },
            #[watch]
            set_visible_child_name: model.first_load().shown_page_name(),
            },
            },
        }
    }

    fn init(
        _page_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = Self {
            toaster: Toaster::new(&root),
            protection_rows: launched_step_group(
                titled_group(&gettext("Checks on your files")),
                &sender,
            ),
            engine_rows: launched_step_group(
                described_group(
                    &gettext("Engine"),
                    &gettext("What the checks above rely on"),
                ),
                &sender,
            ),
            review_rows: launched_step_group(titled_group(&gettext("Needs review")), &sender),
            distribution_family: detect_distribution_family(),
            evidence_refresh: EvidenceRefresh::NothingRunning,
            coverage_summary: gettext("Checking…"),
            unresolved_detections: 0,
            journal_access: JournalAccess::FollowingJournal,
            gathered_evidence: GatheredEvidence::NotGatheredYet,
        };
        let protection_group = &model.protection_rows.widget().clone();
        let engine_group = &model.engine_rows.widget().clone();
        let review_group = &model.review_rows.widget().clone();
        let protection_loading_page = &loading_status_page(&gettext("Checking your protection…"));
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: ProtectionTimelinePageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            ProtectionTimelinePageInput::UnresolvedDetectionsChanged(unresolved_detections) => {
                self.unresolved_detections = unresolved_detections;
            }
            ProtectionTimelinePageInput::JournalAccessChanged(journal_access) => {
                self.journal_access = journal_access;
                self.show_timeline();
            }
            ProtectionTimelinePageInput::RefreshRequested => {
                Self::request_evidence_refresh(&sender);
            }
            ProtectionTimelinePageInput::EvidenceRefreshChanged(evidence_refresh) => {
                self.evidence_refresh = evidence_refresh;
            }
            ProtectionTimelinePageInput::EvidenceGathered(gathered_evidence) => {
                self.gathered_evidence = gathered_evidence;
                self.show_timeline();
            }
            ProtectionTimelinePageInput::StepRequested(TimelineStepRowOutput::ActionChosen(
                chosen_action,
            )) => Self::run_step_action(chosen_action, root),
            ProtectionTimelinePageInput::StepRequested(TimelineStepRowOutput::CopyRequested(
                copied_command,
            )) => {
                root.clipboard().set_text(&copied_command);
                self.toaster
                    .add_toast(adw::Toast::new(&gettext("Command copied to clipboard")));
            }
        }
    }
}

#[cfg(test)]
mod protection_timeline_page_tests {
    use super::*;

    #[test]
    fn the_headline_counts_open_decisions() {
        assert_eq!(decision_headline(0), "Nothing needs your decision");
        assert_eq!(decision_headline(2), "2 detections need your decision");
    }

    #[test]
    fn coverage_lines_shorten_the_home_folder() {
        assert_eq!(
            shown_coverage_text("/home/user/Downloads blocked on access", "/home/user"),
            "~/Downloads blocked on access"
        );
        assert_eq!(
            shown_coverage_text("/home/username/Downloads blocked", "/home/user"),
            "/home/username/Downloads blocked"
        );
    }
}

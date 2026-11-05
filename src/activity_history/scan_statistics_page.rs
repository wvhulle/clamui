use std::time::{SystemTime, UNIX_EPOCH};

use gettextrs::{gettext, ngettext};
use relm4::{Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk};
use tokio::task::spawn_blocking;

use crate::{
    activity_history::{
        activity_entry_row::formatted_local_time,
        activity_export_formats::formatted_duration_text,
        activity_history_database::{ActivityEntryRecord, ActivityHistory, ActivityHistoryFailure},
        scan_activity_chart::{chart_legend, replace_chart_columns},
        scan_activity_statistics::{
            DefinitionFreshness, ProtectionAssessment, ProtectionLevel, ProtectionReason,
            ScanActivityStatistics, StatisticsTimeframe, assess_protection, newest_completed_scan,
            summarize_scan_activity,
        },
    },
    shared_page_widget_templates::ClampedPage,
    virus_database::database_directory_status::{
        DatabaseDirectoryStatus, configured_database_directory, inspect_database_directory,
    },
};

const SECONDS_PER_HOUR: i64 = 3600;
const SECONDS_PER_DAY: i64 = 24 * SECONDS_PER_HOUR;

pub struct ScanStatisticsPage {
    activity_history: ActivityHistory,
    listed_entries: Vec<ActivityEntryRecord>,
    definition_freshness: DefinitionFreshness,
    selected_timeframe: StatisticsTimeframe,
    page_notice: String,
    timeframe_buttons: Vec<gtk::ToggleButton>,
    activity_chart: gtk::Box,
}

#[derive(Debug)]
pub enum ScanStatisticsPageInput {
    ReloadRequested,
    TimeframeSelected(StatisticsTimeframe),
}

#[derive(Debug)]
pub enum ScanStatisticsPageCommand {
    HistoryLoaded {
        loaded_entries: Result<Vec<ActivityEntryRecord>, ActivityHistoryFailure>,
        definition_freshness: DefinitionFreshness,
    },
}

fn current_unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed_time| elapsed_time.as_secs() as i64)
}

fn inspect_definition_freshness() -> DefinitionFreshness {
    match inspect_database_directory(&configured_database_directory(), SystemTime::now()) {
        DatabaseDirectoryStatus::DefinitionsAvailable {
            newest_definition_age_days,
            ..
        } => DefinitionFreshness::DefinitionsAged {
            age_days: newest_definition_age_days,
        },
        _other_status => DefinitionFreshness::FreshnessUnknown,
    }
}

fn protection_level_text(protection_level: ProtectionLevel) -> String {
    match protection_level {
        ProtectionLevel::Protected => gettext("Protected"),
        ProtectionLevel::AtRisk => gettext("At Risk"),
        ProtectionLevel::Unprotected => gettext("Unprotected"),
    }
}

fn protection_level_class(protection_level: ProtectionLevel) -> &'static str {
    match protection_level {
        ProtectionLevel::Protected => "success",
        ProtectionLevel::AtRisk => "warning",
        ProtectionLevel::Unprotected => "error",
    }
}

fn protection_level_icon(protection_level: ProtectionLevel) -> &'static str {
    match protection_level {
        ProtectionLevel::Protected => "object-select-symbolic",
        ProtectionLevel::AtRisk | ProtectionLevel::Unprotected => "dialog-warning-symbolic",
    }
}

fn protection_reason_text(protection_reason: ProtectionReason) -> String {
    match protection_reason {
        ProtectionReason::NoCompletedScans => gettext("No scans performed yet"),
        ProtectionReason::LastScanOverMonthOld => gettext("Last scan was over 30 days ago"),
        ProtectionReason::LastScanOverWeekOld => gettext("Last scan was over a week ago"),
        ProtectionReason::DefinitionsOverWeekOld => {
            gettext("Virus definitions are over 7 days old")
        }
        ProtectionReason::DefinitionsOverDayOld => gettext("Virus definitions are over 1 day old"),
        ProtectionReason::EverythingCurrent => gettext("System is protected"),
    }
}

fn scan_age_text(scan_age_seconds: i64) -> String {
    if scan_age_seconds < SECONDS_PER_HOUR {
        return gettext("less than an hour ago");
    }
    if scan_age_seconds < SECONDS_PER_DAY {
        let hour_count = scan_age_seconds / SECONDS_PER_HOUR;
        return ngettext("{count} hour ago", "{count} hours ago", hour_count as u32)
            .replace("{count}", &hour_count.to_string());
    }
    let day_count = scan_age_seconds / SECONDS_PER_DAY;
    ngettext("{count} day ago", "{count} days ago", day_count as u32)
        .replace("{count}", &day_count.to_string())
}

impl ScanStatisticsPage {
    fn reload_history(&self, sender: &ComponentSender<Self>) {
        let activity_history = self.activity_history.clone();
        sender.oneshot_command(async move {
            ScanStatisticsPageCommand::HistoryLoaded {
                loaded_entries: activity_history.list_recent_entries().await,
                definition_freshness: spawn_blocking(inspect_definition_freshness)
                    .await
                    .unwrap_or(DefinitionFreshness::FreshnessUnknown),
            }
        });
    }

    fn scan_statistics(&self) -> ScanActivityStatistics {
        summarize_scan_activity(
            &self.listed_entries,
            self.selected_timeframe,
            current_unix_time(),
        )
    }

    fn protection_assessment(&self) -> ProtectionAssessment {
        assess_protection(
            &self.listed_entries,
            self.definition_freshness,
            current_unix_time(),
        )
    }

    fn last_scan_text(&self) -> String {
        match newest_completed_scan(&self.listed_entries) {
            Some(newest_scan) => format!(
                "{} ({})",
                formatted_local_time(newest_scan.started_at_unix),
                scan_age_text(current_unix_time() - newest_scan.started_at_unix)
            ),
            None => gettext("No scans recorded"),
        }
    }

    fn statistics_period_text(&self) -> String {
        gettext("Statistics for: {range}").replace(
            "{range}",
            &format!(
                "{} – {}",
                formatted_local_time(self.scan_statistics().period_start_unix),
                formatted_local_time(current_unix_time())
            ),
        )
    }

    fn average_duration_text(&self) -> String {
        let average_duration_millis = self.scan_statistics().average_duration_millis;
        if average_duration_millis == 0 {
            "—".to_owned()
        } else {
            formatted_duration_text(average_duration_millis)
        }
    }

    fn refresh_chart(&self) {
        replace_chart_columns(
            &self.activity_chart,
            &self.scan_statistics().activity_buckets,
        );
    }
}

fn timeframe_button(
    button_label: String,
    timeframe: StatisticsTimeframe,
    sender: &ComponentSender<ScanStatisticsPage>,
) -> gtk::ToggleButton {
    let timeframe_button = gtk::ToggleButton::builder()
        .label(button_label)
        .active(timeframe == StatisticsTimeframe::LastWeek)
        .build();
    let input_sender = sender.input_sender().clone();
    timeframe_button.connect_toggled(move |toggled_button| {
        if toggled_button.is_active() {
            input_sender.emit(ScanStatisticsPageInput::TimeframeSelected(timeframe));
        }
    });
    timeframe_button
}

#[relm4::component(pub)]
impl Component for ScanStatisticsPage {
    type Init = ActivityHistory;
    type Input = ScanStatisticsPageInput;
    type Output = ();
    type CommandOutput = ScanStatisticsPageCommand;

    view! {
        #[template]
        ClampedPage {
            #[template_child]
            page_content {
                gtk::Label {
                    set_xalign: 0.0,
                    set_wrap: true,
                    add_css_class: "error",
                    #[watch]
                    set_visible: !model.page_notice.is_empty(),
                    #[watch]
                    set_label: &model.page_notice,
                },

                adw::PreferencesGroup {
                    set_title: &gettext("Protection Status"),
                    set_description: Some(&gettext("Based on scans run from ClamUI and the age of the virus definitions")),
                    #[wrap(Some)]
                    set_header_suffix = &gtk::Button {
                        set_icon_name: "view-refresh-symbolic",
                        set_tooltip_text: Some(&gettext("Refresh")),
                        set_valign: gtk::Align::Center,
                        add_css_class: "flat",
                        connect_clicked => ScanStatisticsPageInput::ReloadRequested,
                    },

                    adw::ActionRow {
                        set_title: &gettext("System Status"),
                        #[watch]
                        set_subtitle: &protection_reason_text(model.protection_assessment().protection_reason),

                        add_prefix = &gtk::Image {
                            #[watch]
                            set_icon_name: Some(protection_level_icon(model.protection_assessment().protection_level)),
                        },

                        add_suffix = &gtk::Label {
                            #[watch]
                            set_label: &protection_level_text(model.protection_assessment().protection_level),
                            #[watch]
                            set_css_classes: &[protection_level_class(model.protection_assessment().protection_level)],
                        },
                    },

                    adw::ActionRow {
                        set_title: &gettext("Last Scan"),
                        #[watch]
                        set_subtitle: &model.last_scan_text(),

                        add_prefix = &gtk::Image {
                            set_icon_name: Some("document-open-recent-symbolic"),
                        },
                    },
                },

                adw::PreferencesGroup {
                    set_title: &gettext("Timeframe"),
                    set_description: Some(&gettext("Select the time period for statistics")),

                    #[name = "timeframe_box"]
                    gtk::Box {
                        add_css_class: "linked",
                        set_halign: gtk::Align::Center,
                    },
                },

                adw::PreferencesGroup {
                    set_title: &gettext("Scan Statistics"),
                    #[watch]
                    set_description: Some(&model.statistics_period_text()),

                    adw::ActionRow {
                        set_title: &gettext("Total Scans"),
                        set_subtitle: &gettext("Number of scans performed"),
                        add_prefix = &gtk::Image { set_icon_name: Some("system-search-symbolic") },
                        add_suffix = &gtk::Label {
                            add_css_class: "title-2",
                            #[watch]
                            set_label: &model.scan_statistics().total_scans.to_string(),
                        },
                    },

                    adw::ActionRow {
                        set_title: &gettext("Files Scanned"),
                        set_subtitle: &gettext("Total files checked"),
                        add_prefix = &gtk::Image { set_icon_name: Some("folder-open-symbolic") },
                        add_suffix = &gtk::Label {
                            add_css_class: "title-2",
                            #[watch]
                            set_label: &model.scan_statistics().files_scanned.to_string(),
                        },
                    },

                    adw::ActionRow {
                        set_title: &gettext("Threats Detected"),
                        set_subtitle: &gettext("Malware and suspicious files found"),
                        add_prefix = &gtk::Image { set_icon_name: Some("dialog-warning-symbolic") },
                        add_suffix = &gtk::Label {
                            add_css_class: "title-2",
                            #[watch]
                            set_label: &model.scan_statistics().threats_detected.to_string(),
                        },
                    },

                    adw::ActionRow {
                        set_title: &gettext("Clean Scans"),
                        set_subtitle: &gettext("Scans with no threats found"),
                        add_prefix = &gtk::Image { set_icon_name: Some("object-select-symbolic") },
                        add_suffix = &gtk::Label {
                            add_css_class: "title-2",
                            #[watch]
                            set_label: &model.scan_statistics().clean_scans.to_string(),
                        },
                    },

                    adw::ActionRow {
                        set_title: &gettext("Average Scan Duration"),
                        set_subtitle: &gettext("Mean time per scan"),
                        add_prefix = &gtk::Image { set_icon_name: Some("document-open-recent-symbolic") },
                        add_suffix = &gtk::Label {
                            add_css_class: "title-2",
                            #[watch]
                            set_label: &model.average_duration_text(),
                        },
                    },
                },

                adw::PreferencesGroup {
                    set_title: &gettext("Scan Activity"),
                    set_description: Some(&gettext("Scan trends over the selected timeframe")),

                    gtk::Box {
                        set_orientation: gtk::Orientation::Vertical,
                        set_spacing: 12,
                        add_css_class: "card",

                        #[local_ref]
                        activity_chart -> gtk::Box {
                            set_homogeneous: true,
                            set_margin_top: 12,
                            set_margin_start: 12,
                            set_margin_end: 12,
                        },

                        append: &chart_legend(&gettext("Scans"), &gettext("Threats")),
                    },
                },

                adw::PreferencesGroup {
                    set_title: &gettext("Quick Actions"),

                    adw::ActionRow {
                        set_title: &gettext("Quick Scan"),
                        set_subtitle: &gettext("Scan your home directory"),
                        set_activatable: true,
                        set_action_name: Some("app.quick-scan"),
                        add_suffix = &gtk::Image { set_icon_name: Some("go-next-symbolic") },
                    },

                    adw::ActionRow {
                        set_title: &gettext("View Scan Logs"),
                        set_subtitle: &gettext("See detailed scan history"),
                        set_activatable: true,
                        set_action_name: Some("win.show-page"),
                        set_action_target: Some(&"logs".to_variant()),
                        add_suffix = &gtk::Image { set_icon_name: Some("go-next-symbolic") },
                    },
                },
            },
        }
    }

    fn init(
        activity_history: ActivityHistory,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let timeframe_buttons = vec![
            timeframe_button(gettext("Day"), StatisticsTimeframe::LastDay, &sender),
            timeframe_button(gettext("Week"), StatisticsTimeframe::LastWeek, &sender),
            timeframe_button(gettext("Month"), StatisticsTimeframe::LastMonth, &sender),
            timeframe_button(gettext("All Time"), StatisticsTimeframe::AllTime, &sender),
        ];
        let model = Self {
            activity_history,
            listed_entries: Vec::new(),
            definition_freshness: DefinitionFreshness::FreshnessUnknown,
            selected_timeframe: StatisticsTimeframe::LastWeek,
            page_notice: String::new(),
            timeframe_buttons,
            activity_chart: gtk::Box::default(),
        };
        let activity_chart = model.activity_chart.clone();
        let widgets = view_output!();
        model.timeframe_buttons.iter().for_each(|timeframe_button| {
            if let Some(first_button) = model.timeframe_buttons.first()
                && first_button != timeframe_button
            {
                timeframe_button.set_group(Some(first_button));
            }
            widgets.timeframe_box.append(timeframe_button);
        });
        model.refresh_chart();
        model.reload_history(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: ScanStatisticsPageInput,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_input {
            ScanStatisticsPageInput::ReloadRequested => self.reload_history(&sender),
            ScanStatisticsPageInput::TimeframeSelected(selected_timeframe) => {
                self.selected_timeframe = selected_timeframe;
                self.refresh_chart();
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: ScanStatisticsPageCommand,
        _sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            ScanStatisticsPageCommand::HistoryLoaded {
                loaded_entries,
                definition_freshness,
            } => {
                self.definition_freshness = definition_freshness;
                match loaded_entries {
                    Ok(listed_entries) => {
                        self.page_notice.clear();
                        self.listed_entries = listed_entries;
                        self.refresh_chart();
                    }
                    Err(load_failure) => {
                        self.page_notice = gettext("Failed to load statistics: {error}")
                            .replace("{error}", &load_failure.to_string());
                    }
                }
            }
        }
    }
}

use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    gtk::glib,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::application_window::{
    page_links::{SHOW_PAGE_ACTION, page_target},
    sidebar_navigation::sidebar_entry_presentation::{
        EntrySummary, SCAN_FILES_ACTION, SidebarRowKind, SidebarRowPresentation,
        sidebar_row_presentation,
    },
};

pub struct SidebarEntryRow {
    pub row_kind: SidebarRowKind,
    pub entry_summary: EntrySummary,
}

const fn row_action_name(row_kind: SidebarRowKind) -> &'static str {
    match row_kind {
        SidebarRowKind::ScanFilesAction => SCAN_FILES_ACTION,
        SidebarRowKind::PageEntry(_) => SHOW_PAGE_ACTION,
    }
}

fn row_action_target(row_kind: SidebarRowKind) -> Option<glib::Variant> {
    match row_kind {
        SidebarRowKind::ScanFilesAction => None,
        SidebarRowKind::PageEntry(application_page) => Some(page_target(application_page)),
    }
}

const fn row_is_selectable(row_kind: SidebarRowKind) -> bool {
    match row_kind {
        SidebarRowKind::ScanFilesAction => false,
        SidebarRowKind::PageEntry(_) => true,
    }
}

impl SidebarEntryRow {
    fn row_presentation(&self) -> SidebarRowPresentation {
        sidebar_row_presentation(self.row_kind, &self.entry_summary)
    }
}

#[relm4::factory(pub)]
impl FactoryComponent for SidebarEntryRow {
    type Init = SidebarRowKind;
    type Input = ();
    type Output = ();
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        adw::ActionRow {
            set_use_markup: false,
            set_activatable: true,
            set_selectable: row_is_selectable(self.row_kind),
            set_action_name: Some(row_action_name(self.row_kind)),
            set_action_target_value: row_action_target(self.row_kind).as_ref(),
            #[watch]
            set_title: &self.row_presentation().row_title,
            #[watch]
            set_subtitle: &self.row_presentation().row_subtitle,

            add_prefix = &gtk::Image {
                #[watch]
                set_icon_name: Some(self.row_presentation().prefix_icon),
            },

            add_suffix = &gtk::Image {
                set_valign: gtk::Align::Center,
                #[watch]
                set_visible: self.row_presentation().status_image.is_shown(),
                #[watch]
                set_icon_name: Some(self.row_presentation().status_image.icon_name()),
                #[watch]
                set_css_classes: self.row_presentation().status_image.css_classes(),
                #[watch]
                set_tooltip_text: Some(&self.row_presentation().status_image.tooltip_text()),
            },
        }
    }

    fn init_model(
        row_kind: Self::Init,
        _row_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self {
            row_kind,
            entry_summary: EntrySummary::SummaryPending,
        }
    }
}

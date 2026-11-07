use relm4::{adw, adw::prelude::*, gtk};

pub const LOADING_PAGE_NAME: &str = "loading";
pub const LOADED_PAGE_NAME: &str = "loaded";
pub const LOAD_FAILED_PAGE_NAME: &str = "load-failed";
pub const IDLE_PAGE_NAME: &str = "idle";
pub const BUSY_PAGE_NAME: &str = "busy";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirstLoad {
    StillLoading,
    LoadFinished,
}

impl FirstLoad {
    pub const fn shown_page_name(self) -> &'static str {
        match self {
            Self::StillLoading => LOADING_PAGE_NAME,
            Self::LoadFinished => LOADED_PAGE_NAME,
        }
    }
}

pub const fn busy_page_name(work_running: bool) -> &'static str {
    if work_running {
        BUSY_PAGE_NAME
    } else {
        IDLE_PAGE_NAME
    }
}

pub fn loading_status_page(loading_title: &str) -> adw::StatusPage {
    let status_page = adw::StatusPage::builder()
        .title(loading_title)
        .css_classes(["compact"])
        .build();
    status_page.set_paintable(Some(&adw::SpinnerPaintable::new(Some(&status_page))));
    status_page
}

pub fn loading_placeholder_row(loading_title: &str) -> adw::ActionRow {
    let placeholder_row = empty_placeholder_row(loading_title);
    placeholder_row.add_suffix(&adw::Spinner::new());
    placeholder_row
}

pub fn empty_placeholder_row(empty_title: &str) -> adw::ActionRow {
    adw::ActionRow::builder()
        .title(empty_title)
        .use_markup(false)
        .css_classes(["dim-label"])
        .build()
}

pub fn loading_placeholder_stack(
    loading_title: &str,
    empty_page: &impl IsA<gtk::Widget>,
) -> gtk::Stack {
    let placeholder_stack = gtk::Stack::new();
    placeholder_stack.add_named(
        &loading_placeholder_row(loading_title),
        Some(LOADING_PAGE_NAME),
    );
    placeholder_stack.add_named(empty_page, Some(LOADED_PAGE_NAME));
    placeholder_stack.set_visible_child_name(LOADING_PAGE_NAME);
    placeholder_stack
}

#[cfg(test)]
mod loading_indicators_tests {
    use super::*;

    #[test]
    fn page_names_follow_the_loading_state() {
        assert_eq!(FirstLoad::StillLoading.shown_page_name(), LOADING_PAGE_NAME);
        assert_eq!(FirstLoad::LoadFinished.shown_page_name(), LOADED_PAGE_NAME);
        assert_eq!(busy_page_name(true), BUSY_PAGE_NAME);
        assert_eq!(busy_page_name(false), IDLE_PAGE_NAME);
    }
}

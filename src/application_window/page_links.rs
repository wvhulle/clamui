use relm4::{adw::prelude::*, gtk};

use crate::application_window::application_pages::ApplicationPage;

pub const SHOW_PAGE_ACTION: &str = "win.show-page";

pub fn page_target(linked_page: ApplicationPage) -> gtk::glib::Variant {
    linked_page.page_name().to_variant()
}

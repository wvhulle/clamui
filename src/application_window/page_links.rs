use gettextrs::gettext;
use relm4::{adw, adw::prelude::*, gtk};

use crate::application_window::application_pages::ApplicationPage;

const SHOW_PAGE_ACTION: &str = "win.show-page";

fn page_link_subtitle(linked_page: ApplicationPage) -> String {
    match linked_page {
        ApplicationPage::Protection => gettext("What protects your files right now"),
        ApplicationPage::Detections => gettext("Background detections and how alerts reach you"),
        ApplicationPage::Scan => gettext("Scan files and folders, and the folders scans skip"),
        ApplicationPage::RemovableDrives => {
            gettext("Scan removable drives when they are connected")
        }
        ApplicationPage::Logs => gettext("Past scans, updates and system changes"),
        ApplicationPage::Quarantine => gettext("Files isolated from your system"),
        ApplicationPage::Analysis => gettext("Files and detections that ClamAV never reports"),
        ApplicationPage::Signatures => gettext("Where ClamAV's signatures come from"),
        ApplicationPage::DatabaseUpdates => gettext("How freshclam downloads signatures"),
        ApplicationPage::ScanEngine => {
            gettext("clamd settings, unwanted programs, macros and archives")
        }
        ApplicationPage::OnAccessScanning => {
            gettext("Which folders clamonacc watches, and how it blocks")
        }
        ApplicationPage::ScheduledScans => gettext("Scan automatically with a systemd timer"),
        ApplicationPage::Hardening => gettext("Protections outside ClamAV"),
    }
}

pub fn page_link_row(linked_page: ApplicationPage) -> adw::ActionRow {
    let link_row = adw::ActionRow::builder()
        .title(linked_page.page_title())
        .subtitle(page_link_subtitle(linked_page))
        .activatable(true)
        .action_name(SHOW_PAGE_ACTION)
        .action_target(&linked_page.page_name().to_variant())
        .build();
    link_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    link_row
}

pub fn page_link_group(
    group_title: String,
    linked_pages: &[ApplicationPage],
) -> adw::PreferencesGroup {
    let link_group = adw::PreferencesGroup::builder().title(group_title).build();
    linked_pages
        .iter()
        .for_each(|linked_page| link_group.add(&page_link_row(*linked_page)));
    link_group
}

pub fn system_settings_group(linked_pages: &[ApplicationPage]) -> adw::PreferencesGroup {
    let system_group = page_link_group(gettext("System"), linked_pages);
    system_group.set_description(Some(&gettext(
        "ClamAV configuration shared by all users is on these pages. Changes need administrator \
         approval.",
    )));
    system_group
}

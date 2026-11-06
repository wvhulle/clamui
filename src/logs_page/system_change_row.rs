use gettextrs::gettext;
use relm4::{FactorySender, adw, adw::prelude::*, gtk, prelude::FactoryComponent};

use crate::host_services::{
    desktop::locale_formatting::exact_local_time_text,
    settings_helper::helper_audit_records::HelperAuditEntry,
};

pub enum SystemChangeRow {
    ChangeRecorded(HelperAuditEntry),
    ListNotice(String),
}

impl SystemChangeRow {
    fn row_title(&self) -> String {
        match self {
            Self::ChangeRecorded(audit_entry) => audit_entry.action_subject.clone(),
            Self::ListNotice(notice_text) => notice_text.clone(),
        }
    }

    fn row_subtitle(&self) -> String {
        match self {
            Self::ChangeRecorded(audit_entry) => {
                gettext("{time} · {outcome} · requested by user {uid}")
                    .replace("{time}", &exact_local_time_text(audit_entry.recorded_at))
                    .replace("{outcome}", &audit_entry.audited_outcome.described())
                    .replace("{uid}", &audit_entry.requester_uid)
            }
            Self::ListNotice(_notice_text) => String::new(),
        }
    }

    fn lowered_protection(&self) -> bool {
        matches!(self, Self::ChangeRecorded(audit_entry) if audit_entry.lowered_protection())
    }

    const fn is_notice(&self) -> bool {
        matches!(self, Self::ListNotice(_))
    }
}

#[relm4::factory(pub)]
impl FactoryComponent for SystemChangeRow {
    type Init = Self;
    type Input = ();
    type Output = ();
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        adw::ActionRow {
            set_use_markup: false,
            set_title: &self.row_title(),
            set_title_lines: 0,
            set_subtitle: &self.row_subtitle(),
            set_css_classes: if self.is_notice() { &["dim-label"] } else { &[] },

            add_prefix = &gtk::Image {
                set_icon_name: Some("dialog-warning-symbolic"),
                set_tooltip_text: Some(&gettext("This change lowered protection")),
                add_css_class: "warning",
                set_visible: self.lowered_protection(),
            },
        }
    }

    fn init_model(
        system_change: Self::Init,
        _row_index: &Self::Index,
        _sender: FactorySender<Self>,
    ) -> Self {
        system_change
    }
}

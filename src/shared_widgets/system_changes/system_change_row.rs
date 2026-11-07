use gettextrs::gettext;
use relm4::{FactorySender, adw, adw::prelude::*, gtk, prelude::FactoryComponent};

use crate::host_services::{
    clamav_admin_service::admin_audit_records::{AdminAuditEntry, Requester},
    desktop::locale_formatting::exact_local_time_text,
};

pub struct SystemChangeRow {
    audit_entry: AdminAuditEntry,
}

impl SystemChangeRow {
    fn row_subtitle(&self) -> String {
        match self.audit_entry.requester {
            Requester::KnownUser { user_id } => {
                gettext("{time} · {outcome} · requested by user {uid}")
                    .replace("{uid}", &user_id.to_string())
            }
            Requester::UnknownUser => gettext("{time} · {outcome} · requested by an unknown user"),
        }
        .replace(
            "{time}",
            &exact_local_time_text(self.audit_entry.recorded_at),
        )
        .replace("{outcome}", &self.audit_entry.audited_outcome.described())
    }
}

#[relm4::factory(pub)]
impl FactoryComponent for SystemChangeRow {
    type Init = AdminAuditEntry;
    type Input = ();
    type Output = ();
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        adw::ActionRow {
            set_use_markup: false,
            set_title: &self.audit_entry.action_subject,
            set_title_lines: 0,
            set_subtitle: &self.row_subtitle(),

            add_prefix = &gtk::Image {
                set_icon_name: Some("dialog-warning-symbolic"),
                set_tooltip_text: Some(&gettext("This change lowered protection")),
                add_css_class: "warning",
                set_visible: self.audit_entry.lowered_protection(),
            },
        }
    }

    fn init_model(
        audit_entry: Self::Init,
        _row_index: &Self::Index,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self { audit_entry }
    }
}

use gettextrs::gettext;
use relm4::{FactorySender, adw, adw::prelude::*, gtk};

use crate::system_audit::{
    audit_report_model::{AuditCheck, AuditStatus, CheckGuidance},
    audit_section_group::{AuditGuidanceRequest, AuditSectionGroup},
};

pub fn status_indicator_image(check_status: AuditStatus) -> gtk::Image {
    let status_label = check_status.status_label();
    let indicator_image = gtk::Image::builder()
        .icon_name(check_status.status_icon_name())
        .tooltip_text(&status_label)
        .valign(gtk::Align::Center)
        .css_classes([check_status.status_style_class()])
        .build();
    indicator_image.update_property(&[gtk::accessible::Property::Label(&status_label)]);
    indicator_image
}

fn recommendation_row(recommendation_text: &str) -> adw::ActionRow {
    adw::ActionRow::builder()
        .use_markup(false)
        .title(recommendation_text)
        .title_lines(0)
        .build()
}

fn suggested_command_row(
    suggested_command: &'static str,
    sender: &FactorySender<AuditSectionGroup>,
) -> adw::ActionRow {
    let command_label = gtk::Label::builder()
        .label(suggested_command)
        .use_markup(false)
        .selectable(true)
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .hexpand(true)
        .xalign(0.0)
        .css_classes(["monospace"])
        .build();
    let copy_button = gtk::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text(gettext("Copy"))
        .valign(gtk::Align::Center)
        .css_classes(["flat"])
        .build();
    let row_sender = sender.clone();
    copy_button.connect_clicked(move |_clicked_button| {
        let _parent_gone = row_sender.output(AuditGuidanceRequest::CopyCommandRequested(
            suggested_command.to_owned(),
        ));
    });
    let command_row = adw::ActionRow::new();
    command_row.add_prefix(&command_label);
    command_row.add_suffix(&copy_button);
    command_row
}

fn documentation_row(
    documentation_url: &'static str,
    sender: &FactorySender<AuditSectionGroup>,
) -> adw::ActionRow {
    let documentation_row = adw::ActionRow::builder()
        .use_markup(false)
        .title(gettext("Learn more"))
        .tooltip_text(gettext("Open in browser"))
        .activatable(true)
        .build();
    documentation_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    let row_sender = sender.clone();
    documentation_row.connect_activated(move |_activated_row| {
        let _parent_gone = row_sender.output(AuditGuidanceRequest::OpenDocumentationRequested(
            documentation_url,
        ));
    });
    documentation_row
}

fn guidance_row(
    check_guidance: &CheckGuidance,
    sender: &FactorySender<AuditSectionGroup>,
) -> adw::ActionRow {
    match check_guidance {
        CheckGuidance::RecommendationText(recommendation_text) => {
            recommendation_row(recommendation_text)
        }
        CheckGuidance::SuggestedCommand(suggested_command) => {
            suggested_command_row(suggested_command, sender)
        }
        CheckGuidance::DocumentationLink(documentation_url) => {
            documentation_row(documentation_url, sender)
        }
    }
}

pub fn checking_placeholder_row() -> gtk::Widget {
    adw::ActionRow::builder()
        .use_markup(false)
        .title(gettext("Checking"))
        .css_classes(["dim-label"])
        .build()
        .upcast()
}

pub fn audit_check_row(
    audit_check: &AuditCheck,
    sender: &FactorySender<AuditSectionGroup>,
) -> gtk::Widget {
    let status_image = status_indicator_image(audit_check.check_status);
    if audit_check.check_guidance.is_empty() {
        let plain_row = adw::ActionRow::builder()
            .use_markup(false)
            .title(&audit_check.check_name)
            .subtitle(&audit_check.status_detail)
            .subtitle_lines(0)
            .build();
        plain_row.add_suffix(&status_image);
        return plain_row.upcast();
    }
    let expander_row = adw::ExpanderRow::builder()
        .use_markup(false)
        .title(&audit_check.check_name)
        .subtitle(&audit_check.status_detail)
        .subtitle_lines(0)
        .expanded(audit_check.expanded_by_default())
        .build();
    expander_row.add_suffix(&status_image);
    audit_check
        .check_guidance
        .iter()
        .for_each(|check_guidance| {
            expander_row.add_row(&guidance_row(check_guidance, sender));
        });
    expander_row.upcast()
}

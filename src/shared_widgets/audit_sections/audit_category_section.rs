use gettextrs::gettext;
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::shared_widgets::{
    audit_sections::{
        audit_check_results::{AuditCategory, AuditSection, AuditStatus},
        audit_check_row::{audit_check_row, checking_placeholder_row},
    },
    loading_indicators::{BUSY_PAGE_NAME, IDLE_PAGE_NAME, busy_page_name},
};

pub struct AuditCategorySection {
    audit_section: AuditSection,
    displayed_rows: Vec<gtk::Widget>,
}

#[derive(Debug)]
pub enum AuditCategorySectionInput {
    SectionChanged(AuditSection),
}

#[derive(Debug)]
pub enum AuditCategorySectionOutput {
    CopyCommandRequested(String),
    OpenDocumentationRequested(&'static str),
}

impl AuditCategorySection {
    fn replace_displayed_rows(
        &mut self,
        section_group: &adw::PreferencesGroup,
        sender: &FactorySender<Self>,
    ) {
        self.displayed_rows
            .drain(..)
            .for_each(|displayed_row| section_group.remove(&displayed_row));
        self.displayed_rows = if self.audit_section.section_checks.is_empty() {
            vec![checking_placeholder_row()]
        } else {
            self.audit_section
                .section_checks
                .iter()
                .map(|audit_check| audit_check_row(audit_check, sender))
                .collect()
        };
        self.displayed_rows
            .iter()
            .for_each(|displayed_row| section_group.add(displayed_row));
    }
}

#[relm4::factory(pub)]
impl FactoryComponent for AuditCategorySection {
    type Init = AuditCategory;
    type Input = AuditCategorySectionInput;
    type Output = AuditCategorySectionOutput;
    type CommandOutput = ();
    type ParentWidget = adw::PreferencesPage;

    view! {
        #[root]
        #[name = "section_group"]
        adw::PreferencesGroup {
            set_title: &self.audit_section.audit_category.section_title(),
            #[wrap(Some)]
            set_header_suffix = &gtk::Stack {
              set_valign: gtk::Align::Center,
              add_named[Some(BUSY_PAGE_NAME)] = &adw::Spinner {
                set_tooltip_text: Some(&gettext("Checking")),
              },
              add_named[Some(IDLE_PAGE_NAME)] = &gtk::Image {
                #[watch]
                set_icon_name: Some(self.audit_section.overall_status().status_icon_name()),
                #[watch]
                set_tooltip_text: Some(&self.audit_section.overall_status().status_label()),
                #[watch]
                set_css_classes: &[self.audit_section.overall_status().status_style_class()],
              },
              #[watch]
              set_visible_child_name: busy_page_name(self.audit_section.overall_status() == AuditStatus::CheckInProgress),
            },
        }
    }

    fn init_model(
        audit_category: AuditCategory,
        _group_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self {
            audit_section: AuditSection::awaiting_checks(audit_category),
            displayed_rows: Vec::new(),
        }
    }

    fn init_widgets(
        &mut self,
        _group_index: &DynamicIndex,
        root: Self::Root,
        _returned_widget: &<Self::ParentWidget as relm4::factory::FactoryView>::ReturnedWidget,
        sender: FactorySender<Self>,
    ) -> Self::Widgets {
        let widgets = view_output!();
        self.replace_displayed_rows(&widgets.section_group, &sender);
        widgets
    }

    fn update_with_view(
        &mut self,
        widgets: &mut Self::Widgets,
        group_input: AuditCategorySectionInput,
        sender: FactorySender<Self>,
    ) {
        match group_input {
            AuditCategorySectionInput::SectionChanged(audit_section) => {
                self.audit_section = audit_section;
                self.replace_displayed_rows(&widgets.section_group, &sender);
            }
        }
        self.update_view(widgets, sender);
    }
}

use gettextrs::gettext;
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent, FactoryVecDeque},
};

use crate::shared_widgets::{
    audit_sections::{
        audit_check_results::{AuditCategory, AuditSection, AuditStatus},
        audit_check_row::{AuditCheckRow, AuditCheckRowOutput},
    },
    loading_indicators::{BUSY_PAGE_NAME, IDLE_PAGE_NAME, busy_page_name},
};

pub struct AuditCategorySection {
    audit_section: AuditSection,
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

pub struct AuditCategorySectionWidgets {
    status_stack: gtk::Stack,
    status_image: gtk::Image,
    check_rows: FactoryVecDeque<AuditCheckRow>,
}

impl AuditCategorySection {
    fn shown_check_rows(&self) -> Vec<AuditCheckRow> {
        if self.audit_section.section_checks.is_empty() {
            vec![AuditCheckRow::CheckingPlaceholder]
        } else {
            self.audit_section
                .section_checks
                .iter()
                .cloned()
                .map(AuditCheckRow::CheckShown)
                .collect()
        }
    }
}

fn forwarded_check_output(check_output: AuditCheckRowOutput) -> AuditCategorySectionOutput {
    match check_output {
        AuditCheckRowOutput::CopyCommandRequested(copied_command) => {
            AuditCategorySectionOutput::CopyCommandRequested(copied_command)
        }
        AuditCheckRowOutput::DocumentationRequested(documentation_url) => {
            AuditCategorySectionOutput::OpenDocumentationRequested(documentation_url)
        }
    }
}

impl FactoryComponent for AuditCategorySection {
    type ParentWidget = adw::PreferencesPage;
    type CommandOutput = ();
    type Input = AuditCategorySectionInput;
    type Output = AuditCategorySectionOutput;
    type Init = AuditCategory;
    type Root = adw::PreferencesGroup;
    type Widgets = AuditCategorySectionWidgets;
    type Index = DynamicIndex;

    fn init_model(
        audit_category: AuditCategory,
        _group_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self {
            audit_section: AuditSection::awaiting_checks(audit_category),
        }
    }

    fn init_root(&self) -> Self::Root {
        adw::PreferencesGroup::builder()
            .title(self.audit_section.audit_category.section_title())
            .build()
    }

    fn init_widgets(
        &mut self,
        _group_index: &DynamicIndex,
        root: Self::Root,
        _returned_widget: &<Self::ParentWidget as relm4::factory::FactoryView>::ReturnedWidget,
        sender: FactorySender<Self>,
    ) -> Self::Widgets {
        let status_image = gtk::Image::new();
        let status_stack = gtk::Stack::builder().valign(gtk::Align::Center).build();
        status_stack.add_named(
            &adw::Spinner::builder()
                .tooltip_text(gettext("Checking"))
                .build(),
            Some(BUSY_PAGE_NAME),
        );
        status_stack.add_named(&status_image, Some(IDLE_PAGE_NAME));
        root.set_header_suffix(Some(&status_stack));
        let mut widgets = AuditCategorySectionWidgets {
            status_stack,
            status_image,
            check_rows: FactoryVecDeque::builder()
                .launch(root)
                .forward(sender.output_sender(), forwarded_check_output),
        };
        self.update_view(&mut widgets, sender);
        widgets
    }

    fn update(&mut self, group_input: Self::Input, _sender: FactorySender<Self>) {
        match group_input {
            AuditCategorySectionInput::SectionChanged(audit_section) => {
                self.audit_section = audit_section;
            }
        }
    }

    fn update_view(&self, widgets: &mut Self::Widgets, _sender: FactorySender<Self>) {
        let overall_status = self.audit_section.overall_status();
        widgets
            .status_image
            .set_icon_name(Some(overall_status.status_icon_name()));
        widgets
            .status_image
            .set_tooltip_text(Some(&overall_status.status_label()));
        widgets
            .status_image
            .set_css_classes(&[overall_status.status_style_class()]);
        widgets.status_stack.set_visible_child_name(busy_page_name(
            overall_status == AuditStatus::CheckInProgress,
        ));
        let mut row_guard = widgets.check_rows.guard();
        row_guard.clear();
        self.shown_check_rows().into_iter().for_each(|check_row| {
            row_guard.push_back(check_row);
        });
    }
}

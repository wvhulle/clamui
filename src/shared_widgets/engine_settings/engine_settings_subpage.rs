use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller,
    abstractions::Toaster, adw, adw::prelude::*,
};

use crate::shared_widgets::engine_settings::engine_settings_sections::{
    EngineSettingsLayout, EngineSettingsNotice, EngineSettingsSection, EngineSettingsSections,
    EngineSettingsSectionsOutput, engine_settings_notice_toast,
};

pub struct EngineSettingsSubpage {
    toaster: Toaster,
    settings_sections: Controller<EngineSettingsSections>,
}

#[derive(Debug)]
pub enum EngineSettingsSubpageInput {
    SettingsNoticeReceived(EngineSettingsNotice),
}

pub fn subpage_input_for_sections_output(
    sections_output: EngineSettingsSectionsOutput,
) -> EngineSettingsSubpageInput {
    match sections_output {
        EngineSettingsSectionsOutput::ToastRequested(settings_notice) => {
            EngineSettingsSubpageInput::SettingsNoticeReceived(settings_notice)
        }
    }
}

#[relm4::component(pub)]
impl Component for EngineSettingsSubpage {
    type Init = EngineSettingsSection;
    type Input = EngineSettingsSubpageInput;
    type Output = ();
    type CommandOutput = ();

    view! {
        adw::ToastOverlay {
            adw::PreferencesPage {
                set_title: &settings_section.page_title(),
                set_icon_name: Some(settings_section.page_icon()),
                add: model.settings_sections.widget(),
            },
        }
    }

    fn init(
        settings_section: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = Self {
            toaster: Toaster::new(&root),
            settings_sections: EngineSettingsSections::builder()
                .launch(EngineSettingsLayout::SingleSection(settings_section))
                .forward(sender.input_sender(), subpage_input_for_sections_output),
        };
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        subpage_input: EngineSettingsSubpageInput,
        _sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match subpage_input {
            EngineSettingsSubpageInput::SettingsNoticeReceived(settings_notice) => {
                self.toaster
                    .add_toast(engine_settings_notice_toast(&settings_notice));
            }
        }
    }
}

#[cfg(test)]
mod engine_settings_subpage_tests {
    use super::*;
    use crate::shared_widgets::engine_settings::engine_settings_sections::describe_engine_settings_notice;

    #[test]
    fn a_settings_toast_request_becomes_the_subpage_notice() {
        let EngineSettingsSubpageInput::SettingsNoticeReceived(received_notice) =
            subpage_input_for_sections_output(EngineSettingsSectionsOutput::ToastRequested(
                EngineSettingsNotice::StaleConfirmationDropped,
            ));
        assert!(matches!(
            received_notice,
            EngineSettingsNotice::StaleConfirmationDropped
        ));
        assert_eq!(
            describe_engine_settings_notice(&received_notice),
            "The change was not made: the settings locked again or another change started first."
        );
    }
}

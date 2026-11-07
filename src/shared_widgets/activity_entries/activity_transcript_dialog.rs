use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, abstractions::Toaster, adw, adw::prelude::*, gtk,
};

use crate::{
    host_services::{
        activity_history::activity_history_database::ActivityEntryRecord,
        desktop::locale_formatting::exact_local_time_text,
    },
    shared_widgets::activity_entries::activity_export_formats::{
        activity_detail_text, activity_summary_text,
    },
};

pub struct ActivityTranscriptDialog {
    transcript_title: String,
    transcript_text: String,
    toaster: Toaster,
}

#[derive(Debug)]
pub enum ActivityTranscriptDialogInput {
    CopyRequested,
}

pub fn transcript_text_of(activity_entry: &ActivityEntryRecord) -> String {
    activity_detail_text(
        activity_entry,
        &exact_local_time_text(activity_entry.started_at),
    )
}

#[relm4::component(pub)]
impl Component for ActivityTranscriptDialog {
    type Init = ActivityEntryRecord;
    type Input = ActivityTranscriptDialogInput;
    type Output = ();
    type CommandOutput = ();

    view! {
        adw::Dialog {
            set_title: &model.transcript_title,
            set_content_width: 640,
            set_content_height: 520,

            #[wrap(Some)]
            #[local_ref]
            set_child = transcript_overlay -> adw::ToastOverlay {
                adw::ToolbarView {
                    add_top_bar = &adw::HeaderBar {
                        pack_start = &gtk::Button {
                            set_icon_name: "edit-copy-symbolic",
                            set_tooltip_text: Some(&gettext("Copy")),
                            connect_clicked => ActivityTranscriptDialogInput::CopyRequested,
                        },
                    },

                    #[wrap(Some)]
                    set_content = &gtk::ScrolledWindow {
                        set_vexpand: true,
                        set_hscrollbar_policy: gtk::PolicyType::Never,

                        gtk::TextView {
                            set_editable: false,
                            set_monospace: true,
                            set_wrap_mode: gtk::WrapMode::WordChar,
                            set_top_margin: 12,
                            set_bottom_margin: 12,
                            set_left_margin: 12,
                            set_right_margin: 12,
                            #[wrap(Some)]
                            set_buffer = &gtk::TextBuffer {
                                set_text: &model.transcript_text,
                            },
                        },
                    },
                },
            },
        }
    }

    fn init(
        activity_entry: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let transcript_overlay = &adw::ToastOverlay::new();
        let model = Self {
            transcript_title: activity_summary_text(&activity_entry),
            transcript_text: transcript_text_of(&activity_entry),
            toaster: Toaster::new(transcript_overlay),
        };
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        dialog_input: ActivityTranscriptDialogInput,
        _sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match dialog_input {
            ActivityTranscriptDialogInput::CopyRequested => {
                root.clipboard().set_text(&self.transcript_text);
                self.toaster
                    .toast(&gettext("Log details copied to clipboard"));
            }
        }
    }
}

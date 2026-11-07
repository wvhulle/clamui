use relm4::{gtk, gtk::prelude::*, typed_view::list::RelmListItem};

use crate::{
    host_services::desktop::locale_formatting::log_local_time_text,
    shared_widgets::service_log::service_log_state::ShownLogRow,
};

const LEVEL_STYLE_CLASSES: [&str; 3] = ["error", "warning", "dim-label"];

pub struct LogEntryWidgets {
    level_icon: gtk::Image,
    level_label: gtk::Label,
    time_label: gtk::Label,
    sender_label: gtk::Label,
    message_label: gtk::Label,
}

fn plain_text_label(style_classes: &[&str]) -> gtk::Label {
    gtk::Label::builder()
        .use_markup(false)
        .xalign(0.0)
        .css_classes(
            style_classes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        )
        .build()
}

impl RelmListItem for ShownLogRow {
    type Root = gtk::Box;
    type Widgets = LogEntryWidgets;

    fn setup(_list_item: &gtk::ListItem) -> (Self::Root, Self::Widgets) {
        let entry_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(2)
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(12)
            .margin_end(12)
            .build();
        let heading_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let level_icon = gtk::Image::new();
        let level_label = plain_text_label(&["caption-heading"]);
        let time_label = plain_text_label(&["caption", "numeric", "dim-label"]);
        let sender_label = plain_text_label(&["caption", "dim-label"]);
        sender_label.set_ellipsize(gtk::pango::EllipsizeMode::End);
        heading_box.append(&level_icon);
        heading_box.append(&level_label);
        heading_box.append(&time_label);
        heading_box.append(&sender_label);
        let message_label = plain_text_label(&["monospace"]);
        message_label.set_wrap(true);
        message_label.set_wrap_mode(gtk::pango::WrapMode::WordChar);
        entry_box.append(&heading_box);
        entry_box.append(&message_label);
        (
            entry_box,
            LogEntryWidgets {
                level_icon,
                level_label,
                time_label,
                sender_label,
                message_label,
            },
        )
    }

    fn bind(&mut self, entry_widgets: &mut Self::Widgets, _entry_box: &mut Self::Root) {
        let level_icon_name = self.row_level.level_icon_name();
        entry_widgets.level_icon.set_icon_name(level_icon_name);
        entry_widgets
            .level_icon
            .set_visible(level_icon_name.is_some());
        let level_text = self.row_level.level_label_text();
        entry_widgets
            .level_label
            .set_visible(!level_text.is_empty());
        entry_widgets.level_label.set_label(&level_text);
        for level_widget in [
            entry_widgets.level_icon.upcast_ref::<gtk::Widget>(),
            entry_widgets.level_label.upcast_ref(),
        ] {
            LEVEL_STYLE_CLASSES
                .iter()
                .for_each(|style_class| level_widget.remove_css_class(style_class));
            level_widget.add_css_class(self.row_level.level_style_class().unwrap_or("dim-label"));
        }
        entry_widgets
            .time_label
            .set_label(&self.logged_at.map_or_else(String::new, log_local_time_text));
        entry_widgets
            .time_label
            .set_visible(self.logged_at.is_some());
        entry_widgets.sender_label.set_label(&self.sender_text);
        entry_widgets
            .sender_label
            .set_visible(!self.sender_text.is_empty());
        entry_widgets.message_label.set_label(&self.message_text);
    }
}

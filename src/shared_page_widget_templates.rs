use relm4::{RelmWidgetExt, WidgetTemplate, adw, gtk, gtk::prelude::*};

#[relm4::widget_template(pub)]
impl WidgetTemplate for ClampedPage {
    view! {
        gtk::ScrolledWindow {
            set_propagate_natural_height: true,
            set_vexpand: true,

            adw::Clamp {
                set_maximum_size: 720,
                set_margin_all: 24,

                #[name = "page_content"]
                gtk::Box {
                    set_orientation: gtk::Orientation::Vertical,
                    set_spacing: 18,
                },
            },
        }
    }
}

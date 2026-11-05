use gettextrs::gettext;
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::network_sockets::socket_listing_parser::{NetworkSocket, SocketRole};

pub struct NetworkSocketRow {
    network_socket: NetworkSocket,
}

#[derive(Debug)]
pub enum NetworkSocketRowOutput {
    CopyAddressRequested(String),
}

fn socket_row_title(network_socket: &NetworkSocket) -> String {
    let local_text = network_socket.local_endpoint.formatted_endpoint();
    match &network_socket.socket_role {
        SocketRole::ListeningSocket => local_text,
        SocketRole::ConnectedSocket { remote_endpoint } => {
            format!("{local_text} → {}", remote_endpoint.formatted_endpoint())
        }
    }
}

fn socket_role_label(network_socket: &NetworkSocket) -> String {
    if network_socket.is_listening() {
        gettext("Listening and bound")
    } else {
        gettext("Connection")
    }
}

fn socket_process_summary(network_socket: &NetworkSocket) -> String {
    if network_socket.owning_processes.is_empty() {
        return gettext("Process information unavailable");
    }
    network_socket
        .owning_processes
        .iter()
        .map(|owning_process| {
            let process_id_text =
                gettext("PID {pid}").replace("{pid}", &owning_process.process_id.to_string());
            format!("{} · {process_id_text}", owning_process.process_name)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn copy_address_button(
    address_label: &str,
    copied_address: String,
    sender: &FactorySender<NetworkSocketRow>,
) -> gtk::Button {
    let copy_button = gtk::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text(gettext("Copy {label}").replace("{label}", address_label))
        .valign(gtk::Align::Center)
        .css_classes(["flat"])
        .build();
    let row_sender = sender.clone();
    copy_button.connect_clicked(move |_clicked_button| {
        let _parent_gone = row_sender.output(NetworkSocketRowOutput::CopyAddressRequested(
            copied_address.clone(),
        ));
    });
    copy_button
}

#[relm4::factory(pub)]
impl FactoryComponent for NetworkSocketRow {
    type Init = NetworkSocket;
    type Input = ();
    type Output = NetworkSocketRowOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        #[root]
        adw::ActionRow {
            set_use_markup: false,
            set_title: &socket_row_title(&self.network_socket),
            set_title_lines: 0,
            set_subtitle: &format!(
                "{} · {}",
                socket_role_label(&self.network_socket),
                socket_process_summary(&self.network_socket),
            ),
            set_subtitle_lines: 0,

            add_prefix = &gtk::Label {
                set_label: self.network_socket.socket_protocol.protocol_label(),
                set_width_chars: 4,
                add_css_class: "caption-heading",
                add_css_class: "dim-label",
            },

            add_suffix = &gtk::Label {
                set_label: &self.network_socket.socket_state,
                add_css_class: "caption",
                add_css_class: "dim-label",
            },
        }
    }

    fn init_model(
        network_socket: NetworkSocket,
        _row_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self { network_socket }
    }

    fn init_widgets(
        &mut self,
        _row_index: &DynamicIndex,
        root: Self::Root,
        _returned_widget: &<Self::ParentWidget as relm4::factory::FactoryView>::ReturnedWidget,
        sender: FactorySender<Self>,
    ) -> Self::Widgets {
        let widgets = view_output!();
        root.add_suffix(&copy_address_button(
            &gettext("Local address"),
            self.network_socket.local_endpoint.formatted_endpoint(),
            &sender,
        ));
        if let SocketRole::ConnectedSocket { remote_endpoint } = &self.network_socket.socket_role {
            root.add_suffix(&copy_address_button(
                &gettext("Remote address"),
                remote_endpoint.formatted_endpoint(),
                &sender,
            ));
        }
        widgets
    }
}

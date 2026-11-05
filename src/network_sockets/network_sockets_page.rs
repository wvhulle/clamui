use gettextrs::{gettext, ngettext};
use relm4::{
    Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk, gtk::glib,
    prelude::FactoryVecDeque,
};

use crate::{
    network_sockets::{
        network_socket_row::{NetworkSocketRow, NetworkSocketRowOutput},
        socket_listing_parser::{
            NetworkSocket, ParsedSockets, SocketRoleFilter, socket_matches_view,
        },
        socket_listing_probe::{SocketListingFailure, probe_socket_listing},
    },
    shared_page_widget_templates::ClampedPage,
};

const SHOWN_ROWS_PER_PAGE: usize = 50;
const ROLE_FILTER_CHOICES: [SocketRoleFilter; 3] = [
    SocketRoleFilter::AllSockets,
    SocketRoleFilter::ListenersOnly,
    SocketRoleFilter::ConnectionsOnly,
];

enum SocketListingState {
    NotYetStarted,
    SocketsListed {
        parsed_sockets: ParsedSockets,
        captured_time: String,
    },
    ListingFailed(SocketListingFailure),
}

pub struct NetworkSocketsPage {
    socket_rows: FactoryVecDeque<NetworkSocketRow>,
    listing_state: SocketListingState,
    listing_in_progress: bool,
    role_filter: SocketRoleFilter,
    search_query: String,
    shown_row_limit: usize,
    matching_socket_count: usize,
}

#[derive(Debug)]
pub enum NetworkSocketsPageInput {
    PageBecameVisible,
    RefreshRequested,
    RoleFilterChanged(u32),
    SearchQueryChanged(String),
    LoadMoreRequested,
    CopyAddressRequested(String),
}

#[derive(Debug)]
pub enum NetworkSocketsPageCommand {
    ListingFinished(Result<ParsedSockets, SocketListingFailure>),
}

fn describe_listing_failure(listing_failure: SocketListingFailure) -> String {
    match listing_failure {
        SocketListingFailure::ToolTimedOut => {
            gettext("Network socket listing timed out. Try again.")
        }
        SocketListingFailure::OutputTooLarge => {
            gettext("Network socket listing could not be completed safely. Try again.")
        }
        SocketListingFailure::ToolUnavailable => gettext(
            "Network information is unavailable. Check that the system socket tool is installed \
             and try again.",
        ),
    }
}

fn captured_time_text() -> String {
    glib::DateTime::now_local()
        .and_then(|current_time| current_time.format("%X"))
        .map(|formatted_time| formatted_time.to_string())
        .unwrap_or_default()
}

impl NetworkSocketsPage {
    fn start_listing(&mut self, sender: &ComponentSender<Self>) {
        self.listing_in_progress = true;
        sender.oneshot_command(async {
            NetworkSocketsPageCommand::ListingFinished(probe_socket_listing().await)
        });
    }

    fn listed_sockets(&self) -> &[NetworkSocket] {
        match &self.listing_state {
            SocketListingState::SocketsListed { parsed_sockets, .. } => {
                &parsed_sockets.listed_sockets
            }
            SocketListingState::NotYetStarted | SocketListingState::ListingFailed(_) => &[],
        }
    }

    fn rebuild_visible_rows(&mut self) {
        let matching_sockets = self
            .listed_sockets()
            .iter()
            .filter(|network_socket| {
                socket_matches_view(network_socket, self.role_filter, &self.search_query)
            })
            .cloned()
            .collect::<Vec<_>>();
        self.matching_socket_count = matching_sockets.len();
        let shown_row_limit = self.shown_row_limit;
        let mut row_guard = self.socket_rows.guard();
        row_guard.clear();
        matching_sockets
            .into_iter()
            .take(shown_row_limit)
            .for_each(|network_socket| {
                row_guard.push_back(network_socket);
            });
    }

    fn shown_row_count(&self) -> usize {
        self.socket_rows.len()
    }

    fn empty_state_visible(&self) -> bool {
        self.matching_socket_count == 0
            && (!self.listing_in_progress
                || matches!(self.listing_state, SocketListingState::NotYetStarted))
    }

    fn empty_state_title(&self) -> String {
        match &self.listing_state {
            SocketListingState::NotYetStarted => gettext("Loading network connections…"),
            SocketListingState::ListingFailed(listing_failure) => {
                describe_listing_failure(*listing_failure)
            }
            SocketListingState::SocketsListed { parsed_sockets, .. }
                if parsed_sockets.listed_sockets.is_empty()
                    && parsed_sockets.unparsed_line_count > 0 =>
            {
                gettext("No socket records could be read from this snapshot.")
            }
            SocketListingState::SocketsListed { parsed_sockets, .. }
                if parsed_sockets.listed_sockets.is_empty() =>
            {
                gettext("No network sockets were found in this snapshot.")
            }
            SocketListingState::SocketsListed { .. } => {
                gettext("No sockets match the current filters.")
            }
        }
    }

    fn incomplete_listing_notice(&self) -> String {
        match &self.listing_state {
            SocketListingState::SocketsListed { parsed_sockets, .. }
                if parsed_sockets.list_was_limited =>
            {
                gettext("The socket list was limited. This snapshot may be incomplete.")
            }
            SocketListingState::SocketsListed { parsed_sockets, .. }
                if parsed_sockets.unparsed_line_count > 0 =>
            {
                gettext("Some socket records could not be read. This snapshot may be incomplete.")
            }
            SocketListingState::NotYetStarted
            | SocketListingState::ListingFailed(_)
            | SocketListingState::SocketsListed { .. } => String::new(),
        }
    }

    fn capture_time_text(&self) -> String {
        match &self.listing_state {
            SocketListingState::SocketsListed { captured_time, .. } => {
                gettext("Captured at {time}").replace("{time}", captured_time)
            }
            SocketListingState::NotYetStarted | SocketListingState::ListingFailed(_) => {
                String::new()
            }
        }
    }

    fn shown_count_text(&self) -> String {
        ngettext(
            "Showing {shown} of {count} matching socket",
            "Showing {shown} of {count} matching sockets",
            u32::try_from(self.matching_socket_count).unwrap_or(u32::MAX),
        )
        .replace("{shown}", &self.shown_row_count().to_string())
        .replace("{count}", &self.matching_socket_count.to_string())
    }
}

#[relm4::component(pub)]
impl Component for NetworkSocketsPage {
    type Init = ();
    type Input = NetworkSocketsPageInput;
    type Output = ();
    type CommandOutput = NetworkSocketsPageCommand;

    view! {
        adw::ToastOverlay {
            #[wrap(Some)]
            #[template]
            set_child = &ClampedPage {
                #[template_child]
                page_content {
                    adw::PreferencesGroup {
                        set_title: &gettext("Network Connections"),
                        set_description: Some(&gettext("View the current listening ports and socket peers from one local snapshot.")),
                        #[wrap(Some)]
                        set_header_suffix = &gtk::Button {
                            set_icon_name: "view-refresh-symbolic",
                            set_tooltip_text: Some(&gettext("Refresh")),
                            set_valign: gtk::Align::Center,
                            add_css_class: "flat",
                            #[watch]
                            set_sensitive: !model.listing_in_progress,
                            connect_clicked => NetworkSocketsPageInput::RefreshRequested,
                        },
                    },

                    gtk::Box {
                        set_spacing: 6,

                        gtk::SearchEntry {
                            set_hexpand: true,
                            set_placeholder_text: Some(&gettext("Search address, port, process, or PID")),
                            connect_search_changed[sender] => move |search_entry| {
                                sender.input(NetworkSocketsPageInput::SearchQueryChanged(search_entry.text().to_string()));
                            },
                        },

                        gtk::DropDown {
                            set_tooltip_text: Some(&gettext("Network socket filter")),
                            set_model: Some(&gtk::StringList::new(&[
                                &gettext("All"),
                                &gettext("Listening and bound"),
                                &gettext("Connections"),
                            ])),
                            connect_selected_notify[sender] => move |filter_dropdown| {
                                sender.input(NetworkSocketsPageInput::RoleFilterChanged(filter_dropdown.selected()));
                            },
                        },
                    },

                    gtk::Label {
                        set_wrap: true,
                        set_xalign: 0.0,
                        add_css_class: "dim-label",
                        add_css_class: "caption",
                        set_label: &gettext("Process ownership depends on system permissions. Unavailable process information does not mean that no process owns the socket."),
                    },

                    gtk::Label {
                        set_wrap: true,
                        set_xalign: 0.0,
                        add_css_class: "warning",
                        #[watch]
                        set_label: &model.incomplete_listing_notice(),
                        #[watch]
                        set_visible: !model.incomplete_listing_notice().is_empty(),
                    },

                    gtk::Label {
                        set_xalign: 0.0,
                        add_css_class: "dim-label",
                        add_css_class: "caption",
                        #[watch]
                        set_label: &model.capture_time_text(),
                        #[watch]
                        set_visible: !model.capture_time_text().is_empty(),
                    },

                    adw::StatusPage {
                        set_icon_name: Some("dialog-information-symbolic"),
                        add_css_class: "compact",
                        #[watch]
                        set_title: &model.empty_state_title(),
                        #[watch]
                        set_visible: model.empty_state_visible(),
                    },

                    #[local_ref]
                    socket_list -> gtk::ListBox {
                        set_selection_mode: gtk::SelectionMode::None,
                        add_css_class: "boxed-list",
                        #[watch]
                        set_visible: model.shown_row_count() > 0,
                    },

                    gtk::Box {
                        set_spacing: 12,
                        #[watch]
                        set_visible: model.matching_socket_count > 0,

                        gtk::Label {
                            set_hexpand: true,
                            set_xalign: 0.0,
                            set_wrap: true,
                            add_css_class: "dim-label",
                            #[watch]
                            set_label: &model.shown_count_text(),
                        },

                        gtk::Button {
                            set_label: &gettext("Load More"),
                            #[watch]
                            set_visible: model.shown_row_count() < model.matching_socket_count,
                            connect_clicked => NetworkSocketsPageInput::LoadMoreRequested,
                        },
                    },
                },
            },
        }
    }

    fn init(
        _page_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let socket_rows = FactoryVecDeque::builder()
            .launch(gtk::ListBox::default())
            .forward(sender.input_sender(), |row_output| match row_output {
                NetworkSocketRowOutput::CopyAddressRequested(copied_address) => {
                    NetworkSocketsPageInput::CopyAddressRequested(copied_address)
                }
            });
        let model = Self {
            socket_rows,
            listing_state: SocketListingState::NotYetStarted,
            listing_in_progress: false,
            role_filter: SocketRoleFilter::AllSockets,
            search_query: String::new(),
            shown_row_limit: SHOWN_ROWS_PER_PAGE,
            matching_socket_count: 0,
        };
        let socket_list = model.socket_rows.widget();
        let widgets = view_output!();
        let visibility_sender = sender.clone();
        root.connect_map(move |_mapped_page| {
            visibility_sender.input(NetworkSocketsPageInput::PageBecameVisible);
        });
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: NetworkSocketsPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            NetworkSocketsPageInput::PageBecameVisible => {
                if matches!(self.listing_state, SocketListingState::NotYetStarted)
                    && !self.listing_in_progress
                {
                    self.start_listing(&sender);
                }
            }
            NetworkSocketsPageInput::RefreshRequested => self.start_listing(&sender),
            NetworkSocketsPageInput::RoleFilterChanged(filter_position) => {
                self.role_filter = usize::try_from(filter_position)
                    .ok()
                    .and_then(|choice_position| ROLE_FILTER_CHOICES.get(choice_position))
                    .copied()
                    .unwrap_or(SocketRoleFilter::AllSockets);
                self.shown_row_limit = SHOWN_ROWS_PER_PAGE;
                self.rebuild_visible_rows();
            }
            NetworkSocketsPageInput::SearchQueryChanged(search_query) => {
                self.search_query = search_query;
                self.shown_row_limit = SHOWN_ROWS_PER_PAGE;
                self.rebuild_visible_rows();
            }
            NetworkSocketsPageInput::LoadMoreRequested => {
                self.shown_row_limit += SHOWN_ROWS_PER_PAGE;
                self.rebuild_visible_rows();
            }
            NetworkSocketsPageInput::CopyAddressRequested(copied_address) => {
                root.clipboard().set_text(&copied_address);
                root.add_toast(adw::Toast::new(&gettext("Address copied to clipboard")));
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: NetworkSocketsPageCommand,
        _sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            NetworkSocketsPageCommand::ListingFinished(listing_outcome) => {
                self.listing_in_progress = false;
                self.listing_state = match listing_outcome {
                    Ok(parsed_sockets) => SocketListingState::SocketsListed {
                        parsed_sockets,
                        captured_time: captured_time_text(),
                    },
                    Err(listing_failure) => SocketListingState::ListingFailed(listing_failure),
                };
                self.shown_row_limit = SHOWN_ROWS_PER_PAGE;
                self.rebuild_visible_rows();
            }
        }
    }
}

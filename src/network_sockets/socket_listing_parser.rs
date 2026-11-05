use std::net::IpAddr;

use crate::malware_scan::scanner_output_parser::sanitize_scanner_line;

pub const MAX_LISTED_SOCKETS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketProtocol {
    TcpProtocol,
    UdpProtocol,
}

impl SocketProtocol {
    pub fn protocol_label(self) -> &'static str {
        match self {
            Self::TcpProtocol => "TCP",
            Self::UdpProtocol => "UDP",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointPort {
    WildcardPort,
    NumberedPort(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketEndpoint {
    pub endpoint_address: String,
    pub endpoint_port: EndpointPort,
}

impl SocketEndpoint {
    pub fn formatted_endpoint(&self) -> String {
        match self.endpoint_port {
            EndpointPort::WildcardPort => self.endpoint_address.clone(),
            EndpointPort::NumberedPort(port_number) if self.endpoint_address.contains(':') => {
                format!("[{}]:{port_number}", self.endpoint_address)
            }
            EndpointPort::NumberedPort(port_number) => {
                format!("{}:{port_number}", self.endpoint_address)
            }
        }
    }

    pub fn is_loopback(&self) -> bool {
        self.endpoint_address
            .split('%')
            .next()
            .and_then(|unscoped_address| unscoped_address.parse::<IpAddr>().ok())
            .is_some_and(|parsed_address| parsed_address.to_canonical().is_loopback())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwningProcess {
    pub process_name: String,
    pub process_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocketRole {
    ListeningSocket,
    ConnectedSocket { remote_endpoint: SocketEndpoint },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkSocket {
    pub socket_protocol: SocketProtocol,
    pub socket_state: String,
    pub socket_role: SocketRole,
    pub local_endpoint: SocketEndpoint,
    pub owning_processes: Vec<OwningProcess>,
}

impl NetworkSocket {
    pub fn is_listening(&self) -> bool {
        self.socket_role == SocketRole::ListeningSocket
    }

    fn search_text(&self) -> String {
        let role_details = match &self.socket_role {
            SocketRole::ListeningSocket => "listener".to_owned(),
            SocketRole::ConnectedSocket { remote_endpoint } => {
                format!("connection {}", remote_endpoint.formatted_endpoint())
            }
        };
        let process_details = self
            .owning_processes
            .iter()
            .map(|owning_process| {
                format!(
                    "{} {}",
                    owning_process.process_name, owning_process.process_id
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "{} {} {} {role_details} {process_details}",
            self.socket_protocol.protocol_label(),
            self.socket_state,
            self.local_endpoint.formatted_endpoint(),
        )
        .to_lowercase()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketRoleFilter {
    AllSockets,
    ListenersOnly,
    ConnectionsOnly,
}

pub fn socket_matches_view(
    network_socket: &NetworkSocket,
    role_filter: SocketRoleFilter,
    search_query: &str,
) -> bool {
    let role_accepted = match role_filter {
        SocketRoleFilter::AllSockets => true,
        SocketRoleFilter::ListenersOnly => network_socket.is_listening(),
        SocketRoleFilter::ConnectionsOnly => !network_socket.is_listening(),
    };
    let normalized_query = search_query.trim().to_lowercase();
    role_accepted
        && (normalized_query.is_empty() || network_socket.search_text().contains(&normalized_query))
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParsedSockets {
    pub listed_sockets: Vec<NetworkSocket>,
    pub unparsed_line_count: usize,
    pub list_was_limited: bool,
}

pub fn parse_socket_listing(listing_text: &str) -> ParsedSockets {
    listing_text
        .lines()
        .filter(|listing_line| !listing_line.trim().is_empty())
        .fold(
            ParsedSockets::default(),
            |mut parsed_sockets, listing_line| {
                match parse_socket_line(listing_line) {
                    None => parsed_sockets.unparsed_line_count += 1,
                    Some(_excess_socket)
                        if parsed_sockets.listed_sockets.len() == MAX_LISTED_SOCKETS =>
                    {
                        parsed_sockets.list_was_limited = true;
                    }
                    Some(network_socket) => parsed_sockets.listed_sockets.push(network_socket),
                }
                parsed_sockets
            },
        )
}

fn next_listing_column<'line>(remaining_text: &mut &'line str) -> Option<&'line str> {
    let trimmed_text = remaining_text.trim_start();
    let column_length = trimmed_text
        .find(char::is_whitespace)
        .unwrap_or(trimmed_text.len());
    if column_length == 0 {
        return None;
    }
    let split_columns = trimmed_text.split_at(column_length);
    *remaining_text = split_columns.1;
    Some(split_columns.0)
}

pub fn parse_socket_line(listing_line: &str) -> Option<NetworkSocket> {
    let mut remaining_text = listing_line;
    let network_identifier = next_listing_column(&mut remaining_text)?;
    let socket_state = next_listing_column(&mut remaining_text)?;
    next_listing_column(&mut remaining_text)?;
    next_listing_column(&mut remaining_text)?;
    let local_endpoint = parse_listing_endpoint(next_listing_column(&mut remaining_text)?)?;
    let peer_endpoint = parse_listing_endpoint(next_listing_column(&mut remaining_text)?)?;

    let socket_protocol = match network_identifier {
        "tcp" | "tcp6" => SocketProtocol::TcpProtocol,
        "udp" | "udp6" => SocketProtocol::UdpProtocol,
        _other_identifier => return None,
    };
    if !is_supported_state(socket_protocol, socket_state) {
        return None;
    }
    let bound_state = match socket_protocol {
        SocketProtocol::TcpProtocol => "LISTEN",
        SocketProtocol::UdpProtocol => "UNCONN",
    };
    let socket_role = match peer_endpoint {
        ParsedListingEndpoint::WildcardEndpoint { .. } if socket_state == bound_state => {
            SocketRole::ListeningSocket
        }
        ParsedListingEndpoint::SpecificEndpoint(remote_endpoint) if socket_state != bound_state => {
            SocketRole::ConnectedSocket { remote_endpoint }
        }
        ParsedListingEndpoint::WildcardEndpoint { .. }
        | ParsedListingEndpoint::SpecificEndpoint(_) => return None,
    };

    Some(NetworkSocket {
        socket_protocol,
        socket_state: socket_state.to_owned(),
        socket_role,
        local_endpoint: local_endpoint.into_socket_endpoint(),
        owning_processes: parse_owning_processes(remaining_text),
    })
}

fn is_supported_state(socket_protocol: SocketProtocol, socket_state: &str) -> bool {
    match socket_protocol {
        SocketProtocol::TcpProtocol => matches!(
            socket_state,
            "ESTAB"
                | "SYN-SENT"
                | "SYN-RECV"
                | "FIN-WAIT-1"
                | "FIN-WAIT-2"
                | "TIME-WAIT"
                | "CLOSE"
                | "CLOSE-WAIT"
                | "LAST-ACK"
                | "LISTEN"
                | "CLOSING"
                | "NEW-SYN-RECV"
        ),
        SocketProtocol::UdpProtocol => matches!(socket_state, "UNCONN" | "ESTAB" | "CLOSE"),
    }
}

enum ParsedListingEndpoint {
    WildcardEndpoint { wildcard_endpoint: SocketEndpoint },
    SpecificEndpoint(SocketEndpoint),
}

impl ParsedListingEndpoint {
    fn into_socket_endpoint(self) -> SocketEndpoint {
        match self {
            Self::WildcardEndpoint { wildcard_endpoint } => wildcard_endpoint,
            Self::SpecificEndpoint(specific_endpoint) => specific_endpoint,
        }
    }
}

enum EndpointScope<'endpoint> {
    UnscopedAddress,
    ScopedAddress(&'endpoint str),
}

struct EndpointParts<'endpoint> {
    address_text: &'endpoint str,
    address_scope: EndpointScope<'endpoint>,
    port_text: &'endpoint str,
}

fn parse_listing_endpoint(endpoint_text: &str) -> Option<ParsedListingEndpoint> {
    let endpoint_parts = split_endpoint_parts(endpoint_text)?;
    let endpoint_port = parse_endpoint_port(endpoint_parts.port_text)?;
    if endpoint_parts.address_text == "*"
        && matches!(endpoint_parts.address_scope, EndpointScope::UnscopedAddress)
    {
        return Some(ParsedListingEndpoint::WildcardEndpoint {
            wildcard_endpoint: SocketEndpoint {
                endpoint_address: "*".to_owned(),
                endpoint_port,
            },
        });
    }

    let inline_scope = endpoint_parts.address_text.split_once('%');
    let raw_address = inline_scope
        .as_ref()
        .map_or(endpoint_parts.address_text, |address_and_scope| {
            address_and_scope.0
        });
    let effective_scope = match (&endpoint_parts.address_scope, &inline_scope) {
        (EndpointScope::ScopedAddress(_), Some(_duplicate_scope)) => return None,
        (EndpointScope::ScopedAddress(trailing_scope), None) => Some(*trailing_scope),
        (EndpointScope::UnscopedAddress, Some(address_and_scope)) => Some(address_and_scope.1),
        (EndpointScope::UnscopedAddress, None) => None,
    };
    let parsed_address = raw_address.parse::<IpAddr>().ok()?;
    if !effective_scope.is_none_or(is_valid_interface_scope) {
        return None;
    }
    let canonical_address = effective_scope.map_or_else(
        || parsed_address.to_string(),
        |interface_scope| format!("{parsed_address}%{interface_scope}"),
    );
    let socket_endpoint = SocketEndpoint {
        endpoint_address: canonical_address,
        endpoint_port,
    };
    Some(if parsed_address.is_unspecified() {
        ParsedListingEndpoint::WildcardEndpoint {
            wildcard_endpoint: socket_endpoint,
        }
    } else {
        ParsedListingEndpoint::SpecificEndpoint(socket_endpoint)
    })
}

fn split_endpoint_parts(endpoint_text: &str) -> Option<EndpointParts<'_>> {
    if let Some(bracketed_text) = endpoint_text.strip_prefix('[') {
        let bracket_split = bracketed_text.split_once(']')?;
        let address_text = bracket_split.0;
        if address_text.is_empty() {
            return None;
        }
        if let Some(port_text) = bracket_split.1.strip_prefix(':') {
            return Some(EndpointParts {
                address_text,
                address_scope: EndpointScope::UnscopedAddress,
                port_text,
            });
        }
        let scope_split = bracket_split.1.strip_prefix('%')?.split_once(':')?;
        return Some(EndpointParts {
            address_text,
            address_scope: EndpointScope::ScopedAddress(scope_split.0),
            port_text: scope_split.1,
        });
    }
    let port_split = endpoint_text.rsplit_once(':')?;
    Some(EndpointParts {
        address_text: port_split.0,
        address_scope: EndpointScope::UnscopedAddress,
        port_text: port_split.1,
    })
}

fn parse_endpoint_port(port_text: &str) -> Option<EndpointPort> {
    if port_text == "*" {
        return Some(EndpointPort::WildcardPort);
    }
    port_text.parse().ok().map(EndpointPort::NumberedPort)
}

fn is_valid_interface_scope(interface_scope: &str) -> bool {
    !interface_scope.is_empty()
        && interface_scope.len() <= 15
        && interface_scope.bytes().all(|scope_byte| {
            scope_byte.is_ascii_alphanumeric() || matches!(scope_byte, b'_' | b'.' | b'-')
        })
}

struct ProcessEntryParse<'listing> {
    owning_process: OwningProcess,
    remaining_text: &'listing str,
}

fn closing_quote_position(quoted_text: &str) -> Option<usize> {
    quoted_text
        .bytes()
        .enumerate()
        .scan(false, |previous_was_escape, positioned_byte| {
            let is_closing_quote = !*previous_was_escape && positioned_byte.1 == b'"';
            *previous_was_escape = !*previous_was_escape && positioned_byte.1 == b'\\';
            Some(is_closing_quote.then_some(positioned_byte.0))
        })
        .flatten()
        .next()
}

fn has_valid_extra_fields(extra_fields: &str) -> bool {
    extra_fields.is_empty()
        || extra_fields.strip_prefix(',').is_some_and(|listed_fields| {
            listed_fields.split(',').all(|extra_field| {
                !extra_field.is_empty()
                    && extra_field.bytes().all(|field_byte| {
                        field_byte.is_ascii_alphanumeric()
                            || matches!(field_byte, b'_' | b'=' | b'.' | b'-')
                    })
            })
        })
}

fn parse_process_entry(entry_text: &str) -> Option<ProcessEntryParse<'_>> {
    let quoted_text = entry_text.strip_prefix("(\"")?;
    let name_length = closing_quote_position(quoted_text)?;
    let raw_process_name = quoted_text.get(..name_length)?;
    let after_process_id_key = quoted_text.get(name_length + 1..)?.strip_prefix(",pid=")?;
    let digit_count = after_process_id_key
        .find(|process_id_character: char| !process_id_character.is_ascii_digit())
        .unwrap_or(after_process_id_key.len());
    let process_id_split = after_process_id_key.split_at(digit_count);
    let process_id = process_id_split.0.parse::<u32>().ok()?;
    if process_id == 0 || i32::try_from(process_id).is_err() {
        return None;
    }
    let extra_field_split = process_id_split.1.split_once(')')?;
    if !has_valid_extra_fields(extra_field_split.0) {
        return None;
    }
    let process_name = sanitize_scanner_line(raw_process_name).trim().to_owned();
    if process_name.is_empty() {
        return None;
    }
    Some(ProcessEntryParse {
        owning_process: OwningProcess {
            process_name,
            process_id,
        },
        remaining_text: extra_field_split.1,
    })
}

fn parse_owning_processes(process_suffix: &str) -> Vec<OwningProcess> {
    let Some(entries_text) = process_suffix.trim().strip_prefix("users:(") else {
        return Vec::new();
    };
    let entry_parses = std::iter::successors(parse_process_entry(entries_text), |previous_entry| {
        previous_entry
            .remaining_text
            .strip_prefix(',')
            .and_then(parse_process_entry)
    })
    .collect::<Vec<_>>();
    let is_complete = entry_parses
        .last()
        .is_some_and(|final_entry| final_entry.remaining_text == ")");
    if !is_complete {
        return Vec::new();
    }
    entry_parses
        .into_iter()
        .map(|entry_parse| entry_parse.owning_process)
        .collect()
}

#[cfg(test)]
mod socket_listing_parser_tests {
    use super::*;

    fn parsed_line(listing_line: &str) -> NetworkSocket {
        parse_socket_line(listing_line).expect("valid socket row")
    }

    fn remote_of(network_socket: &NetworkSocket) -> &SocketEndpoint {
        match &network_socket.socket_role {
            SocketRole::ConnectedSocket { remote_endpoint } => remote_endpoint,
            SocketRole::ListeningSocket => panic!("expected a connected socket"),
        }
    }

    #[test]
    fn parses_numeric_ipv4_ipv6_scopes_wildcards_and_port_boundaries() {
        let ipv4_socket = parsed_line("tcp LISTEN 0 128 0.0.0.0:0 0.0.0.0:*");
        assert_eq!(ipv4_socket.local_endpoint.endpoint_address, "0.0.0.0");
        assert_eq!(
            ipv4_socket.local_endpoint.endpoint_port,
            EndpointPort::NumberedPort(0)
        );
        assert!(ipv4_socket.is_listening());

        let ipv6_socket = parsed_line("tcp ESTAB 0 0 [2001:4860::1]:65535 [2606:4700::1]:443");
        assert_eq!(ipv6_socket.local_endpoint.endpoint_address, "2001:4860::1");
        assert_eq!(
            ipv6_socket.local_endpoint.endpoint_port,
            EndpointPort::NumberedPort(65535)
        );
        assert_eq!(remote_of(&ipv6_socket).endpoint_address, "2606:4700::1");

        let scoped_socket = parsed_line("udp UNCONN 0 0 [2001:4860::1%eth0]:53 [::]:*");
        assert_eq!(
            scoped_socket.local_endpoint.endpoint_address,
            "2001:4860::1%eth0"
        );
        assert!(scoped_socket.is_listening());

        let device_bound_socket = parsed_line(
            "udp ESTAB 0 0 192.0.2.35%enp191s0:68 198.51.100.1%wan0:67 \
             users:((\"dhcp\",pid=42,fd=3))",
        );
        assert_eq!(device_bound_socket.socket_state, "ESTAB");
        assert_eq!(
            device_bound_socket.local_endpoint.endpoint_address,
            "192.0.2.35%enp191s0"
        );
        assert_eq!(
            device_bound_socket.local_endpoint.endpoint_port,
            EndpointPort::NumberedPort(68)
        );
        assert_eq!(
            remote_of(&device_bound_socket).endpoint_address,
            "198.51.100.1%wan0"
        );
        assert_eq!(
            remote_of(&device_bound_socket).endpoint_port,
            EndpointPort::NumberedPort(67)
        );
        assert_eq!(
            device_bound_socket.owning_processes,
            vec![OwningProcess {
                process_name: "dhcp".to_owned(),
                process_id: 42
            }]
        );

        let native_listener = parsed_line("udp UNCONN 0 0 [fe80::1]%eth0:546 [::]:*");
        assert_eq!(native_listener.socket_state, "UNCONN");
        assert_eq!(
            native_listener.local_endpoint.endpoint_address,
            "fe80::1%eth0"
        );
        assert_eq!(
            native_listener.local_endpoint.endpoint_port,
            EndpointPort::NumberedPort(546)
        );
        assert!(native_listener.is_listening());

        let scoped_peer = parsed_line("tcp ESTAB 0 0 [fe80::1]%eth0:80 [fe80::2]%eth1:443");
        assert_eq!(scoped_peer.local_endpoint.endpoint_address, "fe80::1%eth0");
        assert_eq!(remote_of(&scoped_peer).endpoint_address, "fe80::2%eth1");
        assert_eq!(
            remote_of(&scoped_peer).endpoint_port,
            EndpointPort::NumberedPort(443)
        );

        let wildcard_socket = parsed_line("udp UNCONN 0 0 *:* *:*");
        assert_eq!(wildcard_socket.local_endpoint.endpoint_address, "*");
        assert_eq!(
            wildcard_socket.local_endpoint.endpoint_port,
            EndpointPort::WildcardPort
        );
        assert!(wildcard_socket.is_listening());

        [
            "tcp LISTEN 0 0 [::1%bad/scope]:80 [::]:*",
            "tcp LISTEN 0 0 [::1]%bad/scope:80 [::]:*",
            "tcp LISTEN 0 0 [::1]%eth0%extra:80 [::]:*",
            "tcp LISTEN 0 0 [::1%eth0]%wan0:80 [::]:*",
            "tcp LISTEN 0 0 [::1]eth0:80 [::]:*",
            "tcp LISTEN 0 0 192.0.2.35%:80 0.0.0.0:*",
            "tcp LISTEN 0 0 192.0.2.35%bad%scope:80 0.0.0.0:*",
            "tcp LISTEN 0 0 192.0.2.35%scope-name-too-long:80 0.0.0.0:*",
            "tcp LISTEN 0 0 127.0.0.1:65536 0.0.0.0:*",
        ]
        .into_iter()
        .for_each(|invalid_line| {
            assert_eq!(parse_socket_line(invalid_line), None, "{invalid_line}");
        });
    }

    #[test]
    fn distinguishes_tcp_udp_bound_sockets_from_connections_without_direction_claims() {
        let tcp_listener = parsed_line("tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*");
        assert!(tcp_listener.is_listening());

        let tcp_connection = parsed_line("tcp ESTAB 0 0 127.0.0.1:8080 192.0.2.1:55432");
        assert_eq!(
            remote_of(&tcp_connection).endpoint_port,
            EndpointPort::NumberedPort(55432)
        );

        let udp_bound = parsed_line("udp UNCONN 0 0 127.0.0.1:5353 0.0.0.0:*");
        assert!(udp_bound.is_listening());
        let udp_connection = parsed_line("udp ESTAB 0 0 192.0.2.2:5353 192.0.2.3:5354");
        assert!(!udp_connection.is_listening());
        assert_eq!(
            parse_socket_line("tcp ESTAB 0 0 127.0.0.1:1 0.0.0.0:*"),
            None
        );
    }

    #[test]
    fn preserves_only_complete_unambiguous_process_owners() {
        let without_owner = parsed_line("tcp LISTEN 0 128 127.0.0.1:80 0.0.0.0:*");
        assert!(without_owner.owning_processes.is_empty());

        let multiple_owners = parsed_line(
            "tcp LISTEN 0 128 127.0.0.1:80 0.0.0.0:* users:((\"worker \
             one\",pid=41,fd=3),(\"worker two\",pid=42,fd=4))",
        );
        assert_eq!(multiple_owners.owning_processes.len(), 2);
        assert_eq!(
            multiple_owners.owning_processes[0].process_name,
            "worker one"
        );
        assert_eq!(multiple_owners.owning_processes[1].process_id, 42);

        let malformed_owner =
            parsed_line("tcp LISTEN 0 128 127.0.0.1:80 0.0.0.0:* users:((\"name pid=999\",fd=3))");
        assert!(malformed_owner.owning_processes.is_empty());
        let ambiguous_owner =
            parsed_line("tcp LISTEN 0 128 127.0.0.1:80 0.0.0.0:* users:((\"name\",pid=0,fd=3))");
        assert!(ambiguous_owner.owning_processes.is_empty());
        let unterminated_owner =
            parsed_line("tcp LISTEN 0 128 127.0.0.1:80 0.0.0.0:* users:((\"name\",pid=7,fd=3)");
        assert!(unterminated_owner.owning_processes.is_empty());
    }

    #[test]
    fn process_names_keep_escaped_quotes_and_lose_terminal_controls() {
        let escaped_owner = parsed_line(
            "tcp LISTEN 0 128 127.0.0.1:80 0.0.0.0:* users:((\"odd\\\"name\",pid=9,fd=3))",
        );
        assert_eq!(
            escaped_owner.owning_processes[0].process_name,
            "odd\\\"name"
        );
        let control_owner = parsed_line(
            "tcp LISTEN 0 128 127.0.0.1:80 0.0.0.0:* users:((\"bad\u{1b}[31mname\",pid=9,fd=3))",
        );
        assert_eq!(control_owner.owning_processes[0].process_name, "badname");
    }

    #[test]
    fn real_host_listing_lines_are_understood() {
        let listing_text =
            "udp ESTAB      0      0        192.168.178.31:47541      192.168.178.1:53   \nudp \
             UNCONN     0      0        127.0.0.53%lo:53    0.0.0.0:*    \nudp ESTAB      0      \
             0   192.168.178.31%enp12s0:68    192.168.178.1:67   \nudp UNCONN     0      0         \
             0.0.0.0:34549      0.0.0.0:*     users:((\".spotify-wrappe\",pid=2070451,fd=230))\n";
        let parsed_sockets = parse_socket_listing(listing_text);
        assert_eq!(parsed_sockets.unparsed_line_count, 0);
        assert_eq!(parsed_sockets.listed_sockets.len(), 4);
        assert!(
            parsed_sockets.listed_sockets[1]
                .local_endpoint
                .is_loopback()
        );
        assert_eq!(
            parsed_sockets.listed_sockets[3].owning_processes[0].process_name,
            ".spotify-wrappe"
        );
    }

    #[test]
    fn malformed_and_capped_listings_are_counted() {
        let empty_listing = parse_socket_listing("");
        assert!(empty_listing.listed_sockets.is_empty());
        assert_eq!(empty_listing.unparsed_line_count, 0);

        let malformed_listing = parse_socket_listing("not an ss row\n");
        assert!(malformed_listing.listed_sockets.is_empty());
        assert_eq!(malformed_listing.unparsed_line_count, 1);

        let capped_listing = parse_socket_listing(
            &"tcp LISTEN 0 1 127.0.0.1:80 0.0.0.0:*\n".repeat(MAX_LISTED_SOCKETS + 1),
        );
        assert_eq!(capped_listing.listed_sockets.len(), MAX_LISTED_SOCKETS);
        assert!(capped_listing.list_was_limited);
    }

    #[test]
    fn endpoints_format_like_the_address_family_requires() {
        assert_eq!(
            parsed_line("tcp LISTEN 0 1 127.0.0.1:80 0.0.0.0:*")
                .local_endpoint
                .formatted_endpoint(),
            "127.0.0.1:80"
        );
        assert_eq!(
            parsed_line("tcp LISTEN 0 1 [::1]:80 [::]:*")
                .local_endpoint
                .formatted_endpoint(),
            "[::1]:80"
        );
        assert_eq!(
            parsed_line("udp UNCONN 0 0 *:* *:*")
                .local_endpoint
                .formatted_endpoint(),
            "*"
        );
    }

    #[test]
    fn loopback_detection_covers_scopes_and_mapped_addresses() {
        let local_address = |listing_line| parsed_line(listing_line).local_endpoint;
        assert!(local_address("udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*").is_loopback());
        assert!(local_address("tcp LISTEN 0 1 [::1]:631 [::]:*").is_loopback());
        assert!(local_address("tcp LISTEN 0 1 [::ffff:127.0.0.1]:631 [::]:*").is_loopback());
        assert!(!local_address("tcp LISTEN 0 1 0.0.0.0:22 0.0.0.0:*").is_loopback());
        assert!(!local_address("udp UNCONN 0 0 *:5353 *:*").is_loopback());
    }

    #[test]
    fn filters_and_search_narrow_the_visible_sockets() {
        let web_listener = parsed_line(
            "tcp LISTEN 0 1 0.0.0.0:8080 0.0.0.0:* users:((\"NginxWorker\",pid=321,fd=3))",
        );
        let browser_connection = parsed_line("tcp ESTAB 0 0 192.0.2.2:5000 198.51.100.7:443");
        assert!(socket_matches_view(
            &web_listener,
            SocketRoleFilter::AllSockets,
            ""
        ));
        assert!(socket_matches_view(
            &web_listener,
            SocketRoleFilter::ListenersOnly,
            "  nginxworker "
        ));
        assert!(socket_matches_view(
            &web_listener,
            SocketRoleFilter::AllSockets,
            "321"
        ));
        assert!(!socket_matches_view(
            &web_listener,
            SocketRoleFilter::ConnectionsOnly,
            ""
        ));
        assert!(socket_matches_view(
            &browser_connection,
            SocketRoleFilter::ConnectionsOnly,
            "198.51.100.7:443"
        ));
        assert!(!socket_matches_view(
            &browser_connection,
            SocketRoleFilter::AllSockets,
            "nginx"
        ));
    }
}

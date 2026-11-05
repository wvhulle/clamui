use std::collections::{BTreeMap, BTreeSet};

use futures::join;
use gettextrs::{gettext, ngettext};
use serde_json::{Map, Value};

use crate::{
    clamav_components::distribution_install_guides::DistributionFamily,
    network_sockets::{
        socket_listing_parser::{EndpointPort, NetworkSocket},
        socket_listing_probe::probe_socket_listing,
    },
    system_audit::{
        audit_report_model::{AuditCategory, AuditCheck, AuditSection, AuditStatus},
        host_command_probes::{
            CommandProbe, first_active_unit, locate_host_program, run_command_probe,
            systemd_is_available,
        },
        suggested_audit_commands::{
            FIREWALLD_STATUS_COMMAND, IP6TABLES_RULESET_COMMAND, IPTABLES_RULESET_COMMAND,
            NFTABLES_RULESET_COMMAND, SuggestedRemedy, UFW_ENABLE_COMMAND, UFW_STATUS_COMMAND,
            suggested_command,
        },
    },
};

const UFW_DOCUMENTATION_URL: &str = "https://wiki.archlinux.org/title/Uncomplicated_Firewall";
const FIREWALLD_DOCUMENTATION_URL: &str = "https://firewalld.org/documentation/";
const NFTABLES_DOCUMENTATION_URL: &str = "https://wiki.archlinux.org/title/Nftables";
const OPEN_PORTS_DOCUMENTATION_URL: &str =
    "https://wiki.archlinux.org/title/Security#Network_and_firewalls";

const NIXOS_FIREWALL_UNIT: &str = "firewall.service";
const FIREWALL_SERVICE_UNITS: [&str; 5] = [
    NIXOS_FIREWALL_UNIT,
    "firewalld.service",
    "ufw.service",
    "nftables.service",
    "iptables.service",
];
const FIREWALLD_OWNER_PROBE_ARGUMENTS: [&str; 12] = [
    "--system",
    "--auto-start=no",
    "--allow-interactive-authorization=no",
    "--timeout=2",
    "--json=short",
    "call",
    "org.freedesktop.DBus",
    "/org/freedesktop/DBus",
    "org.freedesktop.DBus",
    "NameHasOwner",
    "s",
    "org.fedoraproject.FirewallD1",
];

struct RiskyPort {
    port_number: u16,
    service_name: &'static str,
}

const RISKY_PORTS: [RiskyPort; 6] = [
    RiskyPort {
        port_number: 23,
        service_name: "Telnet",
    },
    RiskyPort {
        port_number: 135,
        service_name: "RPC",
    },
    RiskyPort {
        port_number: 139,
        service_name: "NetBIOS",
    },
    RiskyPort {
        port_number: 445,
        service_name: "SMB",
    },
    RiskyPort {
        port_number: 3389,
        service_name: "RDP",
    },
    RiskyPort {
        port_number: 5900,
        service_name: "VNC",
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncomingPolicy {
    DenyIncoming,
    RejectIncoming,
    AllowIncoming,
    UnverifiedPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UfwState {
    FirewallActive {
        incoming_policy: IncomingPolicy,
        listed_exceptions: bool,
    },
    FirewallInactive,
    StateUndetermined,
    ProgramNotInstalled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewalldOwner {
    NameOwned,
    NameUnowned,
    OwnershipUndetermined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FamilyEvidence {
    RestrictivePolicy,
    PermissivePolicy,
    NoInputChain,
    IncompleteEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NftablesAssessment {
    pub ipv4_evidence: FamilyEvidence,
    pub ipv6_evidence: FamilyEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NftablesEvidence {
    RulesetAssessed(NftablesAssessment),
    RulesetUnreadable,
    NftablesNotInstalled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IptablesEvidence {
    PolicyObserved(FamilyEvidence),
    PolicyUnreadable,
    IptablesNotInstalled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewallServiceEvidence {
    ActiveUnit(&'static str),
    NoActiveUnit,
    SystemdMissing,
}

pub fn parse_ufw_status(status_text: &str) -> UfwState {
    let reported_states = status_text
        .lines()
        .filter_map(|status_line| match status_line {
            "Status: active" => Some(true),
            "Status: inactive" => Some(false),
            _other_line => None,
        })
        .collect::<Vec<_>>();
    match reported_states.as_slice() {
        [false] => UfwState::FirewallInactive,
        [true] => UfwState::FirewallActive {
            incoming_policy: parse_ufw_incoming_policy(status_text),
            listed_exceptions: status_text.lines().any(ufw_line_lists_exception),
        },
        _ambiguous_states => UfwState::StateUndetermined,
    }
}

fn parse_ufw_incoming_policy(status_text: &str) -> IncomingPolicy {
    status_text
        .lines()
        .find_map(|status_line| status_line.strip_prefix("Default: "))
        .and_then(|default_policies| {
            default_policies
                .split(',')
                .find_map(|default_policy| default_policy.trim().strip_suffix(" (incoming)"))
        })
        .map_or(
            IncomingPolicy::UnverifiedPolicy,
            |incoming_policy| match incoming_policy {
                "deny" => IncomingPolicy::DenyIncoming,
                "reject" => IncomingPolicy::RejectIncoming,
                "allow" => IncomingPolicy::AllowIncoming,
                _other_policy => IncomingPolicy::UnverifiedPolicy,
            },
        )
}

fn ufw_line_lists_exception(status_line: &str) -> bool {
    status_line
        .split_whitespace()
        .skip_while(|line_field| !matches!(*line_field, "ALLOW" | "DENY" | "REJECT"))
        .skip(1)
        .any(|line_field| line_field == "IN")
}

pub fn inspect_ufw_probe(ufw_probe: &CommandProbe) -> UfwState {
    if *ufw_probe == CommandProbe::ProgramMissing {
        return UfwState::ProgramNotInstalled;
    }
    ufw_probe
        .verified_text()
        .map_or(UfwState::StateUndetermined, parse_ufw_status)
}

pub fn ufw_check(ufw_state: UfwState) -> AuditCheck {
    let check_name = gettext("UFW Firewall");
    let ufw_row = match ufw_state {
        UfwState::FirewallActive {
            incoming_policy: IncomingPolicy::DenyIncoming,
            listed_exceptions: true,
        } => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext(
                "UFW is active; the default incoming policy is deny. Listed rules may allow \
                 exceptions.",
            ),
        ),
        UfwState::FirewallActive {
            incoming_policy: IncomingPolicy::RejectIncoming,
            listed_exceptions: true,
        } => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext(
                "UFW is active; the default incoming policy is reject. Listed rules may allow \
                 exceptions.",
            ),
        ),
        UfwState::FirewallActive {
            incoming_policy: IncomingPolicy::DenyIncoming,
            listed_exceptions: false,
        } => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext("UFW is active; the default incoming policy is deny."),
        ),
        UfwState::FirewallActive {
            incoming_policy: IncomingPolicy::RejectIncoming,
            listed_exceptions: false,
        } => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext("UFW is active; the default incoming policy is reject."),
        ),
        UfwState::FirewallActive {
            incoming_policy: IncomingPolicy::AllowIncoming,
            ..
        } => AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            gettext("UFW is active, but the default incoming policy allows traffic."),
        ),
        UfwState::FirewallActive {
            incoming_policy: IncomingPolicy::UnverifiedPolicy,
            ..
        } => AuditCheck::new(
            check_name,
            AuditStatus::StatusUnknown,
            gettext("UFW is active, but its default incoming policy could not be verified."),
        ),
        UfwState::FirewallInactive => AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            gettext("UFW reports inactive."),
        )
        .with_recommendation(gettext("Enable the firewall"))
        .with_suggested_commands([UFW_ENABLE_COMMAND]),
        UfwState::StateUndetermined => AuditCheck::new(
            check_name,
            AuditStatus::StatusUnknown,
            gettext("UFW status could not be inspected safely."),
        )
        .with_suggested_commands([UFW_STATUS_COMMAND]),
        UfwState::ProgramNotInstalled => AuditCheck::new(
            check_name,
            AuditStatus::CheckSkipped,
            gettext("{name} is not installed").replace("{name}", "UFW"),
        ),
    };
    ufw_row.with_documentation(UFW_DOCUMENTATION_URL)
}

pub fn parse_firewalld_owner(owner_text: &str) -> FirewalldOwner {
    let Ok(owner_value) = serde_json::from_str::<Value>(owner_text) else {
        return FirewalldOwner::OwnershipUndetermined;
    };
    if owner_value.get("type").and_then(Value::as_str) != Some("b") {
        return FirewalldOwner::OwnershipUndetermined;
    }
    let owner_flags = owner_value
        .get("data")
        .and_then(Value::as_array)
        .map(|owner_data| owner_data.iter().map(Value::as_bool).collect::<Vec<_>>())
        .unwrap_or_default();
    match owner_flags.as_slice() {
        [Some(true)] => FirewalldOwner::NameOwned,
        [Some(false)] => FirewalldOwner::NameUnowned,
        _other_shape => FirewalldOwner::OwnershipUndetermined,
    }
}

pub fn firewalld_check(firewalld_owner: FirewalldOwner, command_installed: bool) -> AuditCheck {
    let check_name = gettext("Firewalld");
    let firewalld_row = match firewalld_owner {
        FirewalldOwner::NameOwned => AuditCheck::new(
            check_name,
            AuditStatus::StatusUnknown,
            gettext(
                "Firewalld owns its D-Bus name; readiness and firewall policy were not queried.",
            ),
        )
        .with_suggested_commands([FIREWALLD_STATUS_COMMAND]),
        FirewalldOwner::NameUnowned | FirewalldOwner::OwnershipUndetermined
            if !command_installed =>
        {
            AuditCheck::new(
                check_name,
                AuditStatus::CheckSkipped,
                gettext("{name} is not installed").replace("{name}", "Firewalld"),
            )
        }
        FirewalldOwner::NameUnowned => AuditCheck::new(
            check_name,
            AuditStatus::StatusUnknown,
            gettext(
                "No Firewalld D-Bus owner was observed; this does not establish kernel firewall \
                 policy.",
            ),
        ),
        FirewalldOwner::OwnershipUndetermined => AuditCheck::new(
            check_name,
            AuditStatus::StatusUnknown,
            gettext(
                "Firewalld ownership could not be verified; readiness and firewall policy were \
                 not queried.",
            ),
        ),
    };
    firewalld_row.with_documentation(FIREWALLD_DOCUMENTATION_URL)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NftablesTableKey<'ruleset> {
    table_family: &'ruleset str,
    table_name: &'ruleset str,
}

enum ChainContribution<'ruleset> {
    NotInputPolicy,
    FamilyPolicy {
        chain_family: &'ruleset str,
        family_evidence: FamilyEvidence,
    },
}

fn nonempty_text<'ruleset>(
    record_fields: &'ruleset Map<String, Value>,
    field_name: &str,
) -> Option<&'ruleset str> {
    record_fields
        .get(field_name)?
        .as_str()
        .filter(|field_text| !field_text.is_empty())
}

fn dormant_flag(record_fields: &Map<String, Value>) -> Option<bool> {
    let Some(record_flags) = record_fields.get("flags") else {
        return Some(false);
    };
    let flag_names = record_flags
        .as_array()?
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()?;
    Some(flag_names.contains(&"dormant"))
}

fn collect_nftables_tables(
    ruleset_records: &[Value],
) -> Option<BTreeMap<NftablesTableKey<'_>, bool>> {
    ruleset_records
        .iter()
        .try_fold(BTreeMap::new(), |mut known_tables, ruleset_record| {
            let Some(table_value) = ruleset_record.as_object()?.get("table") else {
                return Some(known_tables);
            };
            let table_fields = table_value.as_object()?;
            let table_key = NftablesTableKey {
                table_family: nonempty_text(table_fields, "family")?,
                table_name: nonempty_text(table_fields, "name")?,
            };
            known_tables
                .insert(table_key, dormant_flag(table_fields)?)
                .is_none()
                .then_some(known_tables)
        })
}

fn base_chain_evidence(chain_fields: &Map<String, Value>) -> FamilyEvidence {
    let has_complete_base_chain = nonempty_text(chain_fields, "name").is_some()
        && chain_fields.get("type").and_then(Value::as_str) == Some("filter")
        && chain_fields
            .get("prio")
            .is_some_and(|chain_priority| chain_priority.is_i64() || chain_priority.is_u64());
    if !has_complete_base_chain {
        return FamilyEvidence::IncompleteEvidence;
    }
    match chain_fields.get("policy").and_then(Value::as_str) {
        Some("drop") => FamilyEvidence::RestrictivePolicy,
        Some("accept") => FamilyEvidence::PermissivePolicy,
        _other_policy => FamilyEvidence::IncompleteEvidence,
    }
}

fn chain_contribution<'ruleset>(
    ruleset_record: &'ruleset Value,
    known_tables: &BTreeMap<NftablesTableKey<'ruleset>, bool>,
) -> Option<ChainContribution<'ruleset>> {
    let Some(chain_value) = ruleset_record.as_object()?.get("chain") else {
        return Some(ChainContribution::NotInputPolicy);
    };
    let chain_fields = chain_value.as_object()?;
    if chain_fields.get("hook").and_then(Value::as_str) != Some("input") {
        return Some(ChainContribution::NotInputPolicy);
    }
    let chain_family = nonempty_text(chain_fields, "family")?;
    if !matches!(chain_family, "ip" | "ip6" | "inet") {
        return Some(ChainContribution::NotInputPolicy);
    }
    let table_is_dormant = nonempty_text(chain_fields, "table").and_then(|table_name| {
        known_tables.get(&NftablesTableKey {
            table_family: chain_family,
            table_name,
        })
    });
    let family_evidence = match table_is_dormant {
        Some(true) => return Some(ChainContribution::NotInputPolicy),
        Some(false) if dormant_flag(chain_fields)? => {
            return Some(ChainContribution::NotInputPolicy);
        }
        Some(false) => base_chain_evidence(chain_fields),
        None => FamilyEvidence::IncompleteEvidence,
    };
    Some(ChainContribution::FamilyPolicy {
        chain_family,
        family_evidence,
    })
}

fn combine_family_evidence(family_policies: &[FamilyEvidence]) -> FamilyEvidence {
    let Some(first_policy) = family_policies.first().copied() else {
        return FamilyEvidence::NoInputChain;
    };
    if family_policies
        .iter()
        .all(|family_policy| *family_policy == first_policy)
    {
        first_policy
    } else {
        FamilyEvidence::IncompleteEvidence
    }
}

fn family_evidence_for(
    chain_contributions: &[ChainContribution<'_>],
    covering_families: [&str; 2],
) -> FamilyEvidence {
    combine_family_evidence(
        &chain_contributions
            .iter()
            .filter_map(|contribution| match contribution {
                ChainContribution::FamilyPolicy {
                    chain_family,
                    family_evidence,
                } if covering_families.contains(chain_family) => Some(*family_evidence),
                ChainContribution::FamilyPolicy { .. } | ChainContribution::NotInputPolicy => None,
            })
            .collect::<Vec<_>>(),
    )
}

pub fn parse_nftables_ruleset(ruleset_text: &str) -> Option<NftablesAssessment> {
    let ruleset_value = serde_json::from_str::<Value>(ruleset_text).ok()?;
    let ruleset_records = ruleset_value.get("nftables")?.as_array()?;
    let known_tables = collect_nftables_tables(ruleset_records)?;
    let chain_contributions = ruleset_records
        .iter()
        .map(|ruleset_record| chain_contribution(ruleset_record, &known_tables))
        .collect::<Option<Vec<_>>>()?;
    Some(NftablesAssessment {
        ipv4_evidence: family_evidence_for(&chain_contributions, ["ip", "inet"]),
        ipv6_evidence: family_evidence_for(&chain_contributions, ["ip6", "inet"]),
    })
}

pub fn inspect_nftables_probe(nftables_probe: &CommandProbe) -> NftablesEvidence {
    if *nftables_probe == CommandProbe::ProgramMissing {
        return NftablesEvidence::NftablesNotInstalled;
    }
    nftables_probe
        .verified_text()
        .and_then(parse_nftables_ruleset)
        .map_or(
            NftablesEvidence::RulesetUnreadable,
            NftablesEvidence::RulesetAssessed,
        )
}

pub fn nftables_assessment_status(nftables_assessment: NftablesAssessment) -> AuditStatus {
    let both_families = [
        nftables_assessment.ipv4_evidence,
        nftables_assessment.ipv6_evidence,
    ];
    if both_families == [FamilyEvidence::RestrictivePolicy; 2] {
        AuditStatus::CheckPassed
    } else if both_families.contains(&FamilyEvidence::PermissivePolicy) {
        AuditStatus::NeedsReview
    } else {
        AuditStatus::StatusUnknown
    }
}

pub fn nftables_check(nftables_evidence: NftablesEvidence) -> AuditCheck {
    let check_name = gettext("nftables (native rules)");
    let unverified_row = |check_name: String| {
        AuditCheck::new(
            check_name,
            AuditStatus::StatusUnknown,
            gettext("nftables input policy coverage could not be verified for both IPv4 and IPv6"),
        )
        .with_suggested_commands([NFTABLES_RULESET_COMMAND])
    };
    let nftables_row = match nftables_evidence {
        NftablesEvidence::NftablesNotInstalled => AuditCheck::new(
            check_name,
            AuditStatus::CheckSkipped,
            gettext("{name} is not installed").replace("{name}", "nftables"),
        ),
        NftablesEvidence::RulesetUnreadable => unverified_row(check_name),
        NftablesEvidence::RulesetAssessed(nftables_assessment) => {
            match nftables_assessment_status(nftables_assessment) {
                AuditStatus::CheckPassed => AuditCheck::new(
                    check_name,
                    AuditStatus::CheckPassed,
                    gettext(
                        "nftables has restrictive default input policies for IPv4 and IPv6; \
                         individual rules may allow exceptions.",
                    ),
                ),
                AuditStatus::NeedsReview => AuditCheck::new(
                    check_name,
                    AuditStatus::NeedsReview,
                    gettext(
                        "nftables reports a permissive default input policy; remaining coverage \
                         may be incomplete",
                    ),
                ),
                AuditStatus::CheckFailed
                | AuditStatus::StatusUnknown
                | AuditStatus::CheckSkipped
                | AuditStatus::CheckInProgress => unverified_row(check_name),
            }
        }
    };
    nftables_row.with_documentation(NFTABLES_DOCUMENTATION_URL)
}

pub fn parse_iptables_save(saved_rules: &str) -> Option<FamilyEvidence> {
    if saved_rules
        .lines()
        .filter(|saved_line| *saved_line == "*filter")
        .count()
        != 1
    {
        return None;
    }
    let after_filter_header = saved_rules
        .lines()
        .skip_while(|saved_line| *saved_line != "*filter")
        .skip(1)
        .collect::<Vec<_>>();
    let filter_lines = after_filter_header
        .iter()
        .take_while(|saved_line| **saved_line != "COMMIT")
        .collect::<Vec<_>>();
    if filter_lines.len() == after_filter_header.len()
        || filter_lines
            .iter()
            .any(|saved_line| saved_line.starts_with('*'))
    {
        return None;
    }
    let input_policies = filter_lines
        .iter()
        .filter(|saved_line| saved_line.starts_with(":INPUT"))
        .collect::<Vec<_>>();
    let [input_policy] = input_policies.as_slice() else {
        return None;
    };
    let policy_fields = input_policy.split_whitespace().collect::<Vec<_>>();
    match policy_fields.as_slice() {
        [":INPUT", "DROP", _packet_counters] => Some(FamilyEvidence::RestrictivePolicy),
        [":INPUT", "ACCEPT", _packet_counters] => Some(FamilyEvidence::PermissivePolicy),
        _other_fields => None,
    }
}

pub fn inspect_iptables_probe(iptables_probe: &CommandProbe) -> IptablesEvidence {
    if *iptables_probe == CommandProbe::ProgramMissing {
        return IptablesEvidence::IptablesNotInstalled;
    }
    iptables_probe
        .verified_text()
        .and_then(parse_iptables_save)
        .map_or(
            IptablesEvidence::PolicyUnreadable,
            IptablesEvidence::PolicyObserved,
        )
}

pub fn iptables_ipv4_check(iptables_evidence: IptablesEvidence) -> AuditCheck {
    let check_name = gettext("iptables (IPv4)");
    match iptables_evidence {
        IptablesEvidence::PolicyObserved(FamilyEvidence::RestrictivePolicy) => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext(
                "iptables has a restrictive INPUT default policy; individual rules may allow \
                 exceptions.",
            ),
        ),
        IptablesEvidence::PolicyObserved(FamilyEvidence::PermissivePolicy) => AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            gettext("iptables has a permissive INPUT default policy"),
        ),
        IptablesEvidence::IptablesNotInstalled => AuditCheck::new(
            check_name,
            AuditStatus::CheckSkipped,
            gettext("{name} is not installed").replace("{name}", "iptables"),
        ),
        IptablesEvidence::PolicyObserved(
            FamilyEvidence::NoInputChain | FamilyEvidence::IncompleteEvidence,
        )
        | IptablesEvidence::PolicyUnreadable => AuditCheck::new(
            check_name,
            AuditStatus::StatusUnknown,
            gettext("iptables INPUT policy could not be verified"),
        )
        .with_suggested_commands([IPTABLES_RULESET_COMMAND]),
    }
}

pub fn iptables_ipv6_check(iptables_evidence: IptablesEvidence) -> AuditCheck {
    let check_name = gettext("iptables (IPv6)");
    match iptables_evidence {
        IptablesEvidence::PolicyObserved(FamilyEvidence::RestrictivePolicy) => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext(
                "ip6tables has a restrictive INPUT default policy; individual rules may allow \
                 exceptions.",
            ),
        ),
        IptablesEvidence::PolicyObserved(FamilyEvidence::PermissivePolicy) => AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            gettext("ip6tables has a permissive INPUT default policy"),
        ),
        IptablesEvidence::IptablesNotInstalled => AuditCheck::new(
            check_name,
            AuditStatus::CheckSkipped,
            gettext("{name} is not installed").replace("{name}", "ip6tables"),
        ),
        IptablesEvidence::PolicyObserved(
            FamilyEvidence::NoInputChain | FamilyEvidence::IncompleteEvidence,
        )
        | IptablesEvidence::PolicyUnreadable => AuditCheck::new(
            check_name,
            AuditStatus::StatusUnknown,
            gettext("ip6tables INPUT policy could not be verified"),
        )
        .with_suggested_commands([IP6TABLES_RULESET_COMMAND]),
    }
}

pub fn managers_overlap(ufw_state: UfwState, firewalld_owner: FirewalldOwner) -> bool {
    matches!(ufw_state, UfwState::FirewallActive { .. })
        && firewalld_owner == FirewalldOwner::NameOwned
}

fn manager_overlap_check() -> AuditCheck {
    AuditCheck::new(
        gettext("Firewall manager overlap"),
        AuditStatus::NeedsReview,
        gettext(
            "UFW is active while Firewalld owns its D-Bus name; their rule interaction was not \
             evaluated.",
        ),
    )
}

pub fn firewall_service_check(
    service_evidence: FirewallServiceEvidence,
    distribution_family: DistributionFamily,
) -> AuditCheck {
    let check_name = gettext("Firewall Service");
    match service_evidence {
        FirewallServiceEvidence::ActiveUnit(NIXOS_FIREWALL_UNIT)
            if distribution_family == DistributionFamily::NixosFamily =>
        {
            AuditCheck::new(
                check_name,
                AuditStatus::CheckPassed,
                gettext("The NixOS firewall service is active; allowed ports were not evaluated."),
            )
        }
        FirewallServiceEvidence::ActiveUnit(service_unit) => AuditCheck::new(
            check_name,
            AuditStatus::StatusUnknown,
            gettext("Service {name} is active; its rules were not inspected.")
                .replace("{name}", service_unit),
        ),
        FirewallServiceEvidence::NoActiveUnit => AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            gettext("No known firewall service is active; rules may still be loaded another way."),
        )
        .with_recommendation(gettext("Enable the firewall"))
        .with_suggested_commands(suggested_command(
            SuggestedRemedy::FirewallServiceEnable,
            distribution_family,
        )),
        FirewallServiceEvidence::SystemdMissing => AuditCheck::new(
            check_name,
            AuditStatus::CheckSkipped,
            gettext("Firewall services could not be listed without systemd."),
        ),
    }
}

pub fn open_ports_check(network_sockets: &[NetworkSocket]) -> AuditCheck {
    let exposed_ports = network_sockets
        .iter()
        .filter(|network_socket| {
            network_socket.is_listening() && !network_socket.local_endpoint.is_loopback()
        })
        .filter_map(
            |network_socket| match network_socket.local_endpoint.endpoint_port {
                EndpointPort::NumberedPort(port_number) => Some(port_number),
                EndpointPort::WildcardPort => None,
            },
        )
        .collect::<BTreeSet<_>>();
    let risky_ports = exposed_ports
        .iter()
        .filter_map(|exposed_port| {
            RISKY_PORTS
                .iter()
                .find(|risky_port| risky_port.port_number == *exposed_port)
        })
        .map(|risky_port| format!("{} ({})", risky_port.port_number, risky_port.service_name))
        .collect::<Vec<_>>();
    let exposed_count = u32::try_from(exposed_ports.len()).unwrap_or(u32::MAX);
    let check_name = gettext("Open Ports");
    let ports_row = if !risky_ports.is_empty() {
        AuditCheck::new(
            check_name,
            AuditStatus::CheckFailed,
            ngettext(
                "{count} port listening, risky ports: {ports}",
                "{count} ports listening, risky ports: {ports}",
                exposed_count,
            )
            .replace("{count}", &exposed_count.to_string())
            .replace("{ports}", &risky_ports.join(", ")),
        )
        .with_recommendation(gettext("Review if these services need to be exposed"))
    } else if exposed_count > 0 {
        AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            ngettext(
                "{count} port listening",
                "{count} ports listening",
                exposed_count,
            )
            .replace("{count}", &exposed_count.to_string()),
        )
        .with_recommendation(gettext("Review open ports and close unnecessary services"))
    } else {
        AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext("No open ports detected"),
        )
    };
    ports_row.with_documentation(OPEN_PORTS_DOCUMENTATION_URL)
}

fn open_ports_unavailable_check() -> AuditCheck {
    AuditCheck::new(
        gettext("Open Ports"),
        AuditStatus::StatusUnknown,
        gettext(
            "Network socket listing is unavailable. Check that the system socket tool is \
             installed and try again.",
        ),
    )
    .with_documentation(OPEN_PORTS_DOCUMENTATION_URL)
}

async fn inspect_firewall_service() -> FirewallServiceEvidence {
    if !systemd_is_available() {
        return FirewallServiceEvidence::SystemdMissing;
    }
    first_active_unit(&FIREWALL_SERVICE_UNITS).await.map_or(
        FirewallServiceEvidence::NoActiveUnit,
        FirewallServiceEvidence::ActiveUnit,
    )
}

pub async fn audit_firewall(distribution_family: DistributionFamily) -> AuditSection {
    let (ufw_probe, firewalld_probe, nftables_probe, iptables_probe, ip6tables_probe) = join!(
        run_command_probe("ufw", &["status", "verbose"]),
        run_command_probe("busctl", &FIREWALLD_OWNER_PROBE_ARGUMENTS),
        run_command_probe("nft", &["--json", "list", "ruleset"]),
        run_command_probe("iptables-save", &[]),
        run_command_probe("ip6tables-save", &[]),
    );
    let ufw_state = inspect_ufw_probe(&ufw_probe);
    let firewalld_owner = firewalld_probe
        .verified_text()
        .map_or(FirewalldOwner::OwnershipUndetermined, parse_firewalld_owner);
    let firewalld_installed = locate_host_program("firewall-cmd").is_some();
    let mut section_checks = vec![
        firewall_service_check(inspect_firewall_service().await, distribution_family),
        ufw_check(ufw_state),
        firewalld_check(firewalld_owner, firewalld_installed),
        nftables_check(inspect_nftables_probe(&nftables_probe)),
        iptables_ipv4_check(inspect_iptables_probe(&iptables_probe)),
        iptables_ipv6_check(inspect_iptables_probe(&ip6tables_probe)),
    ];
    if managers_overlap(ufw_state, firewalld_owner) {
        section_checks.push(manager_overlap_check());
    }
    section_checks.push(match probe_socket_listing().await {
        Ok(parsed_sockets) => open_ports_check(&parsed_sockets.listed_sockets),
        Err(_listing_failure) => open_ports_unavailable_check(),
    });
    AuditSection {
        audit_category: AuditCategory::FirewallProtection,
        section_checks,
    }
}

#[cfg(test)]
mod firewall_audit_checks_tests {
    use super::*;
    use crate::network_sockets::socket_listing_parser::parse_socket_listing;

    fn completed_probe(stdout_bytes: &[u8]) -> CommandProbe {
        CommandProbe::ExitedSuccessfully {
            stdout_bytes: stdout_bytes.to_vec(),
        }
    }

    fn nftables_status_of(ruleset_text: &[u8]) -> AuditStatus {
        nftables_check(inspect_nftables_probe(&completed_probe(ruleset_text))).check_status
    }

    #[test]
    fn ufw_requires_an_exact_successful_status_header() {
        assert_eq!(
            parse_ufw_status("Status: active\nDefault: deny (incoming), allow (outgoing)\n"),
            UfwState::FirewallActive {
                incoming_policy: IncomingPolicy::DenyIncoming,
                listed_exceptions: false,
            }
        );
        assert_eq!(
            parse_ufw_status("Status: inactive\n"),
            UfwState::FirewallInactive
        );
        assert_eq!(
            parse_ufw_status("Status: active-ish\nDefault: deny (incoming)\n"),
            UfwState::StateUndetermined
        );
        assert_eq!(
            parse_ufw_status("Status: active\nStatus: inactive\n"),
            UfwState::StateUndetermined
        );
    }

    #[test]
    fn active_ufw_without_default_policy_is_not_a_pass() {
        let ufw_state =
            parse_ufw_status("Status: active\nTo Action From\n22/tcp ALLOW IN Anywhere\n");
        assert_eq!(
            ufw_state,
            UfwState::FirewallActive {
                incoming_policy: IncomingPolicy::UnverifiedPolicy,
                listed_exceptions: true,
            }
        );
        assert_eq!(
            ufw_check(ufw_state).check_status,
            AuditStatus::StatusUnknown
        );
    }

    #[test]
    fn ipv6_only_ufw_exception_qualifies_the_consumer_row() {
        let qualified_row = ufw_check(inspect_ufw_probe(&completed_probe(
            b"Status: active\nDefault: deny (incoming), allow (outgoing)\nTo Action From\n22/tcp \
              (v6) ALLOW IN Anywhere (v6)\n",
        )));
        let unqualified_row = ufw_check(inspect_ufw_probe(&completed_probe(
            b"Status: active\nDefault: deny (incoming), allow (outgoing)\n",
        )));
        assert_eq!(qualified_row.check_status, AuditStatus::CheckPassed);
        assert_eq!(unqualified_row.check_status, AuditStatus::CheckPassed);
        assert_ne!(qualified_row.status_detail, unqualified_row.status_detail);
    }

    #[test]
    fn raw_control_or_invalid_utf8_output_cannot_be_repaired_into_firewall_evidence() {
        assert_eq!(
            inspect_ufw_probe(&completed_probe(
                b"Status: ac\0tive\nDefault: deny (incoming), allow (outgoing)\n"
            )),
            UfwState::StateUndetermined
        );
        let mut nul_ruleset = br#"{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","policy":"drop"}}]}"#.to_vec();
        nul_ruleset.push(0);
        assert_eq!(
            inspect_nftables_probe(&completed_probe(&nul_ruleset)),
            NftablesEvidence::RulesetUnreadable
        );
        assert_eq!(
            inspect_ufw_probe(&completed_probe(b"Status: active\n\xff")),
            UfwState::StateUndetermined
        );
    }

    #[test]
    fn missing_tools_are_skipped_and_denied_tools_are_unknown() {
        assert_eq!(
            ufw_check(inspect_ufw_probe(&CommandProbe::ProgramMissing)).check_status,
            AuditStatus::CheckSkipped
        );
        assert_eq!(
            ufw_check(inspect_ufw_probe(&CommandProbe::ExitedWithFailure)).check_status,
            AuditStatus::StatusUnknown
        );
        assert_eq!(
            nftables_check(inspect_nftables_probe(&CommandProbe::ProgramMissing)).check_status,
            AuditStatus::CheckSkipped
        );
        assert_eq!(
            nftables_check(inspect_nftables_probe(&CommandProbe::ExitedWithFailure)).check_status,
            AuditStatus::StatusUnknown
        );
        assert_eq!(
            iptables_ipv4_check(inspect_iptables_probe(&CommandProbe::ProgramMissing)).check_status,
            AuditStatus::CheckSkipped
        );
        assert_eq!(
            iptables_ipv6_check(inspect_iptables_probe(&CommandProbe::ProbeTimedOut)).check_status,
            AuditStatus::StatusUnknown
        );
        assert_eq!(
            firewalld_check(FirewalldOwner::NameUnowned, false).check_status,
            AuditStatus::CheckSkipped
        );
        assert_eq!(
            firewalld_check(FirewalldOwner::OwnershipUndetermined, false).check_status,
            AuditStatus::CheckSkipped
        );
        assert_eq!(
            firewalld_check(FirewalldOwner::OwnershipUndetermined, true).check_status,
            AuditStatus::StatusUnknown
        );
        assert_eq!(
            firewalld_check(FirewalldOwner::NameOwned, false).check_status,
            AuditStatus::StatusUnknown
        );
        assert_eq!(
            firewalld_check(FirewalldOwner::NameUnowned, true).check_status,
            AuditStatus::StatusUnknown
        );
    }

    #[test]
    fn firewalld_bus_owner_requires_the_verified_boolean_shape() {
        assert_eq!(
            parse_firewalld_owner(r#"{"type":"b","data":[true]}"#),
            FirewalldOwner::NameOwned
        );
        assert_eq!(
            parse_firewalld_owner(r#"{"type":"b","data":[false]}"#),
            FirewalldOwner::NameUnowned
        );
        assert_eq!(
            parse_firewalld_owner(r#"{"type":"b","data":true}"#),
            FirewalldOwner::OwnershipUndetermined
        );
        assert_eq!(
            parse_firewalld_owner(r#"{"type":"s","data":["true"]}"#),
            FirewalldOwner::OwnershipUndetermined
        );
    }

    #[test]
    fn overlap_is_only_a_potential_manager_warning() {
        let active_state = UfwState::FirewallActive {
            incoming_policy: IncomingPolicy::DenyIncoming,
            listed_exceptions: false,
        };
        assert!(managers_overlap(active_state, FirewalldOwner::NameOwned));
        assert!(!managers_overlap(
            UfwState::FirewallInactive,
            FirewalldOwner::NameOwned
        ));
        assert!(!managers_overlap(active_state, FirewalldOwner::NameUnowned));
    }

    #[test]
    fn nft_ignores_nat_forward_named_input_and_dormant_chains() {
        let nftables_assessment = parse_nftables_ruleset(
            r#"{"nftables":[
                {"table":{"family":"ip","name":"filter"}},
                {"table":{"family":"ip","name":"sleep","flags":["dormant"]}},
                {"chain":{"family":"ip","table":"nat","name":"prerouting","type":"nat","hook":"prerouting","policy":"accept"}},
                {"chain":{"family":"ip","table":"filter","name":"forward","type":"filter","hook":"forward","policy":"accept"}},
                {"chain":{"family":"ip","table":"filter","name":"input","policy":"drop"}},
                {"chain":{"family":"ip","table":"sleep","name":"sleeping","type":"filter","hook":"input","policy":"drop"}},
                {"chain":{"family":"ip","table":"filter","name":"live","type":"filter","hook":"input","prio":0,"policy":"drop"}}
            ]}"#,
        )
        .expect("valid nft JSON");
        assert_eq!(
            nftables_assessment.ipv4_evidence,
            FamilyEvidence::RestrictivePolicy
        );
        assert_eq!(
            nftables_assessment.ipv6_evidence,
            FamilyEvidence::NoInputChain
        );
    }

    #[test]
    fn nft_complete_inet_base_chain_covers_both_families() {
        let ruleset_text = r#"{"nftables":[
            {"table":{"family":"inet","name":"filter"}},
            {"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}}
        ]}"#;
        let nftables_assessment =
            parse_nftables_ruleset(ruleset_text).expect("complete nft base chain");
        assert_eq!(
            nftables_assessment.ipv4_evidence,
            FamilyEvidence::RestrictivePolicy
        );
        assert_eq!(
            nftables_assessment.ipv6_evidence,
            FamilyEvidence::RestrictivePolicy
        );
        assert_eq!(
            nftables_status_of(ruleset_text.as_bytes()),
            AuditStatus::CheckPassed
        );
    }

    #[test]
    fn nft_incomplete_base_chain_evidence_is_unknown_to_consumers() {
        [
            r#"{"nftables":[{"chain":{"family":"inet","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}}]}"#,
            r#"{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}}]}"#,
            r#"{"nftables":[{"table":{"family":"inet","name":"filter"}},{"chain":{"family":"inet","table":"filter","type":"filter","hook":"input","prio":0,"policy":"drop"}}]}"#,
            r#"{"nftables":[{"table":{"family":"inet","name":"filter"}},{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","policy":"drop"}}]}"#,
            r#"{"nftables":[{"table":{"family":"inet","name":"filter"}},{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"reject"}}]}"#,
            r#"{"nftables":[{"table":{"family":"inet","name":"filter"}},{"chain":{"family":"inet","table":"filter","name":"valid","type":"filter","hook":"input","prio":0,"policy":"drop"}},{"chain":{"family":"inet","table":"filter","name":"invalid","type":"filter","hook":"input","policy":"drop"}}]}"#,
        ]
        .into_iter()
        .for_each(|ruleset_text| {
            assert_eq!(
                nftables_status_of(ruleset_text.as_bytes()),
                AuditStatus::StatusUnknown,
                "incomplete base-chain evidence must not be reported as protected"
            );
        });
    }

    #[test]
    fn nft_malformed_or_single_family_evidence_never_claims_full_coverage() {
        assert_eq!(nftables_status_of(b"not json"), AuditStatus::StatusUnknown);
        assert_eq!(
            nftables_status_of(br#"{"nftables":[{"chain":"malformed"}]}"#),
            AuditStatus::StatusUnknown
        );
        assert_ne!(
            nftables_check(NftablesEvidence::RulesetAssessed(NftablesAssessment {
                ipv4_evidence: FamilyEvidence::RestrictivePolicy,
                ipv6_evidence: FamilyEvidence::NoInputChain,
            }))
            .check_status,
            AuditStatus::CheckPassed,
            "single-family evidence cannot establish IPv4 and IPv6 coverage"
        );
    }

    #[test]
    fn iptables_requires_a_complete_filter_table_and_a_valid_input_policy() {
        assert_eq!(
            parse_iptables_save("*filter\n:INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"),
            Some(FamilyEvidence::RestrictivePolicy)
        );
        assert_eq!(
            parse_iptables_save("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\nCOMMIT\n"),
            Some(FamilyEvidence::PermissivePolicy)
        );
        assert_eq!(
            parse_iptables_save(
                "*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n*filter\n:FORWARD DROP [0:0]\nCOMMIT\n"
            ),
            None
        );
        assert_eq!(parse_iptables_save("*filter\n:INPUT DROP [0:0]\n"), None);
        assert_eq!(
            parse_iptables_save("*filter\n:INPUT REJECT [0:0]\nCOMMIT\n"),
            None
        );
        assert_eq!(
            parse_iptables_save("*filter\n:INPUT DROP [0:0]\n:INPUT DROP [0:0]\nCOMMIT\n"),
            None
        );
        assert_eq!(parse_iptables_save(""), None);
    }

    #[test]
    fn firewall_service_row_never_claims_protection_from_a_generic_active_unit() {
        assert_eq!(
            firewall_service_check(
                FirewallServiceEvidence::ActiveUnit("firewall.service"),
                DistributionFamily::NixosFamily
            )
            .check_status,
            AuditStatus::CheckPassed
        );
        assert_eq!(
            firewall_service_check(
                FirewallServiceEvidence::ActiveUnit("ufw.service"),
                DistributionFamily::DebianFamily
            )
            .check_status,
            AuditStatus::StatusUnknown
        );
        assert_eq!(
            firewall_service_check(
                FirewallServiceEvidence::ActiveUnit("firewall.service"),
                DistributionFamily::DebianFamily
            )
            .check_status,
            AuditStatus::StatusUnknown
        );
        assert_eq!(
            firewall_service_check(
                FirewallServiceEvidence::NoActiveUnit,
                DistributionFamily::DebianFamily
            )
            .check_status,
            AuditStatus::NeedsReview
        );
        assert_eq!(
            firewall_service_check(
                FirewallServiceEvidence::SystemdMissing,
                DistributionFamily::UnrecognizedFamily
            )
            .check_status,
            AuditStatus::CheckSkipped
        );
    }

    #[test]
    fn loopback_listeners_do_not_count_as_open_ports() {
        let parsed_sockets = parse_socket_listing(
            "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\ntcp LISTEN 0 1 [::1]:631 [::]:*\n",
        );
        let ports_row = open_ports_check(&parsed_sockets.listed_sockets);
        assert_eq!(ports_row.check_status, AuditStatus::CheckPassed);
        assert_eq!(ports_row.status_detail, "No open ports detected");
    }

    #[test]
    fn exposed_ports_are_counted_once_and_connections_are_ignored() {
        let parsed_sockets = parse_socket_listing(
            "tcp LISTEN 0 1 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 1 [::]:22 [::]:*\ntcp ESTAB 0 0 \
             192.0.2.2:5000 198.51.100.7:443\n",
        );
        let ports_row = open_ports_check(&parsed_sockets.listed_sockets);
        assert_eq!(ports_row.check_status, AuditStatus::NeedsReview);
        assert_eq!(ports_row.status_detail, "1 port listening");
    }

    #[test]
    fn exposed_risky_ports_fail_but_loopback_risky_ports_do_not() {
        let exposed_sockets = parse_socket_listing(
            "tcp LISTEN 0 1 0.0.0.0:445 0.0.0.0:*\ntcp LISTEN 0 1 0.0.0.0:5900 0.0.0.0:*\n",
        );
        let exposed_row = open_ports_check(&exposed_sockets.listed_sockets);
        assert_eq!(exposed_row.check_status, AuditStatus::CheckFailed);
        assert_eq!(
            exposed_row.status_detail,
            "2 ports listening, risky ports: 445 (SMB), 5900 (VNC)"
        );
        let loopback_sockets = parse_socket_listing("tcp LISTEN 0 1 127.0.0.1:5900 0.0.0.0:*\n");
        assert_eq!(
            open_ports_check(&loopback_sockets.listed_sockets).check_status,
            AuditStatus::CheckPassed
        );
    }
}

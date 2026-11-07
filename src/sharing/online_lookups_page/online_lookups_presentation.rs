use gettextrs::gettext;

use crate::host_services::threat_intel::service_key_status::{LookupKeyStatuses, ServiceKeyStatus};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookupService {
    CirclHashlookup,
    MalwareBazaar,
    VirusTotal,
}

pub const ALL_LOOKUP_SERVICES: [LookupService; 3] = [
    LookupService::CirclHashlookup,
    LookupService::MalwareBazaar,
    LookupService::VirusTotal,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LookupServiceAccess {
    KeylessService,
    KeyedService(ServiceKeyStatus),
}

impl LookupServiceAccess {
    pub const fn service_ready(&self) -> bool {
        match self {
            Self::KeylessService => true,
            Self::KeyedService(key_status) => key_status.service_ready(),
        }
    }

    pub const fn needs_attention(&self) -> bool {
        match self {
            Self::KeylessService => false,
            Self::KeyedService(key_status) => key_status.needs_attention(),
        }
    }

    fn access_text(&self) -> String {
        match self {
            Self::KeylessService => gettext("No API key needed"),
            Self::KeyedService(key_status) => key_status.status_text(),
        }
    }
}

impl LookupService {
    pub const fn service_name(self) -> &'static str {
        match self {
            Self::CirclHashlookup => "CIRCL hashlookup",
            Self::MalwareBazaar => "MalwareBazaar",
            Self::VirusTotal => "VirusTotal",
        }
    }

    pub fn received_data_text(self) -> String {
        match self {
            Self::CirclHashlookup => gettext("Receives the file's SHA-256 hash"),
            Self::MalwareBazaar => {
                gettext("Receives the detection's signature name or the file's SHA-256 hash")
            }
            Self::VirusTotal => gettext("Receives the file's SHA-256 hash"),
        }
    }

    pub fn service_access(self, lookup_key_statuses: &LookupKeyStatuses) -> LookupServiceAccess {
        match self {
            Self::CirclHashlookup => LookupServiceAccess::KeylessService,
            Self::MalwareBazaar => {
                LookupServiceAccess::KeyedService(lookup_key_statuses.abuse_ch_key.clone())
            }
            Self::VirusTotal => {
                LookupServiceAccess::KeyedService(lookup_key_statuses.virustotal_key.clone())
            }
        }
    }
}

pub fn lookup_service_subtitle(
    lookup_service: LookupService,
    service_access: &LookupServiceAccess,
) -> String {
    format!(
        "{}\n{}",
        lookup_service.received_data_text(),
        service_access.access_text()
    )
}

pub fn ready_service_count(lookup_key_statuses: &LookupKeyStatuses) -> usize {
    ALL_LOOKUP_SERVICES
        .into_iter()
        .filter(|lookup_service| {
            lookup_service
                .service_access(lookup_key_statuses)
                .service_ready()
        })
        .count()
}

pub fn some_lookup_key_unreadable(lookup_key_statuses: &LookupKeyStatuses) -> bool {
    ALL_LOOKUP_SERVICES.into_iter().any(|lookup_service| {
        lookup_service
            .service_access(lookup_key_statuses)
            .needs_attention()
    })
}

pub fn ready_services_text(lookup_key_statuses: &LookupKeyStatuses) -> String {
    gettext("{ready} of {total} services ready")
        .replace(
            "{ready}",
            &ready_service_count(lookup_key_statuses).to_string(),
        )
        .replace("{total}", &ALL_LOOKUP_SERVICES.len().to_string())
}

#[cfg(test)]
mod online_lookups_presentation_tests {
    use super::*;

    fn key_statuses(
        abuse_ch_key: ServiceKeyStatus,
        virustotal_key: ServiceKeyStatus,
    ) -> LookupKeyStatuses {
        LookupKeyStatuses {
            abuse_ch_key,
            virustotal_key,
        }
    }

    fn unreadable_key() -> ServiceKeyStatus {
        ServiceKeyStatus::KeyUnreadable {
            failure_text: "permission denied".to_owned(),
        }
    }

    #[test]
    fn each_service_row_says_what_it_receives_and_whether_its_key_is_set() {
        let lookup_key_statuses = key_statuses(
            ServiceKeyStatus::KeyMissing,
            ServiceKeyStatus::KeyConfigured,
        );
        assert_eq!(
            lookup_service_subtitle(
                LookupService::CirclHashlookup,
                &LookupService::CirclHashlookup.service_access(&lookup_key_statuses)
            ),
            "Receives the file's SHA-256 hash\nNo API key needed"
        );
        assert_eq!(
            lookup_service_subtitle(
                LookupService::MalwareBazaar,
                &LookupService::MalwareBazaar.service_access(&lookup_key_statuses)
            ),
            "Receives the detection's signature name or the file's SHA-256 hash\nNo API key, so \
             this service is off"
        );
        assert_eq!(
            lookup_service_subtitle(
                LookupService::VirusTotal,
                &LookupService::VirusTotal.service_access(&lookup_key_statuses)
            ),
            "Receives the file's SHA-256 hash\nAPI key configured"
        );
    }

    #[test]
    fn the_keyless_service_is_always_ready() {
        let missing_keys = key_statuses(ServiceKeyStatus::KeyMissing, ServiceKeyStatus::KeyMissing);
        assert_eq!(ready_service_count(&missing_keys), 1);
        assert_eq!(ready_services_text(&missing_keys), "1 of 3 services ready");
        let all_keys = key_statuses(
            ServiceKeyStatus::KeyConfigured,
            ServiceKeyStatus::KeyConfigured,
        );
        assert_eq!(ready_services_text(&all_keys), "3 of 3 services ready");
    }

    #[test]
    fn only_an_unreadable_key_needs_attention() {
        assert!(!some_lookup_key_unreadable(&key_statuses(
            ServiceKeyStatus::KeyMissing,
            ServiceKeyStatus::KeyConfigured
        )));
        assert!(some_lookup_key_unreadable(&key_statuses(
            ServiceKeyStatus::KeyConfigured,
            unreadable_key()
        )));
        assert_eq!(
            ready_service_count(&key_statuses(
                unreadable_key(),
                ServiceKeyStatus::KeyConfigured
            )),
            2
        );
    }
}

use std::fmt::{self, Debug};

use jiff::Timestamp;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, DeserializeOwned},
};

use crate::{
    protection_rules::{BaseValue, TunableValue},
    setting_values::{
        BlockingSwitch, CLAMAV_DEFAULT_MAX_EMBEDDED_PE, CLAMAV_DEFAULT_MAX_FILE_SIZE,
        CLAMAV_DEFAULT_MAX_FILES, CLAMAV_DEFAULT_MAX_RECURSION, CLAMAV_DEFAULT_MAX_SCAN_SIZE,
        CLAMAV_DEFAULT_MAX_SCAN_TIME, CLAMAV_DEFAULT_PCRE_MAX_FILE_SIZE,
        CLAMD_DEFAULT_MAX_DIRECTORY_RECURSION, CLAMD_DEFAULT_ON_ACCESS_MAX_FILE_SIZE, ContentCheck,
        CountLimit, SizeLimit, SkipSwitch, SkippedPaths, SkippedPatterns, ThreadCount,
        WatchedFolders,
    },
};

pub trait SettingSlot {
    fn is_unset(&self) -> bool;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ConfiguredValue<Value> {
    #[default]
    NotConfigured,
    Configured(Value),
}

impl<Value> SettingSlot for ConfiguredValue<Value> {
    fn is_unset(&self) -> bool {
        matches!(self, Self::NotConfigured)
    }
}

impl<Value: Serialize> Serialize for ConfiguredValue<Value> {
    fn serialize<ValueSerializer: Serializer>(
        &self,
        serializer: ValueSerializer,
    ) -> Result<ValueSerializer::Ok, ValueSerializer::Error> {
        match self {
            Self::Configured(configured_value) => configured_value.serialize(serializer),
            Self::NotConfigured => serializer.serialize_none(),
        }
    }
}

impl<'de, Value: Deserialize<'de>> Deserialize<'de> for ConfiguredValue<Value> {
    fn deserialize<ValueDeserializer: Deserializer<'de>>(
        deserializer: ValueDeserializer,
    ) -> Result<Self, ValueDeserializer::Error> {
        Value::deserialize(deserializer).map(Self::Configured)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SettingOverride<Value> {
    #[default]
    FromSystem,
    Permanent {
        value: Value,
    },
    TemporaryReduction {
        value: Value,
        expires_at: Timestamp,
    },
}

impl<Value: Clone> SettingOverride<Value> {
    pub fn value_in_effect_at(&self, now: Timestamp) -> ConfiguredValue<Value> {
        match self {
            Self::Permanent { value } => ConfiguredValue::Configured(value.clone()),
            Self::TemporaryReduction { value, expires_at } if *expires_at > now => {
                ConfiguredValue::Configured(value.clone())
            }
            Self::TemporaryReduction { .. } | Self::FromSystem => ConfiguredValue::NotConfigured,
        }
    }
}

impl<Value> SettingSlot for SettingOverride<Value> {
    fn is_unset(&self) -> bool {
        matches!(self, Self::FromSystem)
    }
}

pub trait SlotFamily: Clone + Debug + Default + PartialEq {
    type Slot<Value: TunableValue>: SettingSlot
        + Clone
        + Debug
        + Default
        + PartialEq
        + Serialize
        + DeserializeOwned;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConfiguredSlots;

impl SlotFamily for ConfiguredSlots {
    type Slot<Value: TunableValue> = ConfiguredValue<Value>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OverrideSlots;

impl SlotFamily for OverrideSlots {
    type Slot<Value: TunableValue> = SettingOverride<Value>;
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""), deny_unknown_fields)]
pub struct TunableRecord<Family: SlotFamily> {
    #[serde(
        rename = "OnAccessPrevention",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub on_access_prevention: Family::Slot<BlockingSwitch>,
    #[serde(
        rename = "OnAccessExtraScanning",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub on_access_extra_scanning: Family::Slot<ContentCheck<false>>,
    #[serde(
        rename = "ScanPE",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub scan_pe: Family::Slot<ContentCheck<true>>,
    #[serde(
        rename = "ScanELF",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub scan_elf: Family::Slot<ContentCheck<true>>,
    #[serde(
        rename = "ScanOLE2",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub scan_ole2: Family::Slot<ContentCheck<true>>,
    #[serde(
        rename = "ScanPDF",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub scan_pdf: Family::Slot<ContentCheck<true>>,
    #[serde(
        rename = "ScanHTML",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub scan_html: Family::Slot<ContentCheck<true>>,
    #[serde(
        rename = "ScanMail",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub scan_mail: Family::Slot<ContentCheck<true>>,
    #[serde(
        rename = "ScanArchive",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub scan_archive: Family::Slot<ContentCheck<true>>,
    #[serde(
        rename = "ScanSWF",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub scan_swf: Family::Slot<ContentCheck<true>>,
    #[serde(
        rename = "ScanXMLDOCS",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub scan_xml_docs: Family::Slot<ContentCheck<true>>,
    #[serde(
        rename = "ScanHWP3",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub scan_hwp3: Family::Slot<ContentCheck<true>>,
    #[serde(
        rename = "AlertBrokenExecutables",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub alert_broken_executables: Family::Slot<ContentCheck<false>>,
    #[serde(
        rename = "AlertEncrypted",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub alert_encrypted: Family::Slot<ContentCheck<false>>,
    #[serde(
        rename = "AlertEncryptedArchive",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub alert_encrypted_archive: Family::Slot<ContentCheck<false>>,
    #[serde(
        rename = "AlertEncryptedDoc",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub alert_encrypted_doc: Family::Slot<ContentCheck<false>>,
    #[serde(
        rename = "AlertOLE2Macros",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub alert_ole2_macros: Family::Slot<ContentCheck<false>>,
    #[serde(
        rename = "AlertExceedsMax",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub alert_exceeds_max: Family::Slot<ContentCheck<false>>,
    #[serde(
        rename = "DetectPUA",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub detect_pua: Family::Slot<ContentCheck<false>>,
    #[serde(
        rename = "HeuristicAlerts",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub heuristic_alerts: Family::Slot<ContentCheck<true>>,
    #[serde(
        rename = "Bytecode",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub bytecode: Family::Slot<ContentCheck<true>>,
    #[serde(
        rename = "MaxScanTime",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub max_scan_time: Family::Slot<CountLimit<CLAMAV_DEFAULT_MAX_SCAN_TIME>>,
    #[serde(
        rename = "MaxRecursion",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub max_recursion: Family::Slot<CountLimit<CLAMAV_DEFAULT_MAX_RECURSION>>,
    #[serde(
        rename = "MaxFiles",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub max_files: Family::Slot<CountLimit<CLAMAV_DEFAULT_MAX_FILES>>,
    #[serde(
        rename = "MaxDirectoryRecursion",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub max_directory_recursion: Family::Slot<CountLimit<CLAMD_DEFAULT_MAX_DIRECTORY_RECURSION>>,
    #[serde(
        rename = "MaxEmbeddedPE",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub max_embedded_pe: Family::Slot<SizeLimit<CLAMAV_DEFAULT_MAX_EMBEDDED_PE>>,
    #[serde(
        rename = "MaxScanSize",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub max_scan_size: Family::Slot<SizeLimit<CLAMAV_DEFAULT_MAX_SCAN_SIZE>>,
    #[serde(
        rename = "MaxFileSize",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub max_file_size: Family::Slot<SizeLimit<CLAMAV_DEFAULT_MAX_FILE_SIZE>>,
    #[serde(
        rename = "OnAccessMaxFileSize",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub on_access_max_file_size: Family::Slot<SizeLimit<CLAMD_DEFAULT_ON_ACCESS_MAX_FILE_SIZE>>,
    #[serde(
        rename = "PCREMaxFileSize",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub pcre_max_file_size: Family::Slot<SizeLimit<CLAMAV_DEFAULT_PCRE_MAX_FILE_SIZE>>,
    #[serde(
        rename = "OnAccessIncludePath",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub on_access_include_path: Family::Slot<WatchedFolders>,
    #[serde(
        rename = "OnAccessExcludePath",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub on_access_exclude_path: Family::Slot<SkippedPaths>,
    #[serde(
        rename = "ExcludePath",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub exclude_path: Family::Slot<SkippedPatterns>,
    #[serde(
        rename = "ExcludePUA",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub exclude_pua: Family::Slot<SkippedPatterns>,
    #[serde(
        rename = "OnAccessExcludeRootUID",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub on_access_exclude_root_uid: Family::Slot<SkipSwitch>,
    #[serde(
        rename = "MaxThreads",
        default,
        skip_serializing_if = "SettingSlot::is_unset"
    )]
    pub max_threads: Family::Slot<ThreadCount>,
}

pub type TunableSettings = TunableRecord<ConfiguredSlots>;

pub type LiveOverrides = TunableRecord<OverrideSlots>;

pub trait SlotCombiner {
    fn combine_slot<Value: TunableValue>(
        &mut self,
        setting_name: &'static str,
        live_override: &SettingOverride<Value>,
        base_value: &BaseValue<'_, Value>,
        requested_value: &ConfiguredValue<Value>,
    ) -> SettingOverride<Value>;
}

#[derive(Clone, Copy, Debug)]
pub enum BaseSettings<'base> {
    ReadableBase(&'base TunableSettings),
    UnreadableBase,
}

impl<'base> BaseSettings<'base> {
    const fn readable_settings(self) -> Option<&'base TunableSettings> {
        match self {
            Self::ReadableBase(base_settings) => Some(base_settings),
            Self::UnreadableBase => None,
        }
    }
}

impl LiveOverrides {
    pub fn combine_with(
        &self,
        base_settings: BaseSettings<'_>,
        requested_settings: &TunableSettings,
        slot_combiner: &mut impl SlotCombiner,
    ) -> Self {
        let readable_base = base_settings.readable_settings();
        Self {
            on_access_prevention: slot_combiner.combine_slot(
                "OnAccessPrevention",
                &self.on_access_prevention,
                &BaseValue::from(readable_base.map(|base| &base.on_access_prevention)),
                &requested_settings.on_access_prevention,
            ),
            on_access_extra_scanning: slot_combiner.combine_slot(
                "OnAccessExtraScanning",
                &self.on_access_extra_scanning,
                &BaseValue::from(readable_base.map(|base| &base.on_access_extra_scanning)),
                &requested_settings.on_access_extra_scanning,
            ),
            scan_pe: slot_combiner.combine_slot(
                "ScanPE",
                &self.scan_pe,
                &BaseValue::from(readable_base.map(|base| &base.scan_pe)),
                &requested_settings.scan_pe,
            ),
            scan_elf: slot_combiner.combine_slot(
                "ScanELF",
                &self.scan_elf,
                &BaseValue::from(readable_base.map(|base| &base.scan_elf)),
                &requested_settings.scan_elf,
            ),
            scan_ole2: slot_combiner.combine_slot(
                "ScanOLE2",
                &self.scan_ole2,
                &BaseValue::from(readable_base.map(|base| &base.scan_ole2)),
                &requested_settings.scan_ole2,
            ),
            scan_pdf: slot_combiner.combine_slot(
                "ScanPDF",
                &self.scan_pdf,
                &BaseValue::from(readable_base.map(|base| &base.scan_pdf)),
                &requested_settings.scan_pdf,
            ),
            scan_html: slot_combiner.combine_slot(
                "ScanHTML",
                &self.scan_html,
                &BaseValue::from(readable_base.map(|base| &base.scan_html)),
                &requested_settings.scan_html,
            ),
            scan_mail: slot_combiner.combine_slot(
                "ScanMail",
                &self.scan_mail,
                &BaseValue::from(readable_base.map(|base| &base.scan_mail)),
                &requested_settings.scan_mail,
            ),
            scan_archive: slot_combiner.combine_slot(
                "ScanArchive",
                &self.scan_archive,
                &BaseValue::from(readable_base.map(|base| &base.scan_archive)),
                &requested_settings.scan_archive,
            ),
            scan_swf: slot_combiner.combine_slot(
                "ScanSWF",
                &self.scan_swf,
                &BaseValue::from(readable_base.map(|base| &base.scan_swf)),
                &requested_settings.scan_swf,
            ),
            scan_xml_docs: slot_combiner.combine_slot(
                "ScanXMLDOCS",
                &self.scan_xml_docs,
                &BaseValue::from(readable_base.map(|base| &base.scan_xml_docs)),
                &requested_settings.scan_xml_docs,
            ),
            scan_hwp3: slot_combiner.combine_slot(
                "ScanHWP3",
                &self.scan_hwp3,
                &BaseValue::from(readable_base.map(|base| &base.scan_hwp3)),
                &requested_settings.scan_hwp3,
            ),
            alert_broken_executables: slot_combiner.combine_slot(
                "AlertBrokenExecutables",
                &self.alert_broken_executables,
                &BaseValue::from(readable_base.map(|base| &base.alert_broken_executables)),
                &requested_settings.alert_broken_executables,
            ),
            alert_encrypted: slot_combiner.combine_slot(
                "AlertEncrypted",
                &self.alert_encrypted,
                &BaseValue::from(readable_base.map(|base| &base.alert_encrypted)),
                &requested_settings.alert_encrypted,
            ),
            alert_encrypted_archive: slot_combiner.combine_slot(
                "AlertEncryptedArchive",
                &self.alert_encrypted_archive,
                &BaseValue::from(readable_base.map(|base| &base.alert_encrypted_archive)),
                &requested_settings.alert_encrypted_archive,
            ),
            alert_encrypted_doc: slot_combiner.combine_slot(
                "AlertEncryptedDoc",
                &self.alert_encrypted_doc,
                &BaseValue::from(readable_base.map(|base| &base.alert_encrypted_doc)),
                &requested_settings.alert_encrypted_doc,
            ),
            alert_ole2_macros: slot_combiner.combine_slot(
                "AlertOLE2Macros",
                &self.alert_ole2_macros,
                &BaseValue::from(readable_base.map(|base| &base.alert_ole2_macros)),
                &requested_settings.alert_ole2_macros,
            ),
            alert_exceeds_max: slot_combiner.combine_slot(
                "AlertExceedsMax",
                &self.alert_exceeds_max,
                &BaseValue::from(readable_base.map(|base| &base.alert_exceeds_max)),
                &requested_settings.alert_exceeds_max,
            ),
            detect_pua: slot_combiner.combine_slot(
                "DetectPUA",
                &self.detect_pua,
                &BaseValue::from(readable_base.map(|base| &base.detect_pua)),
                &requested_settings.detect_pua,
            ),
            heuristic_alerts: slot_combiner.combine_slot(
                "HeuristicAlerts",
                &self.heuristic_alerts,
                &BaseValue::from(readable_base.map(|base| &base.heuristic_alerts)),
                &requested_settings.heuristic_alerts,
            ),
            bytecode: slot_combiner.combine_slot(
                "Bytecode",
                &self.bytecode,
                &BaseValue::from(readable_base.map(|base| &base.bytecode)),
                &requested_settings.bytecode,
            ),
            max_scan_time: slot_combiner.combine_slot(
                "MaxScanTime",
                &self.max_scan_time,
                &BaseValue::from(readable_base.map(|base| &base.max_scan_time)),
                &requested_settings.max_scan_time,
            ),
            max_recursion: slot_combiner.combine_slot(
                "MaxRecursion",
                &self.max_recursion,
                &BaseValue::from(readable_base.map(|base| &base.max_recursion)),
                &requested_settings.max_recursion,
            ),
            max_files: slot_combiner.combine_slot(
                "MaxFiles",
                &self.max_files,
                &BaseValue::from(readable_base.map(|base| &base.max_files)),
                &requested_settings.max_files,
            ),
            max_directory_recursion: slot_combiner.combine_slot(
                "MaxDirectoryRecursion",
                &self.max_directory_recursion,
                &BaseValue::from(readable_base.map(|base| &base.max_directory_recursion)),
                &requested_settings.max_directory_recursion,
            ),
            max_embedded_pe: slot_combiner.combine_slot(
                "MaxEmbeddedPE",
                &self.max_embedded_pe,
                &BaseValue::from(readable_base.map(|base| &base.max_embedded_pe)),
                &requested_settings.max_embedded_pe,
            ),
            max_scan_size: slot_combiner.combine_slot(
                "MaxScanSize",
                &self.max_scan_size,
                &BaseValue::from(readable_base.map(|base| &base.max_scan_size)),
                &requested_settings.max_scan_size,
            ),
            max_file_size: slot_combiner.combine_slot(
                "MaxFileSize",
                &self.max_file_size,
                &BaseValue::from(readable_base.map(|base| &base.max_file_size)),
                &requested_settings.max_file_size,
            ),
            on_access_max_file_size: slot_combiner.combine_slot(
                "OnAccessMaxFileSize",
                &self.on_access_max_file_size,
                &BaseValue::from(readable_base.map(|base| &base.on_access_max_file_size)),
                &requested_settings.on_access_max_file_size,
            ),
            pcre_max_file_size: slot_combiner.combine_slot(
                "PCREMaxFileSize",
                &self.pcre_max_file_size,
                &BaseValue::from(readable_base.map(|base| &base.pcre_max_file_size)),
                &requested_settings.pcre_max_file_size,
            ),
            on_access_include_path: slot_combiner.combine_slot(
                "OnAccessIncludePath",
                &self.on_access_include_path,
                &BaseValue::from(readable_base.map(|base| &base.on_access_include_path)),
                &requested_settings.on_access_include_path,
            ),
            on_access_exclude_path: slot_combiner.combine_slot(
                "OnAccessExcludePath",
                &self.on_access_exclude_path,
                &BaseValue::from(readable_base.map(|base| &base.on_access_exclude_path)),
                &requested_settings.on_access_exclude_path,
            ),
            exclude_path: slot_combiner.combine_slot(
                "ExcludePath",
                &self.exclude_path,
                &BaseValue::from(readable_base.map(|base| &base.exclude_path)),
                &requested_settings.exclude_path,
            ),
            exclude_pua: slot_combiner.combine_slot(
                "ExcludePUA",
                &self.exclude_pua,
                &BaseValue::from(readable_base.map(|base| &base.exclude_pua)),
                &requested_settings.exclude_pua,
            ),
            on_access_exclude_root_uid: slot_combiner.combine_slot(
                "OnAccessExcludeRootUID",
                &self.on_access_exclude_root_uid,
                &BaseValue::from(readable_base.map(|base| &base.on_access_exclude_root_uid)),
                &requested_settings.on_access_exclude_root_uid,
            ),
            max_threads: slot_combiner.combine_slot(
                "MaxThreads",
                &self.max_threads,
                &BaseValue::from(readable_base.map(|base| &base.max_threads)),
                &requested_settings.max_threads,
            ),
        }
    }

    pub fn settings_in_effect_at(&self, now: Timestamp) -> TunableSettings {
        TunableSettings {
            on_access_prevention: self.on_access_prevention.value_in_effect_at(now),
            on_access_extra_scanning: self.on_access_extra_scanning.value_in_effect_at(now),
            scan_pe: self.scan_pe.value_in_effect_at(now),
            scan_elf: self.scan_elf.value_in_effect_at(now),
            scan_ole2: self.scan_ole2.value_in_effect_at(now),
            scan_pdf: self.scan_pdf.value_in_effect_at(now),
            scan_html: self.scan_html.value_in_effect_at(now),
            scan_mail: self.scan_mail.value_in_effect_at(now),
            scan_archive: self.scan_archive.value_in_effect_at(now),
            scan_swf: self.scan_swf.value_in_effect_at(now),
            scan_xml_docs: self.scan_xml_docs.value_in_effect_at(now),
            scan_hwp3: self.scan_hwp3.value_in_effect_at(now),
            alert_broken_executables: self.alert_broken_executables.value_in_effect_at(now),
            alert_encrypted: self.alert_encrypted.value_in_effect_at(now),
            alert_encrypted_archive: self.alert_encrypted_archive.value_in_effect_at(now),
            alert_encrypted_doc: self.alert_encrypted_doc.value_in_effect_at(now),
            alert_ole2_macros: self.alert_ole2_macros.value_in_effect_at(now),
            alert_exceeds_max: self.alert_exceeds_max.value_in_effect_at(now),
            detect_pua: self.detect_pua.value_in_effect_at(now),
            heuristic_alerts: self.heuristic_alerts.value_in_effect_at(now),
            bytecode: self.bytecode.value_in_effect_at(now),
            max_scan_time: self.max_scan_time.value_in_effect_at(now),
            max_recursion: self.max_recursion.value_in_effect_at(now),
            max_files: self.max_files.value_in_effect_at(now),
            max_directory_recursion: self.max_directory_recursion.value_in_effect_at(now),
            max_embedded_pe: self.max_embedded_pe.value_in_effect_at(now),
            max_scan_size: self.max_scan_size.value_in_effect_at(now),
            max_file_size: self.max_file_size.value_in_effect_at(now),
            on_access_max_file_size: self.on_access_max_file_size.value_in_effect_at(now),
            pcre_max_file_size: self.pcre_max_file_size.value_in_effect_at(now),
            on_access_include_path: self.on_access_include_path.value_in_effect_at(now),
            on_access_exclude_path: self.on_access_exclude_path.value_in_effect_at(now),
            exclude_path: self.exclude_path.value_in_effect_at(now),
            exclude_pua: self.exclude_pua.value_in_effect_at(now),
            on_access_exclude_root_uid: self.on_access_exclude_root_uid.value_in_effect_at(now),
            max_threads: self.max_threads.value_in_effect_at(now),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum FieldNameProbeOutcome {
    #[error("field names found")]
    FieldNamesFound(&'static [&'static str]),
    #[error("not a struct: {0}")]
    NotAStruct(String),
}

impl de::Error for FieldNameProbeOutcome {
    fn custom<Message: fmt::Display>(probe_message: Message) -> Self {
        Self::NotAStruct(probe_message.to_string())
    }
}

struct FieldNameProbe;

impl<'de> Deserializer<'de> for FieldNameProbe {
    type Error = FieldNameProbeOutcome;

    fn deserialize_any<ProbeVisitor: de::Visitor<'de>>(
        self,
        _visitor: ProbeVisitor,
    ) -> Result<ProbeVisitor::Value, Self::Error> {
        Err(FieldNameProbeOutcome::NotAStruct("any".to_owned()))
    }

    fn deserialize_struct<ProbeVisitor: de::Visitor<'de>>(
        self,
        _struct_name: &'static str,
        field_names: &'static [&'static str],
        _visitor: ProbeVisitor,
    ) -> Result<ProbeVisitor::Value, Self::Error> {
        Err(FieldNameProbeOutcome::FieldNamesFound(field_names))
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        option unit unit_struct newtype_struct seq tuple tuple_struct map enum identifier
        ignored_any
    }
}

pub fn tunable_setting_names() -> &'static [&'static str] {
    match TunableSettings::deserialize(FieldNameProbe) {
        Err(FieldNameProbeOutcome::FieldNamesFound(field_names)) => field_names,
        Ok(_) | Err(FieldNameProbeOutcome::NotAStruct(_)) => &[],
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TunableSettingName(&'static str);

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{setting_name} is not a setting that can change at runtime")]
pub struct UnknownSettingName {
    pub setting_name: String,
}

impl TunableSettingName {
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    pub fn all_names() -> impl Iterator<Item = Self> {
        tunable_setting_names().iter().copied().map(Self)
    }
}

impl std::str::FromStr for TunableSettingName {
    type Err = UnknownSettingName;

    fn from_str(setting_name: &str) -> Result<Self, Self::Err> {
        tunable_setting_names()
            .iter()
            .find(|known_name| known_name.eq_ignore_ascii_case(setting_name.trim()))
            .map(|known_name| Self(known_name))
            .ok_or_else(|| UnknownSettingName {
                setting_name: setting_name.to_owned(),
            })
    }
}

impl fmt::Display for TunableSettingName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Serialize for TunableSettingName {
    fn serialize<NameSerializer: Serializer>(
        &self,
        serializer: NameSerializer,
    ) -> Result<NameSerializer::Ok, NameSerializer::Error> {
        serializer.serialize_str(self.0)
    }
}

impl<'de> Deserialize<'de> for TunableSettingName {
    fn deserialize<NameDeserializer: Deserializer<'de>>(
        deserializer: NameDeserializer,
    ) -> Result<Self, NameDeserializer::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tunable_record_tests {
    use super::*;
    use crate::protection_rules::ProtectionReduction;

    struct NameCollector {
        combined_names: Vec<&'static str>,
    }

    impl SlotCombiner for NameCollector {
        fn combine_slot<Value: TunableValue>(
            &mut self,
            setting_name: &'static str,
            live_override: &SettingOverride<Value>,
            _base_value: &BaseValue<'_, Value>,
            _requested_value: &ConfiguredValue<Value>,
        ) -> SettingOverride<Value> {
            self.combined_names.push(setting_name);
            live_override.clone()
        }
    }

    #[test]
    fn the_combined_names_match_the_serialized_field_names_in_order() {
        let mut name_collector = NameCollector {
            combined_names: Vec::new(),
        };
        let _unchanged = LiveOverrides::default().combine_with(
            BaseSettings::UnreadableBase,
            &TunableSettings::default(),
            &mut name_collector,
        );
        assert_eq!(name_collector.combined_names, tunable_setting_names());
        assert_eq!(tunable_setting_names().len(), 36);
    }

    #[test]
    fn no_tunable_setting_is_protected() {
        let protected_names = include_str!("../../data/protected-clamav-settings.txt");
        assert!(tunable_setting_names().iter().all(|tunable_name| {
            !protected_names
                .lines()
                .any(|protected_name| protected_name.trim().eq_ignore_ascii_case(tunable_name))
        }));
    }

    #[test]
    fn setting_names_parse_case_insensitively_to_their_canonical_spelling() {
        assert_eq!(
            "detectpua"
                .parse::<TunableSettingName>()
                .map(TunableSettingName::as_str),
            Ok("DetectPUA")
        );
        assert!("VirusEvent".parse::<TunableSettingName>().is_err());
    }

    #[test]
    fn an_expired_reduction_is_no_longer_in_effect() {
        let expiry_time = Timestamp::from_second(1_000).expect("timestamp");
        let temporary_reduction = SettingOverride::TemporaryReduction {
            value: 1_u8,
            expires_at: expiry_time,
        };
        assert_eq!(
            temporary_reduction.value_in_effect_at(Timestamp::from_second(999).expect("timestamp")),
            ConfiguredValue::Configured(1)
        );
        assert_eq!(
            temporary_reduction.value_in_effect_at(expiry_time),
            ConfiguredValue::NotConfigured
        );
        assert!(ProtectionReduction::ScanLimitLowered.weakens_protection());
    }
}

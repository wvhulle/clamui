use std::str::FromStr;

use serde::{
    de::{self, DeserializeOwned, IntoDeserializer, value::SeqDeserializer},
    forward_to_deserialize_any,
};

use crate::clamd_conf_format::{ClamdFormatError, config_lines::ClamdConfigLines};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownSettingPolicy {
    SkipUnknownSettings,
    RefuseUnknownSettings,
}

struct GroupedSetting<'lines> {
    setting_name: &'lines str,
    setting_values: Vec<&'lines str>,
}

fn grouped_settings<'lines>(
    config_lines: &'lines ClamdConfigLines,
    known_names: &[&str],
    unknown_policy: UnknownSettingPolicy,
) -> Result<Vec<GroupedSetting<'lines>>, ClamdFormatError> {
    config_lines.setting_lines().try_fold(
        Vec::<GroupedSetting<'lines>>::new(),
        |mut grouped, setting_line| {
            let setting_name = setting_line.setting_name.as_str();
            if !known_names.contains(&setting_name) {
                return match unknown_policy {
                    UnknownSettingPolicy::SkipUnknownSettings => Ok(grouped),
                    UnknownSettingPolicy::RefuseUnknownSettings => {
                        Err(ClamdFormatError::UnknownSetting {
                            setting_name: setting_name.to_owned(),
                        })
                    }
                };
            }
            match grouped
                .iter_mut()
                .find(|grouped_setting| grouped_setting.setting_name == setting_name)
            {
                Some(grouped_setting) => grouped_setting
                    .setting_values
                    .push(setting_line.setting_value.as_str()),
                None => grouped.push(GroupedSetting {
                    setting_name,
                    setting_values: vec![setting_line.setting_value.as_str()],
                }),
            }
            Ok(grouped)
        },
    )
}

pub fn from_config_lines<Record: DeserializeOwned>(
    config_lines: &ClamdConfigLines,
    known_names: &[&str],
    unknown_policy: UnknownSettingPolicy,
) -> Result<Record, ClamdFormatError> {
    Record::deserialize(RecordDeserializer {
        grouped_settings: grouped_settings(config_lines, known_names, unknown_policy)?,
    })
}

struct RecordDeserializer<'lines> {
    grouped_settings: Vec<GroupedSetting<'lines>>,
}

struct GroupedSettingAccess<'lines> {
    remaining_settings: std::iter::Peekable<std::vec::IntoIter<GroupedSetting<'lines>>>,
}

impl<'de> de::MapAccess<'de> for GroupedSettingAccess<'de> {
    type Error = ClamdFormatError;

    fn next_key_seed<KeySeed: de::DeserializeSeed<'de>>(
        &mut self,
        key_seed: KeySeed,
    ) -> Result<Option<KeySeed::Value>, Self::Error> {
        let Some(grouped_setting) = self.remaining_settings.peek() else {
            return Ok(None);
        };
        let setting_name = grouped_setting.setting_name;
        key_seed
            .deserialize(de::value::BorrowedStrDeserializer::new(setting_name))
            .map(Some)
    }

    fn next_value_seed<ValueSeed: de::DeserializeSeed<'de>>(
        &mut self,
        value_seed: ValueSeed,
    ) -> Result<ValueSeed::Value, Self::Error> {
        let grouped_setting = self.remaining_settings.next().ok_or_else(|| {
            ClamdFormatError::Message("a value was read before its name".to_owned())
        })?;
        value_seed.deserialize(SettingValuesDeserializer {
            setting_name: grouped_setting.setting_name,
            setting_values: grouped_setting.setting_values,
        })
    }
}

impl<'de> de::Deserializer<'de> for RecordDeserializer<'de> {
    type Error = ClamdFormatError;

    fn deserialize_any<RecordVisitor: de::Visitor<'de>>(
        self,
        visitor: RecordVisitor,
    ) -> Result<RecordVisitor::Value, Self::Error> {
        visitor.visit_map(GroupedSettingAccess {
            remaining_settings: self.grouped_settings.into_iter().peekable(),
        })
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        option unit unit_struct newtype_struct seq tuple tuple_struct map struct enum identifier
        ignored_any
    }
}

struct SettingValuesDeserializer<'lines> {
    setting_name: &'lines str,
    setting_values: Vec<&'lines str>,
}

impl<'lines> SettingValuesDeserializer<'lines> {
    fn single_value(&self) -> Result<&'lines str, ClamdFormatError> {
        match self.setting_values.as_slice() {
            [single_value] => Ok(single_value),
            _several_values => Err(ClamdFormatError::RepeatedSetting {
                setting_name: self.setting_name.to_owned(),
            }),
        }
    }

    fn parsed_number<Number: FromStr>(&self) -> Result<Number, ClamdFormatError> {
        let number_text = self.single_value()?;
        number_text
            .parse()
            .map_err(|_unparsed| ClamdFormatError::InvalidValue {
                setting_name: self.setting_name.to_owned(),
                setting_value: number_text.to_owned(),
            })
    }

    fn value_deserializers(&self) -> Vec<Self> {
        self.setting_values
            .iter()
            .map(|setting_value| Self {
                setting_name: self.setting_name,
                setting_values: vec![setting_value],
            })
            .collect()
    }
}

impl<'de> IntoDeserializer<'de, ClamdFormatError> for SettingValuesDeserializer<'de> {
    type Deserializer = Self;

    fn into_deserializer(self) -> Self {
        self
    }
}

impl<'de> de::Deserializer<'de> for SettingValuesDeserializer<'de> {
    type Error = ClamdFormatError;

    fn deserialize_any<ValueVisitor: de::Visitor<'de>>(
        self,
        visitor: ValueVisitor,
    ) -> Result<ValueVisitor::Value, Self::Error> {
        if self.setting_values.len() == 1 {
            visitor.visit_borrowed_str(self.single_value()?)
        } else {
            self.deserialize_seq(visitor)
        }
    }

    fn deserialize_bool<ValueVisitor: de::Visitor<'de>>(
        self,
        visitor: ValueVisitor,
    ) -> Result<ValueVisitor::Value, Self::Error> {
        let switch_text = self.single_value()?;
        match switch_text.to_ascii_lowercase().as_str() {
            "yes" | "true" | "on" => visitor.visit_bool(true),
            "no" | "false" | "off" => visitor.visit_bool(false),
            _other_text => Err(ClamdFormatError::InvalidValue {
                setting_name: self.setting_name.to_owned(),
                setting_value: switch_text.to_owned(),
            }),
        }
    }

    fn deserialize_u8<ValueVisitor: de::Visitor<'de>>(
        self,
        visitor: ValueVisitor,
    ) -> Result<ValueVisitor::Value, Self::Error> {
        visitor.visit_u8(self.parsed_number()?)
    }

    fn deserialize_u16<ValueVisitor: de::Visitor<'de>>(
        self,
        visitor: ValueVisitor,
    ) -> Result<ValueVisitor::Value, Self::Error> {
        visitor.visit_u16(self.parsed_number()?)
    }

    fn deserialize_u32<ValueVisitor: de::Visitor<'de>>(
        self,
        visitor: ValueVisitor,
    ) -> Result<ValueVisitor::Value, Self::Error> {
        visitor.visit_u32(self.parsed_number()?)
    }

    fn deserialize_u64<ValueVisitor: de::Visitor<'de>>(
        self,
        visitor: ValueVisitor,
    ) -> Result<ValueVisitor::Value, Self::Error> {
        visitor.visit_u64(self.parsed_number()?)
    }

    fn deserialize_i32<ValueVisitor: de::Visitor<'de>>(
        self,
        visitor: ValueVisitor,
    ) -> Result<ValueVisitor::Value, Self::Error> {
        visitor.visit_i32(self.parsed_number()?)
    }

    fn deserialize_i64<ValueVisitor: de::Visitor<'de>>(
        self,
        visitor: ValueVisitor,
    ) -> Result<ValueVisitor::Value, Self::Error> {
        visitor.visit_i64(self.parsed_number()?)
    }

    fn deserialize_str<ValueVisitor: de::Visitor<'de>>(
        self,
        visitor: ValueVisitor,
    ) -> Result<ValueVisitor::Value, Self::Error> {
        visitor.visit_borrowed_str(self.single_value()?)
    }

    fn deserialize_string<ValueVisitor: de::Visitor<'de>>(
        self,
        visitor: ValueVisitor,
    ) -> Result<ValueVisitor::Value, Self::Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_option<ValueVisitor: de::Visitor<'de>>(
        self,
        visitor: ValueVisitor,
    ) -> Result<ValueVisitor::Value, Self::Error> {
        visitor.visit_some(self)
    }

    fn deserialize_newtype_struct<ValueVisitor: de::Visitor<'de>>(
        self,
        _struct_name: &'static str,
        visitor: ValueVisitor,
    ) -> Result<ValueVisitor::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<ValueVisitor: de::Visitor<'de>>(
        self,
        visitor: ValueVisitor,
    ) -> Result<ValueVisitor::Value, Self::Error> {
        visitor.visit_seq(SeqDeserializer::new(self.value_deserializers().into_iter()))
    }

    fn deserialize_ignored_any<ValueVisitor: de::Visitor<'de>>(
        self,
        visitor: ValueVisitor,
    ) -> Result<ValueVisitor::Value, Self::Error> {
        visitor.visit_unit()
    }

    forward_to_deserialize_any! {
        i8 i16 i128 u128 f32 f64 char bytes byte_buf unit unit_struct tuple tuple_struct map
        struct enum identifier
    }
}

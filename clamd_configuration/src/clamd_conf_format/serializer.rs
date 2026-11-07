use serde::{
    Serialize,
    ser::{self, Impossible},
};

use crate::clamd_conf_format::{ClamdFormatError, config_lines::SettingLine};

pub fn to_setting_lines<Record: Serialize>(
    record: &Record,
) -> Result<Vec<SettingLine>, ClamdFormatError> {
    record.serialize(RecordSerializer)
}

fn unsupported_shape(shape_name: &str) -> ClamdFormatError {
    ClamdFormatError::Message(format!("clamd.conf can't hold a {shape_name}"))
}

struct RecordSerializer;

struct RecordFieldCollector {
    collected_lines: Vec<SettingLine>,
}

impl ser::SerializeStruct for RecordFieldCollector {
    type Ok = Vec<SettingLine>;
    type Error = ClamdFormatError;

    fn serialize_field<FieldValue: ?Sized + Serialize>(
        &mut self,
        setting_name: &'static str,
        field_value: &FieldValue,
    ) -> Result<(), Self::Error> {
        let setting_values = field_value.serialize(ValueSerializer)?;
        setting_values.iter().try_for_each(|setting_value| {
            self.collected_lines
                .push(SettingLine::rendered(setting_name, setting_value)?);
            Ok(())
        })
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(self.collected_lines)
    }
}

impl ser::Serializer for RecordSerializer {
    type Ok = Vec<SettingLine>;
    type Error = ClamdFormatError;
    type SerializeSeq = Impossible<Self::Ok, Self::Error>;
    type SerializeTuple = Impossible<Self::Ok, Self::Error>;
    type SerializeTupleStruct = Impossible<Self::Ok, Self::Error>;
    type SerializeTupleVariant = Impossible<Self::Ok, Self::Error>;
    type SerializeMap = Impossible<Self::Ok, Self::Error>;
    type SerializeStruct = RecordFieldCollector;
    type SerializeStructVariant = Impossible<Self::Ok, Self::Error>;

    fn serialize_struct(
        self,
        _struct_name: &'static str,
        _field_count: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(RecordFieldCollector {
            collected_lines: Vec::new(),
        })
    }

    fn serialize_bool(self, _value: bool) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("bare value"))
    }
    fn serialize_i8(self, _value: i8) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("bare value"))
    }
    fn serialize_i16(self, _value: i16) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("bare value"))
    }
    fn serialize_i32(self, _value: i32) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("bare value"))
    }
    fn serialize_i64(self, _value: i64) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("bare value"))
    }
    fn serialize_u8(self, _value: u8) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("bare value"))
    }
    fn serialize_u16(self, _value: u16) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("bare value"))
    }
    fn serialize_u32(self, _value: u32) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("bare value"))
    }
    fn serialize_u64(self, _value: u64) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("bare value"))
    }
    fn serialize_f32(self, _value: f32) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("bare value"))
    }
    fn serialize_f64(self, _value: f64) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("bare value"))
    }
    fn serialize_char(self, _value: char) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("bare value"))
    }
    fn serialize_str(self, _value: &str) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("bare value"))
    }
    fn serialize_bytes(self, _value: &[u8]) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("bare value"))
    }
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(Vec::new())
    }
    fn serialize_some<Inner: ?Sized + Serialize>(
        self,
        inner_value: &Inner,
    ) -> Result<Self::Ok, Self::Error> {
        inner_value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(Vec::new())
    }
    fn serialize_unit_struct(self, _struct_name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(Vec::new())
    }
    fn serialize_unit_variant(
        self,
        _enum_name: &'static str,
        _variant_index: u32,
        _variant_name: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("bare value"))
    }
    fn serialize_newtype_struct<Inner: ?Sized + Serialize>(
        self,
        _struct_name: &'static str,
        inner_value: &Inner,
    ) -> Result<Self::Ok, Self::Error> {
        inner_value.serialize(self)
    }
    fn serialize_newtype_variant<Inner: ?Sized + Serialize>(
        self,
        _enum_name: &'static str,
        _variant_index: u32,
        _variant_name: &'static str,
        _inner_value: &Inner,
    ) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("enum"))
    }
    fn serialize_seq(self, _length: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Err(unsupported_shape("list of records"))
    }
    fn serialize_tuple(self, _length: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(unsupported_shape("tuple"))
    }
    fn serialize_tuple_struct(
        self,
        _struct_name: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(unsupported_shape("tuple"))
    }
    fn serialize_tuple_variant(
        self,
        _enum_name: &'static str,
        _variant_index: u32,
        _variant_name: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(unsupported_shape("enum"))
    }
    fn serialize_map(self, _length: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(unsupported_shape("map"))
    }
    fn serialize_struct_variant(
        self,
        _enum_name: &'static str,
        _variant_index: u32,
        _variant_name: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(unsupported_shape("enum"))
    }
}

struct ValueSerializer;

struct ValueListCollector {
    collected_values: Vec<String>,
}

impl ser::SerializeSeq for ValueListCollector {
    type Ok = Vec<String>;
    type Error = ClamdFormatError;

    fn serialize_element<Element: ?Sized + Serialize>(
        &mut self,
        list_element: &Element,
    ) -> Result<(), Self::Error> {
        self.collected_values
            .extend(list_element.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(self.collected_values)
    }
}

fn single_text(value_text: impl ToString) -> Result<Vec<String>, ClamdFormatError> {
    Ok(vec![value_text.to_string()])
}

impl ser::Serializer for ValueSerializer {
    type Ok = Vec<String>;
    type Error = ClamdFormatError;
    type SerializeSeq = ValueListCollector;
    type SerializeTuple = Impossible<Self::Ok, Self::Error>;
    type SerializeTupleStruct = Impossible<Self::Ok, Self::Error>;
    type SerializeTupleVariant = Impossible<Self::Ok, Self::Error>;
    type SerializeMap = Impossible<Self::Ok, Self::Error>;
    type SerializeStruct = Impossible<Self::Ok, Self::Error>;
    type SerializeStructVariant = Impossible<Self::Ok, Self::Error>;

    fn serialize_bool(self, switched_on: bool) -> Result<Self::Ok, Self::Error> {
        single_text(if switched_on { "yes" } else { "no" })
    }
    fn serialize_i8(self, number: i8) -> Result<Self::Ok, Self::Error> {
        single_text(number)
    }
    fn serialize_i16(self, number: i16) -> Result<Self::Ok, Self::Error> {
        single_text(number)
    }
    fn serialize_i32(self, number: i32) -> Result<Self::Ok, Self::Error> {
        single_text(number)
    }
    fn serialize_i64(self, number: i64) -> Result<Self::Ok, Self::Error> {
        single_text(number)
    }
    fn serialize_u8(self, number: u8) -> Result<Self::Ok, Self::Error> {
        single_text(number)
    }
    fn serialize_u16(self, number: u16) -> Result<Self::Ok, Self::Error> {
        single_text(number)
    }
    fn serialize_u32(self, number: u32) -> Result<Self::Ok, Self::Error> {
        single_text(number)
    }
    fn serialize_u64(self, number: u64) -> Result<Self::Ok, Self::Error> {
        single_text(number)
    }
    fn serialize_f32(self, number: f32) -> Result<Self::Ok, Self::Error> {
        single_text(number)
    }
    fn serialize_f64(self, number: f64) -> Result<Self::Ok, Self::Error> {
        single_text(number)
    }
    fn serialize_char(self, character: char) -> Result<Self::Ok, Self::Error> {
        single_text(character)
    }
    fn serialize_str(self, value_text: &str) -> Result<Self::Ok, Self::Error> {
        single_text(value_text)
    }
    fn serialize_bytes(self, _value: &[u8]) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("byte string"))
    }
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(Vec::new())
    }
    fn serialize_some<Inner: ?Sized + Serialize>(
        self,
        inner_value: &Inner,
    ) -> Result<Self::Ok, Self::Error> {
        inner_value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(Vec::new())
    }
    fn serialize_unit_struct(self, _struct_name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(Vec::new())
    }
    fn serialize_unit_variant(
        self,
        _enum_name: &'static str,
        _variant_index: u32,
        variant_name: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        single_text(variant_name)
    }
    fn serialize_newtype_struct<Inner: ?Sized + Serialize>(
        self,
        _struct_name: &'static str,
        inner_value: &Inner,
    ) -> Result<Self::Ok, Self::Error> {
        inner_value.serialize(self)
    }
    fn serialize_newtype_variant<Inner: ?Sized + Serialize>(
        self,
        _enum_name: &'static str,
        _variant_index: u32,
        _variant_name: &'static str,
        _inner_value: &Inner,
    ) -> Result<Self::Ok, Self::Error> {
        Err(unsupported_shape("enum with data"))
    }
    fn serialize_seq(self, _length: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(ValueListCollector {
            collected_values: Vec::new(),
        })
    }
    fn serialize_tuple(self, _length: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(unsupported_shape("tuple"))
    }
    fn serialize_tuple_struct(
        self,
        _struct_name: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(unsupported_shape("tuple"))
    }
    fn serialize_tuple_variant(
        self,
        _enum_name: &'static str,
        _variant_index: u32,
        _variant_name: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(unsupported_shape("enum with data"))
    }
    fn serialize_map(self, _length: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(unsupported_shape("nested map"))
    }
    fn serialize_struct(
        self,
        _struct_name: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Err(unsupported_shape("nested record"))
    }
    fn serialize_struct_variant(
        self,
        _enum_name: &'static str,
        _variant_index: u32,
        _variant_name: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(unsupported_shape("enum with data"))
    }
}

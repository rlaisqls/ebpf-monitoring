use std::collections::HashMap;
use std::fs;
use std::str;
use std::string::String;

use gimli::{AttributeValue, constants::DW_AT_byte_size, constants::DW_AT_data_member_location, constants::DW_AT_name, Dwarf, EndianSlice, LittleEndian};
use object::Object;

use crate::error::Error::InvalidData;
use crate::error::Result;

impl Typ {
    fn get_field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|field| field.name == name)
    }
}
#[derive(Debug)]
struct Field {
    name: String,
    offset: u64,
}

#[derive(Debug)]
struct Typedef {
    name: String,
    type_offsets: Vec<u32>,
}

#[derive(Debug)]
struct Typ {
    name: String,
    fields: Vec<Field>,
    size: i64,
}

#[derive(Debug)]
struct Index {
    offset_to_type: HashMap<u32, Typ>,
    typedefs: HashMap<String, Typedef>,
}

impl Index {
    fn new() -> Self {
        Self {
            offset_to_type: HashMap::new(),
            typedefs: HashMap::new(),
        }
    }

    fn get_type_by_name(&self, name: &str) -> Option<&Typ> {
        let typedef = self.typedefs.get(name)?;
        let mut types = Vec::new();
        for &offset in &typedef.type_offsets {
            if let Some(typ) = self.offset_to_type.get(&offset) {
                types.push(typ);
            }
        }
        types.first().cloned()
    }
}

fn struct_member_offsets_from_dwarf(data: &Dwarf<&str>) -> Result<Index> {
    let mut res = Index::new();

    for unit in data.units() {
        let abbrevs = unit.abbreviations()?;
        let mut entries = unit.entries();

        while let Some(entry) = entries.next()? {
            let attrs = entry.attrs(&abbrevs)?;

            match entry.tag() {
                gimli::DW_TAG_structure_type | gimli::DW_TAG_typedef => {
                    let name = match attrs.get(DW_AT_name) {
                        Some(AttributeValue::DebugStrRef(name_offset)) => {
                            let debug_str = data.debug_str()?;
                            debug_str.get_str(*name_offset)?.to_string()
                        }
                        _ => continue,
                    };

                    let byte_size = match attrs.get(DW_AT_byte_size) {
                        Some(AttributeValue::Udata(size)) => *size as i64,
                        _ => 0,
                    };

                    if byte_size == 0 {
                        continue;
                    }
                    let mut fields = Vec::new();
                    for attr in attrs {
                        if let (DW_AT_name, Some(AttributeValue::DebugStrRef(name_offset))) = attr {
                            let name = data.debug_str()?.get_str(*name_offset)?.to_string();

                            if let (DW_AT_data_member_location, Some(AttributeValue::Exprloc(data))) = attr {
                                let offset = parse_expr(data)?;
                                fields.push(Field { name, offset });
                            }
                        }
                    }

                    let typ = Typ {
                        name,
                        fields,
                        size: byte_size,
                    };

                    if let Some(typedef) = attrs.get(DW_AT_name) {
                        if let Some(AttributeValue::DebugStrRef(type_name_offset)) = typedef {
                            let name = data.debug_str()?.get_str(*type_name_offset)?.to_string();

                            if let Some(AttributeValue::UnitRef(type_offset)) = attrs.get(gimli::DW_AT_type) {
                                let typedef = res.typedefs.entry(name.clone()).or_insert_with(|| Typedef {
                                    name,
                                    type_offsets: Vec::new(),
                                });

                                typedef.type_offsets.push(*type_offset);
                            }
                        }
                    }

                    let offset = entry.offset();
                    res.offset_to_type.insert(offset, typ);
                }
                _ => {}
            }
        }
    }
    Ok(res)
}

fn parse_expr(data: &[u8]) -> Result<u64> {
    let mut reader = gimli::EndianBuf::new(data, gimli::RunTimeEndian::Little);
    let mut expr = Vec::new();

    while let Ok(oper) = gimli::Reader::read_uleb128(&mut reader) {
        match oper {
            0 => break,
            2 => expr.push(0x90),
            _ => expr.push(oper as u8),
        }
    }

    let mut stack = Vec::new();

    for &op in &expr {
        match op {
            0x90 => {
                let v = stack.pop().ok_or(InvalidData("Empty stack".to_string()))?;
                stack.push(v + 1);
            }
            0x9c => {
                let b = stack.pop().ok_or(InvalidData("Empty stack".to_string()))?;
                let a = stack.pop().ok_or(InvalidData("Empty stack".to_string()))?;
                stack.push(a + b);
            }
            op => stack.push(op as u64),
        }
    }

    if stack.len() != 1 {
        return Err(InvalidData("Invalid expression".to_string()));
    }

    Ok(stack[0])
}

#[derive(Debug)]
struct FieldDump {
    name: String,
    offset: i32,
}

fn dump(elf_path: &str, fields: &[Need], types: &Index) -> Result<Vec<FieldDump>> {

    let elf_file = fs::File::open(elf_path)?;

    let dwarf = Dwarf::load(|id| -> Result<_, gimli::Error> {
        let endian = LittleEndian;
        let bytes = elf_file.section_data_by_name(id.name()).map_or(Ok(&[][..]), |data| Ok(data))?;
        Ok(EndianSlice::new(bytes, endian))
    })?;

    let types = struct_member_offsets_from_dwarf(&dwarf)?;

    let mut field_dumps = Vec::new();
    for need in fields {
        let typ = types.get_type_by_name(&need.name)
            .or_else(|| types.get_type_by_name(&need.pretty_name));

        let mut e: Vec<FieldDump> = Vec::new();
        if let Some(typ) = typ {
            for need_field in &need.fields {
                let o = if let Some(f) = typ.get_field(&need_field.name) {
                    f.offset as i32
                } else {
                    -1
                };
                let pname = if need_field.print_name.is_empty() {
                    format!("{}{}", type_name(&need), field_name(&need_field.name))
                } else {
                    need_field.print_name.clone()
                };
                e.push(FieldDump { name: pname, offset: o });
            }
            if need.size {
                let sz_name = format!("{}Size", type_name(&need));
                let size = if typ.size == 0 { -1 } else { typ.size as i32 };
                e.push(FieldDump { name: sz_name, offset: size });
            }
        }
        field_dumps.extend(e);
    }
    Ok(field_dumps)
}

#[derive(Debug)]
struct Need {
    name: String,
    pretty_name: String,
    fields: Vec<NeedField>,
    size: bool,
}

#[derive(Debug)]
struct NeedField {
    name: String,
    print_name: String,
}

#[derive(Debug)]
struct Version {
    major: i32,
    minor: i32,
    patch: i32,
}

fn type_name(need: &Need) -> String {
    let n = if need.pretty_name.is_empty() { need.name.clone() } else { need.pretty_name.clone() };
    let mut n = n.trim_matches(&['_', '_'] as &[_]).to_owned();
    let parts: Vec<&str> = n.split('_').collect();
    let mut result = String::new();

    for part in parts {
        let (first, rest) = part.split_at(1);
        result.push_str(&first.to_uppercase());
        result.push_str(rest);
    }

    result
}

fn field_name(field: &str) -> String {
    let mut field = field.trim_start_matches('_');
    let parts: Vec<&str> = field.split('_').collect();
    let mut result = String::new();

    for part in parts {
        let (first, rest) = part.split_at(1);
        result.push_str(&first.to_uppercase());
        result.push_str(rest);
    }

    result
}
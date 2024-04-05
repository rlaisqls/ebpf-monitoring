use crate::ebpf::symtab::elf::elfmmap::MappedElfFile;
use crate::error::Error::{InvalidData, NotFound};
use crate::error::Result;

#[derive(Debug, Copy)]
pub struct BuildID {
    id: String,
    typ: String,
}

impl BuildID {
    fn new(id: String, typ: String) -> Self {
        BuildID { id, typ }
    }

    fn empty(&self) -> bool {
        self.id.is_empty() || self.typ.is_empty()
    }

    fn is_gnu(&self) -> bool {
        self.typ == "gnu"
    }
}

pub trait BuildIdentified {
    fn build_id(&self) -> Result<BuildID>;
    fn go_build_id(&self) -> Result<BuildID>;
    fn gnu_build_id(&self) -> Result<BuildID>;
}

impl BuildIdentified for MappedElfFile {
    fn build_id(&mut self) -> Result<BuildID> {
        let id_result = self.gnu_build_id();
        if let Ok(id) = id_result {
            if !id.empty() {
                return Ok(id);
            }
        } else if !id_result.is_err() {
            return Err(*Box::new(id_result.err().unwrap()));
        }

        let id_result = self.go_build_id();
        if let Ok(id) = id_result {
            if !id.empty() {
                return Ok(id);
            }
        } else if !id_result.is_err() {
            return Err(NotFound("".to_string()));
        }

        Err(NotFound("".to_string()))
    }

    fn go_build_id(&mut self) -> Result<BuildID> {
        let build_id_section = self.section(".note.go.buildid");
        if build_id_section.is_none() {
            return Err(NotFound("".to_string()));
        }
        let build_id_section = build_id_section.unwrap();
        let data_result = self.section_data(build_id_section)?;
        let data = data_result.as_slice();
        if data.len() < 17 {
            return Err(InvalidData(".note.gnu.build-id is too small".to_string()));
        }

        let data = &data[16..data.len() - 1];
        if data.len() < 40 || data.iter().filter(|&&b| b == b'/').count() < 2 {
            return Err(InvalidData(format!("wrong .note.go.buildid {}", "")));
        }

        let id = String::from_utf8_lossy(data).to_string();
        if id == "redacted" {
            return Err(InvalidData(format!("blacklisted .note.go.buildid {}", "" /* provide fpath */)));
        }

        Ok(BuildID::new(id, "go".to_string()))
    }

    fn gnu_build_id(&mut self) -> Result<BuildID> {
        let build_id_section = self.section(".note.gnu.build-id");
        if build_id_section.is_none() {
            return Err(NotFound("".to_string()));
        }
        let build_id_section = build_id_section.unwrap();
        let data_result = self.section_data(build_id_section)?;
        let data = data_result.as_slice();
        if data.len() < 16 {
            return Err(InvalidData(".note.gnu.build-id is too small".to_string()));
        }
        if &data[12..15] != b"GNU" {
            return Err(InvalidData(".note.gnu.build-id is not a GNU build-id".to_string()))
        }

        let raw_build_id = &data[16..];
        if raw_build_id.len() != 20 && raw_build_id.len() != 8 {
            return Err(InvalidData(format!(".note.gnu.build-id has wrong size {}", "" /* provide fpath */)))
        }
        let build_id_hex = hex::encode(raw_build_id);
        Ok(BuildID::new(build_id_hex, "gnu".to_string()))
    }
}
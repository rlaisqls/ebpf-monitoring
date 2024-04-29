use crate::ebpf::symtab::elf::elfmmap::MappedElfFile;
use crate::error::Error::{InvalidData, NotFound};
use crate::error::Result;

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct BuildID {
    pub(crate) id: String,
    typ: String,
}

impl BuildID {
    pub fn new(id: String, typ: String) -> Self {
        BuildID { id, typ }
    }
    pub fn is_empty(&self) -> bool {
        self.id.is_empty() || self.typ.is_empty()
    }
    pub fn is_gnu(&self) -> bool {
        self.typ == "gnu"
    }
}

pub trait BuildIdentified {
    fn build_id(&mut self) -> Result<BuildID>;
    fn go_build_id(&mut self) -> Result<BuildID>;
    fn gnu_build_id(&mut self) -> Result<BuildID>;
}

impl BuildIdentified for MappedElfFile {
    fn build_id(&mut self) -> Result<BuildID> {
        let id_result = self.gnu_build_id();
        if let Ok(id) = id_result {
            if !id.is_empty() {
                return Ok(id);
            }
        }

        let id_result = self.go_build_id();
        if let Ok(id) = id_result {
            if !id.is_empty() {
                return Ok(id);
            }
        }
        Err(NotFound("Build id not found".to_string()))
    }

    fn go_build_id(&mut self) -> Result<BuildID> {
        let data_result = self.section_data_by_section_name(".note.gnu.build-id")?;
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
        let data_result = self.section_data_by_section_name(".note.gnu.build-id")?;
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
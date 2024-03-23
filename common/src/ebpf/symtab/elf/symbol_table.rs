use goblin::elf::SectionHeader;

use crate::ebpf::symtab::elf::elfmmap::MappedElfFile;
use crate::ebpf::symtab::gosym::pcindex::PCIndex;
use crate::error::{Error::NotFound, Result};

pub struct SymbolIndex {
    pub(crate) name: Name,
    pub(crate) value: u64,
}

pub(crate) struct Name(u32);
#[derive(Clone, Copy, Debug)]
pub(crate) struct SectionLinkIndex(u8);

pub(crate) const SECTION_TYPE_SYM: SectionLinkIndex = SectionLinkIndex(0);
pub(crate) const SECTION_TYPE_DYN_SYM: SectionLinkIndex = SectionLinkIndex(1);

impl Name {
    pub(crate) fn new(name_index: u32, link_index: SectionLinkIndex) -> Self {
        Name(name_index | (link_index) << 31)
    }

    fn name_index(&self) -> u32 {
        self.0 & 0x7FFFFFFF
    }

    fn link_index(&self) -> SectionLinkIndex {
        SectionLinkIndex((self.0 >> 31) as u8)
    }
}

struct FlatSymbolIndex {
    links: [SectionHeader; 2],
    names: Vec<Name>,
    values: PCIndex,
}

#[derive(Debug)]
pub struct SymbolTable {
    index: FlatSymbolIndex,
    file: MappedElfFile
}

impl SymbolTable {
    fn is_dead(&self) -> bool {
        self.file.err.is_some()
    }

    fn debug_info(&self) -> SymTabDebugInfo {
        SymTabDebugInfo {
            name: format!("SymbolTable {:?}", self),
            size: self.index.names.len(),
            file: self.file.fpath.clone().unwrap_or_default().to_str(),
            last_used_round: 0,
        }
    }

    fn size(&self) -> usize {
        self.index.names.len()
    }

    fn refresh(&mut self) {}

    fn debug_string(&self) -> String {
        format!(
            "SymbolTable{{ f = {} , sz = {} }}",
            self.file.file_path(),
            self.index.values.length()
        )
    }

    fn resolve(&mut self, addr: u64) -> String {
        if self.index.names.is_empty() {
            return String::new();
        }
        if let Some(i) = self.index.values.find_index(addr) {
            if let Ok(name) = self.symbol_name(i) {
                return name;
            }
        }
        String::new()
    }

    fn cleanup(&mut self) {
        self.file.close();
    }

    fn symbol_name(&mut self, idx: usize) -> Result<String> {
        let link_index = self.index.names[idx].link_index();
        let section_header_link = &self.index.links[link_index];
        let name_index = self.index.names[idx].name_index();

        let (s, b) = self.file.get_string(
            (name_index + section_header_link.sh_offset) as usize
        ).unwrap();
        if !b {
            return Err(NotFound(format!("failed to get symbols {:?}", link_index)));
        }
        Ok(s)
    }
}

pub struct SymTabDebugInfo {
    name: String,
    size: usize,
    file: String,
    last_used_round: usize,
}

impl Default for SymTabDebugInfo {
    fn default() -> Self {
        SymTabDebugInfo {
            name: "".to_string(),
            size: 0,
            file: "".to_string(),
            last_used_round: 0,
        }
    }
}

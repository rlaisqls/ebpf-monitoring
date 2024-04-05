use goblin::elf::SectionHeader;

use crate::ebpf::symtab::elf::elfmmap::MappedElfFile;
use crate::ebpf::symtab::elf::pcindex::PCIndex;
use crate::ebpf::symtab::symtab::SymbolNameResolver;
use crate::error::{Error::NotFound, Result};

pub struct SymbolIndex {
    pub(crate) name: Name,
    pub(crate) value: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SectionLinkIndex(u8);
pub(crate) struct Name(u32);

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

pub struct FlatSymbolIndex {
    pub(crate) links: [SectionHeader; 2],
    pub(crate) names: Vec<Name>,
    pub(crate) values: PCIndex
}

#[derive(Debug)]
pub struct SymbolNameTable {
    pub(crate) index: FlatSymbolIndex,
    pub(crate) file: MappedElfFile
}

impl SymbolNameResolver for SymbolNameTable {

    fn refresh(&mut self) {}

    fn cleanup(&mut self) {
        self.file.close();
    }

    fn debug_info(&self) -> SymTabDebugInfo {
        SymTabDebugInfo {
            name: format!("SymbolTable {:?}", self),
            size: self.index.names.len(),
            file: self.file.fpath.clone().unwrap_or_default().to_str(),
            last_used_round: 0,
        }
    }

    fn is_dead(&self) -> bool {
        self.file.err.is_some()
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
}

impl SymbolNameTable {

    fn size(&self) -> usize {
        self.index.names.len()
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

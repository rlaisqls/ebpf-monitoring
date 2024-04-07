use std::ops::Shl;
use goblin::elf::SectionHeader;

use crate::ebpf::symtab::elf::elfmmap::MappedElfFile;
use crate::ebpf::symtab::elf::pcindex::PCIndex;
use crate::ebpf::symtab::symtab::SymbolNameResolver;
use crate::ebpf::symtab::gcache::Resource;
use crate::error::{Error::NotFound, Result};

#[derive(PartialOrd, Eq, PartialEq, Ord, Clone)]
pub struct SymbolIndex {
    pub(crate) name: Name,
    pub(crate) value: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SectionLinkIndex(u8);

#[derive(PartialOrd, Ord, PartialEq, Eq, Debug, Clone)]
pub(crate) struct Name(pub(crate) u32);

pub(crate) const SECTION_TYPE_SYM: SectionLinkIndex = SectionLinkIndex(0);
pub(crate) const SECTION_TYPE_DYN_SYM: SectionLinkIndex = SectionLinkIndex(1);

impl Name {
    pub(crate) fn new(name_index: u32, link_index: SectionLinkIndex) -> Self {
        Name(name_index | (link_index.0 as u32) << 31)
    }
    fn name_index(&self) -> u32 {
        self.0 & 0x7FFFFFFF
    }
    fn link_index(&self) -> SectionLinkIndex {
        SectionLinkIndex((self.0 >> 31) as u8)
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FlatSymbolIndex {
    pub(crate) links: Vec<SectionHeader>,
    pub(crate) names: Vec<Name>,
    pub(crate) values: PCIndex
}

#[derive(Debug, Eq, Ord, PartialOrd, PartialEq)]
pub struct SymbolNameTable<'a> {
    pub(crate) index: FlatSymbolIndex,
    pub(crate) file: MappedElfFile<'a>
}

impl Resource for SymbolNameTable<'_> {
    fn refresh(&mut self) {}
    fn cleanup(&mut self) {
        self.file.close();
    }
}

impl SymbolNameResolver for SymbolNameTable<'_> {

    fn refresh(&mut self) {}
    fn cleanup(&mut self) {
        self.file.close();
    }

    fn debug_info(&self) -> SymTabDebugInfo {
        SymTabDebugInfo {
            name: format!("SymbolTable {:?}", self),
            size: self.index.names.len(),
            file: self.file.fpath.clone().to_str().unwrap().to_string(),
            last_used_round: 0,
        }
    }

    fn is_dead(&self) -> bool {
        // self.file.err.is_some()
        false
    }

    fn resolve(&mut self, addr: u64) -> Option<String> {
        if self.index.names.is_empty() {
            return None;
        }
        if let Some(i) = self.index.values.find_index(addr) {
            if let Ok(name) = self.symbol_name(i as usize) {
                return Some(name);
            }
        }
        None
    }
}

impl SymbolNameTable<'_> {

    fn size(&self) -> usize {
        self.index.names.len()
    }

    fn symbol_name(&mut self, idx: usize) -> Result<String> {
        let link_index = self.index.names[idx].link_index();
        let section_header_link = &self.index.links[link_index.0 as usize];
        let name_index = self.index.names[idx].name_index() as u64;

        let (s, b) = self.file.get_string(
            (name_index + section_header_link.sh_offset) as usize
        ).unwrap();
        if !b { return Err(NotFound(format!("failed to get symbols {:?}", link_index))); }
        Ok(s)
    }
}

pub struct SymTabDebugInfo {
    name: String,
    size: usize,
    file: String,
    pub(crate) last_used_round: usize,
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

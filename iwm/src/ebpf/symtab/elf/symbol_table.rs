use goblin::elf32::section_header::{SHT_DYNSYM, SHT_SYMTAB};
use goblin::elf::SectionHeader;

use crate::ebpf::symtab::elf::elfmmap::MappedElfFile;
use crate::ebpf::symtab::elf::pcindex::PCIndex;
use crate::ebpf::symtab::symtab::SymbolNameResolver;
use crate::ebpf::symtab::gcache::Resource;
use crate::error::{Error::NotFound, Result};
use crate::error::Error::SymbolError;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SymbolIndex {
    pub(crate) name: Name,
    pub(crate) value: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct SectionLinkIndex(u8);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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

pub struct FlatSymbolIndex {
    pub(crate) links: Vec<SectionHeader>,
    pub(crate) names: Vec<Name>,
    pub(crate) values: PCIndex
}

pub struct SymbolNameTable {
    pub(crate) index: FlatSymbolIndex,
    pub(crate) file: MappedElfFile
}

impl Resource for SymbolNameTable {
    fn refresh_resource(&mut self) {}
    fn cleanup_resource(&mut self) {
        self.file.close();
    }
}

impl SymbolNameResolver for SymbolNameTable {

    fn refresh(&mut self) {}
    fn cleanup(&mut self) {
        self.file.close();
    }

    fn debug_info(&self) -> SymTabDebugInfo {
        SymTabDebugInfo {
            name: format!("SymbolTable"), // add debug info
            size: self.index.names.len(),
            file: self.file.fpath.clone().to_str().unwrap().to_string(),
            last_used_round: 0,
        }
    }

    fn is_dead(&self) -> bool {
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

impl SymbolNameTable {

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

    pub fn new(mut elf_file: MappedElfFile) -> Result<SymbolNameTable> {
        let (sym, section_sym) = elf_file.get_symbols(SHT_SYMTAB)?;
        let (dynsym, section_dynsym) = elf_file.get_symbols(SHT_DYNSYM)?;
        let total = dynsym.len() + sym.len();
        if total == 0 {
            return Err(SymbolError("No Symbol".to_string()));
        }

        let mut all: Vec<SymbolIndex> = Vec::with_capacity(total);
        all.extend_from_slice(sym.as_slice());
        all.extend_from_slice(dynsym.as_slice());
        all.sort();

        let mut res = SymbolNameTable {
            index: FlatSymbolIndex {
                links: Vec::from([
                    elf_file.section_headers[section_sym as usize].clone(),    // should be at 0 - SectionTypeSym
                    elf_file.section_headers[section_dynsym as usize].clone()  // should be at 1 - SectionTypeDynSym
                ]),
                names: Vec::with_capacity(total),
                values: PCIndex::new(total)
            },
            file: elf_file
        };

        for (i, symbol) in all.iter().enumerate() {
            res.index.names.push(symbol.name.clone());
            res.index.values.set(i, symbol.value.clone());
        }
        Ok(res)
    }
}

#[derive(Debug)]
pub struct SymTabDebugInfo {
    name: String,
    pub(crate) size: usize,
    file: String,
    pub(crate) last_used_round: i32,
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

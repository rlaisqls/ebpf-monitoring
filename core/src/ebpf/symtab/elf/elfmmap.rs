use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use byteorder::{ByteOrder, LittleEndian};
use goblin::elf::{Elf, Header, ProgramHeaders, SectionHeader, SectionHeaders};
use goblin::elf::header::{EI_CLASS, ELFCLASS32, ELFCLASS64};
use goblin::elf::section_header::{SHT_DYNSYM, SHT_SYMTAB};
use goblin::elf::sym::{STT_FUNC, sym32, sym64};

use crate::ebpf::symtab::elf::pcindex::PCIndex;
use crate::ebpf::symtab::elf::symbol_table::{FlatSymbolIndex, SECTION_TYPE_DYN_SYM, SECTION_TYPE_SYM, SectionLinkIndex, SymbolIndex, SymbolNameTable};
use crate::ebpf::symtab::elf::symbol_table::Name;
use crate::error::Error::{NotFound, SymbolError};
use crate::error::Result;

#[derive(Debug)]
pub struct MappedElfFile {
    pub header: Header,
    pub program_headers: ProgramHeaders,
    pub section_headers: SectionHeaders,
    pub strtab: HashMap<usize, String>,
    pub fpath: PathBuf,
    pub fd: Option<File>,
    pub string_cache: HashMap<usize, String>
}

#[derive(Debug)]
pub struct SymbolsOptions {
    filter_from: u64,
    filter_to: u64,
}

impl MappedElfFile {
    pub fn new(fpath: PathBuf) -> Result<Self> {
        let fd = Some(File::open(&fpath).unwrap());
        let mut buffer = Vec::new();
        fd.as_ref().borrow_mut().unwrap().read_to_end(&mut buffer).unwrap();
        let elf = Elf::parse(buffer.as_slice()).unwrap();

        let strtab = elf.section_headers.iter()
            .map(|s| (s.sh_name, elf.shdr_strtab.get_at(s.sh_name).unwrap().to_string()))
            .collect::<HashMap<usize, String>>();

        Ok(Self {
            header: elf.header,
            program_headers: elf.program_headers,
            section_headers: elf.section_headers,
            strtab,
            fpath,
            fd,
            string_cache: HashMap::new(),
        })
    }

    pub fn section(&self, name: &str) -> Option<&SectionHeader> {
        self.section_headers.iter()
            .find(|s| self.strtab.get(&s.sh_name) == Some(&name.to_string()))
    }

    fn section_by_type(&self, typ: u32) -> Option<&SectionHeader> {
        self.section_headers.iter()
            .find(|s| s.sh_type == typ)
    }

    fn open(&mut self) -> Result<()> {
        let fd = File::open(&self.fpath).unwrap();
        self.fd = Some(fd);
        Ok(())
    }

    pub(crate) fn section_data_by_section_name(&mut self, name: &str) -> Result<Vec<u8>> {
        let section = match self.section_headers
            .iter().find(|s| self.strtab.get(&s.sh_name) == Some(&name.to_string())) {
            Some(section) => section,
            None => return Err(NotFound("section_data_by_section_name".to_string()))
        };
        let mut res = vec![0; section.sh_size as usize];
        let mut fd = self.fd.borrow_mut().as_ref().unwrap();
        fd.seek(SeekFrom::Start(section.sh_offset)).unwrap();
        fd.read_exact(&mut res).unwrap();

        Ok(res)
    }

    pub(crate) fn section_data(&mut self, typ: u32) -> Result<(Vec<u8>, &SectionHeader)> {
        let section = match self.section_headers.iter().find(|s| s.sh_type == typ) {
            Some(section) => section,
            None => return Err(SymbolError("No symbol section".to_string())),
        };
        let mut res = vec![0; section.sh_size as usize];
        let mut fd = self.fd.borrow_mut().as_ref().unwrap();
        fd.seek(SeekFrom::Start(section.sh_offset)).unwrap();
        fd.read_exact(&mut res).unwrap();

        Ok((res, section))
    }

    pub(crate) fn get_string(&mut self, start: usize) -> Result<(String, bool)> {
        if let Some(s) = self.string_cache.get(&start).cloned() {
            return Ok((s, true));
        }

        const TMP_BUF_SIZE: usize = 128;
        let mut tmp_buf = [0; TMP_BUF_SIZE];
        let mut sb = String::new();

        for i in 0..10 {
            let mut fd = self.fd.borrow_mut().as_ref().unwrap();
            fd.seek(SeekFrom::Start((start + i * TMP_BUF_SIZE) as u64)).unwrap();
            fd.read_exact(&mut tmp_buf).unwrap();

            if let Some(idx) = tmp_buf.iter().position(|&x| x == 0) {
                sb.push_str(&String::from_utf8_lossy(&tmp_buf[..idx]));
                let s = sb.clone();
                self.string_cache.insert(start, s.clone());
                return Ok((s, true));
            } else {
                sb.push_str(&String::from_utf8_lossy(&tmp_buf));
            }
        }
        Ok((String::new(), false))
    }

    pub(crate) fn close(&mut self) {
        self.fd = None;
        self.string_cache.clear();
        self.section_headers.clear();
    }

    fn get_symbols(&mut self, typ: u32) -> Result<(Vec<SymbolIndex>, u32)> {
        match self.header.e_ident[EI_CLASS] {
            ELFCLASS32 => self.get_symbols32(typ),
            ELFCLASS64 => self.get_symbols64(typ),
            class => Err(SymbolError(format!("Invalid class in Header: {}", class)))
        }
    }

    fn get_symbols64(&mut self, typ: u32) -> Result<(Vec<SymbolIndex>, u32)> {
        let (mut data, section) = self.section_data(typ).unwrap();
        if data.len() % sym64::SIZEOF_SYM != 0 {
            return Err(SymbolError("Length of symbol section is not a multiple of Sym64Size".to_string()));
        }

        data = data.split_off(sym64::SIZEOF_SYM);
        let mut symbols = Vec::new();
        let mut i = 0;
        let mut sym = [0; sym64::SIZEOF_SYM];

        while !data.is_empty() {
            sym.copy_from_slice(&data[..sym64::SIZEOF_SYM]);
            data = data.split_off(sym64::SIZEOF_SYM);

            let name = LittleEndian::read_u32(&sym[0..4]);
            let info = sym[4];
            let value = LittleEndian::read_u64(&sym[8..16]);

            if value != 0 && (info & 0xf) == STT_FUNC {
                if name >= 0x7fffffff {
                    return Err(SymbolError("Wrong symbol name".to_string()));
                }
                let pc = value;
                // if pc >= opt.filter_from && pc < opt.filter_to {
                //     continue;
                // }
                let link_index = get_link_index(typ);
                symbols.push(SymbolIndex {
                    name: Name::new(name, link_index.clone()),
                    value: pc,
                });
                i += 1;
            }
        }
        Ok((symbols, section.sh_link))
    }

    fn get_symbols32(&mut self, typ: u32) -> Result<(Vec<SymbolIndex>, u32)> {
        let (mut data, section)  = self.section_data(typ).unwrap();
        if data.len() % sym32::SIZEOF_SYM != 0 {
            return Err(SymbolError("Length of symbol section is not a multiple of Sym32Size".to_string()));
        }

        data = data.split_off(sym32::SIZEOF_SYM);
        let mut symbols = Vec::new();
        let mut i = 0;
        let mut sym = [0; sym32::SIZEOF_SYM];

        while !data.is_empty() {
            sym.copy_from_slice(&data[..sym32::SIZEOF_SYM]);
            data = data.split_off(sym32::SIZEOF_SYM);

            let name = LittleEndian::read_u32(&sym[0..4]);
            let info = sym[12];
            let value = LittleEndian::read_u32(&sym[4..8]);

            if value != 0 && (info & 0xf) == STT_FUNC {
                if name >= 0x7fffffff {
                    return Err(SymbolError("Wrong symbol name".to_string()));
                }
                let pc = value as u64;
                // if pc >= opt.filter_from && pc < opt.filter_to {
                //     continue;
                // }
                let link_index = get_link_index(typ);
                symbols.push(SymbolIndex {
                    name: Name::new(name, link_index.clone()),
                    value: pc,
                });
                i += 1;
            }
        }
        Ok((symbols, section.sh_link))
    }
}

fn get_link_index(typ: u32) -> SectionLinkIndex {
    if typ == SHT_DYNSYM {
        SECTION_TYPE_DYN_SYM
    } else {
        SECTION_TYPE_SYM
    }
}

pub(crate) fn new_symbol_table(mut elf_file: MappedElfFile) -> Result<SymbolNameTable> {
    let (sym, section_sym) = elf_file.get_symbols(SHT_SYMTAB).unwrap();
    let (dynsym, section_dynsym) = elf_file.get_symbols(SHT_DYNSYM).unwrap();
    let total = dynsym.len() + sym.len();
    if total == 0 {
        return Err(SymbolError("No Symbol".to_string()));
    }

    let mut all: Vec<SymbolIndex> = Vec::with_capacity(total);
    all.extend_from_slice(sym.as_slice());
    all.extend_from_slice(dynsym.as_slice());
    all.sort();

    Ok(SymbolNameTable {
        index: FlatSymbolIndex {
            links: Vec::from([
                elf_file.section_headers[section_sym as usize].clone(),    // should be at 0 - SectionTypeSym
                elf_file.section_headers[section_dynsym as usize].clone()  // should be at 1 - SectionTypeDynSym
            ]),
            names: Vec::new(),
            values: PCIndex::new(total)
        },
        file: elf_file
    })
}

impl Drop for MappedElfFile {
    fn drop(&mut self) {
        if let Some(fd) = self.fd.take() {
            drop(fd);
        }
    }
}

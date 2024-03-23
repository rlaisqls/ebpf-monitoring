use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;

use anyhow::Error;
use byteorder::{ByteOrder, LittleEndian};
use goblin::elf::{Elf, ProgramHeader, SectionHeader};
use goblin::elf::Header;
use goblin::elf::header::{EI_CLASS, ELFCLASS32, ELFCLASS64};
use goblin::elf::section_header::SHT_DYNSYM;
use goblin::elf::sym::{STT_FUNC, sym32, sym64};

use crate::error::Result;
use crate::ebpf::symtab::elf::symbol_table::{SECTION_TYPE_DYN_SYM, SECTION_TYPE_SYM, SectionLinkIndex, SymbolIndex};
use crate::ebpf::symtab::elf::symbol_table::Name;

pub struct MappedElfFile {
    pub file_header: Header,
    pub sections: Vec<SectionHeader>,
    pub progs: Vec<ProgramHeader>,

    pub(crate) fpath: PathBuf,
    pub(crate) err:   Option<Err>,
    fd: Option<File>,

    string_cache: std::collections::HashMap<usize, String>,
}

struct SymbolsOptions<'a> {
    filter_from: u64,
    filter_to: u64,
}

impl MappedElfFile {
    pub fn new(fpath: PathBuf) -> io::Result<Self> {
        let mut res = Self {
            fpath,
            err: None,
            fd: None,
            file_header: Default::default(),
            sections: Vec::new(),
            progs: Vec::new(),
            string_cache: std::collections::HashMap::new(),
        };
        res.ensure_open()?;

        let mut buffer = Vec::new();
        res.fd.as_mut().unwrap().read_to_end(&mut buffer)?;

        let elf = Elf::parse(&buffer)?;
        res.file_header = elf.header;
        res.sections = elf.section_headers;
        res.progs = elf.program_headers;

        Ok(res)
    }

    pub(crate) fn section(&self, name: &str) -> Option<&SectionHeader> {
        self.sections.iter()
            .find(|s| s.name() == Some(name))
    }

    fn section_by_type(&self, typ: u32) -> Option<&SectionHeader> {
        self.sections.iter()
            .find(|s| s.sh_type == typ)
    }

    fn ensure_open(&mut self) -> Result<()> {
        if self.fd.is_none() {
            self.fd = Some(File::open(&self.fpath)?);
        }
        Ok(())
    }

    fn open(&mut self) -> Result<()> {
        let fd = File::open(&self.fpath)?;
        self.fd = Some(fd);
        Ok(())
    }

    pub(crate) fn section_data(&mut self, s: &SectionHeader) -> Result<Vec<u8>> {
        self.ensure_open()?;

        let mut file = File::open("your_file_name_here")?; // Replace "your_file_name_here" with your file name
        let mut res = vec![0; s.size() as usize];
        file.seek(SeekFrom::Start(s.sh_offset))?;
        file.read_exact(&mut res)?;

        Ok(res)
    }

    pub(crate) fn get_string(&mut self, start: usize) -> Result<(String, bool)> {
        self.ensure_open()?;
        if let Some(s) = self.string_cache.get(&start).cloned() {
            return Ok((s, true));
        }

        const TMP_BUF_SIZE: usize = 128;
        let mut tmp_buf = [0; TMP_BUF_SIZE];
        let mut sb = String::new();

        for i in 0..10 {
            self.fd.seek(SeekFrom::Start((start + i * TMP_BUF_SIZE) as u64))?;
            self.fd.read_exact(&mut tmp_buf)?;

            if let Some(idx) = tmp_buf.iter().position(|&x| x == 0) {
                sb.push_str(&String::from_utf8_lossy(&tmp_buf[..idx]));
                let mut s = sb.clone();
                self.string_cache.insert(start, s.clone());
                return (s, true);
            } else {
                sb.push_str(&String::from_utf8_lossy(&tmp_buf));
            }
        }
        (String::new(), false)
    }

    pub(crate) fn close(&mut self) {
        self.fd = None;
        self.string_cache.clear();
        self.sections.clear();
    }

    fn get_symbols(&mut self, typ: u32, opt: SymbolsOptions) -> io::Result<(Vec<SymbolIndex>, u32)> {
        match self.file_header.e_ident[EI_CLASS] {
            ELFCLASS32 => self.get_symbols64(typ, opt),
            ELFCLASS64 => self.get_symbols32(typ, opt),
            class =>Err(Error::Malformed(format!("Invalid class in Header: {}", class)))
        }
    }

    fn get_symbols64(&mut self, typ: u32, opt: SymbolsOptions) -> io::Result<(Vec<SymbolIndex>, u32)> {
        let symtab_section = match self.section_by_type(typ) {
            Some(section) => section,
            None => return Err(io::Error::new(io::ErrorKind::Other, "No symbol section")),
        };
        let link_index = Self::get_link_index(typ);

        let mut data = self.section_data(&symtab_section)?;
        if data.len() % sym64::SIZEOF_SYM != 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "Length of symbol section is not a multiple of Sym64Size"));
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
                    return Err(io::Error::new(io::ErrorKind::Other, "Wrong symbol name"));
                }
                let pc = value;
                if pc >= opt.filter_from && pc < opt.filter_to {
                    continue;
                }
                symbols.push(SymbolIndex {
                    name: Name::new(name, link_index),
                    value: pc,
                });
                i += 1;
            }
        }
        Ok((symbols, symtab_section.sh_link))
    }

    fn get_symbols32(&mut self, typ: u32, opt: SymbolsOptions) -> io::Result<(Vec<SymbolIndex>, u32)> {
        let symtab_section = match self.section_by_type(typ) {
            Some(section) => section,
            None => return Err(io::Error::new(io::ErrorKind::Other, "No symbol section")),
        };
        let link_index = Self::get_link_index(typ);

        let mut data = self.section_data(&symtab_section)?;
        if data.len() % sym32::SIZEOF_SYM != 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "Length of symbol section is not a multiple of Sym32Size"));
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
                    return Err(io::Error::new(io::ErrorKind::Other, "Wrong symbol name"));
                }
                let pc = value as u64;
                if pc >= opt.filter_from && pc < opt.filter_to {
                    continue;
                }
                symbols.push(SymbolIndex {
                    name: Name::new(name, link_index),
                    value: pc,
                });
                i += 1;
            }
        }

        Ok((symbols, symtab_section.sh_link))
    }

    fn get_link_index(typ: u32) -> SectionLinkIndex {
        if typ == SHT_DYNSYM {
            SECTION_TYPE_DYN_SYM
        } else {
            SECTION_TYPE_SYM
        }
    }
}

impl Drop for MappedElfFile {
    fn drop(&mut self) {
        if let Some(fd) = self.fd.take() {
            drop(fd);
        }
    }
}

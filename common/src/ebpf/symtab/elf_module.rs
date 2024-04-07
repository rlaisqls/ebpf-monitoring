use std::borrow::Borrow;
use std::fs;
use std::path::{Path, PathBuf};
use log::info;
use std::borrow::BorrowMut;
use goblin::elf::header::ET_EXEC;
use goblin::elf::program_header::{PF_X, PT_LOAD};
use rustix::path::Arg;

use crate::ebpf::metrics::symtab::SymtabMetrics;
use crate::ebpf::symtab::elf::buildid::{BuildID, BuildIdentified};
use crate::ebpf::symtab::elf::elfmmap::{MappedElfFile, new_symbol_table};
use crate::ebpf::symtab::elf::symbol_table::{SymbolNameTable, SymTabDebugInfo};
use crate::ebpf::symtab::elf_cache::ElfCache;
use crate::ebpf::symtab::procmap::ProcMap;
use crate::ebpf::symtab::stat::stat_from_file_info;
use crate::ebpf::symtab::symtab::{NoopSymbolNameResolver, SymbolNameResolver};
use crate::error::Error::{ELFError, NotFound};
use crate::error::Result;

#[derive(Clone)]
pub struct ElfTableOptions<'a> {
    pub(crate) elf_cache: ElfCache<'a>,
    pub(crate) metrics: SymtabMetrics,
    pub(crate) symbol_options: SymbolOptions,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct SymbolOptions {
    pub python_full_file_path: bool
}

impl Default for SymbolOptions {
    fn default() -> Self {
        Self { python_full_file_path: false }
    }
}

#[derive(Eq, PartialEq, PartialOrd, Ord)]
pub struct ElfTable<'a> {
    fs: String,
    pub(crate) table: Box<dyn SymbolNameResolver>,
    pub(crate) base: u64,
    loaded: bool,
    loaded_cached: bool,
    options: ElfTableOptions<'a>,
    proc_map: ProcMap,
    err: Option<crate::error::Error>
}

impl ElfTable<'_> {
    pub fn new(proc_map: ProcMap, fs: String, options: ElfTableOptions) -> Self {
        Self {
            fs,
            table: Box::new(NoopSymbolNameResolver {}),
            base: 0,
            loaded: false,
            loaded_cached: false,
            options,
            proc_map,
            err: None,
        }
    }

    fn load(&mut self) {
        if self.loaded { return; }
        self.loaded = true;
        let fs_elf_file_path = PathBuf::from(&self.fs).join(&self.proc_map.pathname);

        let me_result = MappedElfFile::new(fs_elf_file_path);
        let mut me = match me_result {
            Ok(file) => file,
            Err(err) => {
                self.on_load_error(err);
                return;
            }
        };

        if !self.find_base(&me) {
            self.err = Some(NotFound("".to_string()));
            return;
        }

        let build_id_result = me.build_id();
        let build_id = match build_id_result {
            Ok(id) => id,
            Err(err) => {
                // if err != NotFound
                self.on_load_error(err);
                return;
            }
        };

        if let Some(symbols) = self.options.elf_cache.get_symbols_by_build_id(&build_id) {
            self.table = Box::new(symbols);
            self.loaded_cached = true;
            return;
        }

        let file_info = match fs::metadata(&fs_elf_file_path) {
            Ok(info) => info,
            Err(err) => {
                self.on_load_error(ELFError(err.to_string()));
                return;
            }
        };

        if let Some(symbols) = self.options.elf_cache.get_symbols_by_stat(stat_from_file_info(&file_info)) {
            self.table = Box::new(symbols);
            self.loaded_cached = true;
            return;
        }

        let debug_file_path = self.find_debug_file(&build_id, me.borrow_mut()).unwrap();
        if !debug_file_path.is_empty() {
            let debug_me_result = MappedElfFile::new(PathBuf::from(&self.fs).join(debug_file_path));
            let mut debug_me = match debug_me_result {
                Ok(file) => file,
                Err(err) => {
                    self.on_load_error(err);
                    return;
                }
            };

            let symbols = match self.create_symbol_table(debug_me) {
                Ok(sym) => sym,
                Err(err) => {
                    self.on_load_error(err);
                    return;
                }
            };
            self.table = Box::new(symbols);
            self.options.elf_cache.cache_by_build_id(build_id, &symbols);
            return;
        }

        let symbols = match self.create_symbol_table(me) {
            Ok(sym) => sym,
            Err(_err) => {
                return;
            }
        };

        self.table = Box::new(symbols);
        if build_id.is_empty() {
            self.options.elf_cache.cache_by_stat(stat_from_file_info(&file_info), symbols.borrow());
        } else {
            self.options.elf_cache.cache_by_build_id(build_id, &symbols);
        }
    }

    fn find_base(&mut self, e: &MappedElfFile) -> bool {
        if e.elf.header.e_type == ET_EXEC {
            self.base = 0;
            return true;
        }
        for prog in &e.elf.program_headers {
            if prog.p_type == PT_LOAD && (prog.p_flags & PF_X != 0) {
                if self.proc_map.offset as u64 == prog.p_offset {
                    self.base = self.proc_map.start_addr - prog.p_vaddr;
                    return true;
                }
            }
        }
        false
    }

    fn on_load_error(&mut self, err: crate::error::Error) {
        self.err = Option::from(err);
        info!("failed to load elf table err: {}, f: {}, fs: {}",
            &err.to_string(), &self.proc_map.pathname.to_string(), &self.fs.to_string());
        self.options.metrics.elf_errors.with_label_values(&[&err.to_string()]).inc();
    }

    fn find_debug_file(&self, build_id: &BuildID, elf_file: &mut MappedElfFile) -> Option<String> {
        // Attempt to find debug file with build ID
        if let Some(debug_file) = self.find_debug_file_with_build_id(build_id) {
            return Some(debug_file);
        }

        // Attempt to find debug file with debug link
        self.find_debug_file_with_debug_link(elf_file)
    }

    fn find_debug_file_with_build_id(&self, build_id: &BuildID) -> Option<String> {
        let id = &build_id.id;
        if id.len() < 3 || !build_id.is_gnu() {
            return None;
        }

        let debug_file = format!("/usr/lib/debug/.build-id/{}/{}.debug", &id[0..2], &id[2..]);
        let fs_debug_file = Path::new(&self.fs).join(&debug_file);

        if fs_debug_file.exists() {
            return Some(debug_file);
        }

        None
    }

    fn find_debug_file_with_debug_link(&self, elf_file: &mut MappedElfFile) -> Option<String> {
        let elf_file_path = Path::new(&self.proc_map.pathname);
        let debug_link_section = elf_file.section(".gnu_debuglink").unwrap();
        let data = elf_file.section_data(debug_link_section).unwrap();

        if data.len() < 6 {
            return None;
        }

        let debug_link = String::from_utf8_lossy(&data[..data.len() - 4]).as_str().unwrap();

        let mut check_debug_file = |subdir: &str| -> Option<String> {
            let fs_debug_file = elf_file_path.with_file_name(subdir).join(&debug_link);
            if fs::metadata(&fs_debug_file).is_ok() {
                return Some(fs_debug_file.to_string_lossy().to_string());
            }
            None
        };

        if let Some(debug_file) = check_debug_file("") {
            return Some(debug_file);
        }
        if let Some(debug_file) = check_debug_file(".debug") {
            return Some(debug_file);
        }
        if let Some(debug_file) = check_debug_file("/usr/lib/debug") {
            return Some(debug_file);
        }

        None
    }

    fn create_symbol_table(&self, mut me: MappedElfFile) -> Result<SymbolNameTable> {
        match new_symbol_table(me) {
            Ok(table) => Ok(table),
            Err(sym_err) => {
                return Err(sym_err);
            }
        }
    }

    pub(crate) fn resolve(&mut self, mut pc: u64) -> Option<String> {
        if !self.loaded {
            self.load();
        }
        if let Some(_err) = &self.err { return None; }

        pc -= self.base;
        let res = self.table.resolve(pc);

        if res.is_some() {
            return res;
        } else if !self.table.is_dead() {
            return None;
        } else if !self.loaded_cached {
            self.err = Some(ELFError("Table is dead".to_string()));
            return None;
        }

        self.table = Box::new(NoopSymbolNameResolver {});
        self.loaded = false;
        self.loaded_cached = false;
        self.load();

        if let Some(_err) = &self.err { return None; }
        self.table.resolve(pc)
    }

    pub fn cleanup(&mut self) {
        self.table.cleanup();
    }
}

impl SymbolOptions {
    fn new(python_full_file_path: bool) -> Self {
        Self {
            python_full_file_path
        }
    }
}

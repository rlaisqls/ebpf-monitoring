use std::error::Error;
use std::fs;
use std::path::PathBuf;

use crate::ebpf::metrics::symtab::SymtabMetrics;
use crate::ebpf::symtab::elf::buildid::BuildIdentified;
use crate::ebpf::symtab::elf::elfmmap::MappedElfFile;
use crate::ebpf::symtab::stat::stat_from_file_info;
use crate::error::Error::NotFound;

pub struct ElfTable {
    fs: String,
    elf_file_path: String,
    table: Box<dyn SymbolNameResolver>,
    base: u64,
    loaded: bool,
    loaded_cached: bool,
    err: Option<dyn Error>,
    options: ElfTableOptions,
    proc_map: ProcMap,
}

pub struct ElfTableOptions {
    pub(crate) elf_cache: ElfCache,
    pub(crate) metrics: SymtabMetrics,
    pub(crate) symbol_options: SymbolOptions,
}

pub struct SymbolOptions {
    pub go_table_fallback: bool,
    pub python_full_file_path: bool
}

impl Default for SymbolOptions {
    fn default() -> Self {
        Self {
            go_table_fallback: false,
            python_full_file_path: false
        }
    }
}

struct ElfCache;

struct ProcMap;

trait SymbolNameResolver {
    fn resolve(&self, pc: u64) -> String;
    fn is_dead(&self) -> bool;
    fn cleanup(&mut self);
}

impl ElfTable {
    fn new(proc_map: ProcMap, fs: String, elf_file_path: String, options: ElfTableOptions) -> Self {
        let options = options.ensure_defaults();
        Self {
            fs,
            elf_file_path,
            table: Box::new(NoopSymbolNameResolver {}),
            base: 0,
            loaded: false,
            loaded_cached: false,
            err: None,
            options,
            proc_map,
        }
    }

    fn load(&mut self) {
        if self.loaded {
            return;
        }
        self.loaded = true;
        let fs_elf_file_path = PathBuf::from(&self.fs).join(&self.elf_file_path);

        let me_result = MappedElfFile::new(fs_elf_file_path);
        let mut me = match me_result {
            Ok(file) => file,
            Err(err) => {
                self.on_load_error(err);
                return;
            }
        };

        if !self.find_base(&me) {
            self.err = Err(NotFound(""));
            return;
        }

        let build_id_result = me.build_id();
        let build_id = match build_id_result {
            Ok(id) => id,
            Err(err) => {
                if err != NotFound {
                    self.on_load_error(err);
                }
                return;
            }
        };

        if let Some(symbols) = self.options.elf_cache.get_symbols_by_build_id(&build_id) {
            self.table = symbols;
            self.loaded_cached = true;
            return;
        }

        let file_info = match fs::metadata(&fs_elf_file_path) {
            Ok(info) => info,
            Err(err) => {
                self.on_load_error(err.into());
                return;
            }
        };

        if let Some(symbols) = self.options.elf_cache.get_symbols_by_stat(stat_from_file_info(&file_info)) {
            self.table = symbols;
            self.loaded_cached = true;
            return;
        }

        let debug_file_path = self.find_debug_file(&build_id, &me);
        if !debug_file_path.is_empty() {
            let debug_me_result = MappedElfFile::new(&PathBuf::from(&self.fs).join(&debug_file_path));
            let debug_me = match debug_me_result {
                Ok(file) => file,
                Err(err) => {
                    self.on_load_error(err);
                    return;
                }
            };

            let symbols_result = self.create_symbol_table(&debug_me);
            let symbols = match symbols_result {
                Ok(sym) => sym,
                Err(err) => {
                    self.on_load_error(err);
                    return;
                }
            };
            self.table = symbols;
            self.options.elf_cache.cache_by_build_id(&build_id, &symbols);
            return;
        }

        let symbols_result = self.create_symbol_table(&me);
        let symbols = match symbols_result {
            Ok(sym) => sym,
            Err(err) => {
                self.on_load_error(err);
                return;
            }
        };
        self.table = symbols;
        if build_id.is_empty() {
            self.options.elf_cache.cache_by_stat(stat_from_file_info(&file_info), &symbols);
        } else {
            self.options.elf_cache.cache_by_build_id(&build_id, &symbols);
        }
    }

    fn resolve(&mut self, mut pc: u64) -> String {
        if !self.loaded {
            self.load();
        }
        if let Some(_err) = &self.err { return String::new(); }

        pc -= self.base;
        let res = self.table.resolve(pc);

        if !res.is_empty() {
            return res;
        } else if !self.table.is_dead() {
            return String::new();
        } else if !self.loaded_cached {
            self.err = Some(String::from("Table is dead"));
            return String::new();
        }

        self.table = Box::new(NoopSymbolNameResolver {});
        self.loaded = false;
        self.loaded_cached = false;
        self.load();

        if let Some(_err) = &self.err { return String::new(); }
        self.table.resolve(pc)
    }

}

impl ElfTableOptions {
    fn ensure_defaults(self) -> Self {
        let mut new_self = self;
        if new_self.symbol_options.is_none() {
            new_self.symbol_options = Some(SymbolOptions::default());
        }
        if new_self.metrics.is_none() {
            panic!("metrics is nil");
        }
        new_self
    }
}

impl SymbolOptions {
    fn new(go_table_fallback: bool, python_full_file_path: bool) -> Self {
        Self {
            go_table_fallback,
            python_full_file_path
        }
    }
}

struct NoopSymbolNameResolver;

impl SymbolNameResolver for NoopSymbolNameResolver {
    fn resolve(&self, _pc: u64) -> String {
        String::new()
    }
    fn is_dead(&self) -> bool {
        false
    }
    fn cleanup(&mut self) {}
}
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use gimli::DebugInfo;
use crate::error::Result;
use crate::ebpf::symtab::elf::buildid::BuildID;
use crate::ebpf::symtab::elf::symbol_table::{SymbolNameTable, SymTabDebugInfo};
use crate::ebpf::symtab::gcache::{debug_info, GCache, GCacheDebugInfo, GCacheOptions};
use crate::ebpf::symtab::stat::Stat;
use crate::ebpf::symtab::symtab::SymbolNameResolver;

pub struct ElfCache<'a> {
    build_id_cache: Mutex<GCache<BuildID, SymbolNameTable<'a>>>,
    same_file_cache: Mutex<GCache<Stat, SymbolNameTable<'a>>>,
}

impl<'a> ElfCache<'a> {
    pub fn new(build_id_cache_options: GCacheOptions, same_file_cache_options: GCacheOptions) -> Result<Self> {
        let build_id_cache = Mutex::new(GCache::<BuildID, SymbolNameTable>::new(build_id_cache_options));
        let same_file_cache = Mutex::new(GCache::<Stat, SymbolNameTable>::new(same_file_cache_options));
        Ok(Self { build_id_cache, same_file_cache })
    }

    pub fn get_symbols_by_build_id(&self, build_id: &BuildID) -> Option<Arc<SymbolNameTable>> {
        let res = self.build_id_cache.lock().unwrap().get(build_id).unwrap();
        if res.is_dead() {
            self.build_id_cache.lock().unwrap().remove(build_id);
            return None;
        }
        Some(res)
    }

    pub fn cache_by_build_id(&self, build_id: BuildID, v: Arc<SymbolNameTable>) {
        self.build_id_cache.lock().unwrap().cache(build_id, v);
    }

    pub fn get_symbols_by_stat(&self, s: Stat) -> Option<Arc<SymbolNameTable>> {
        let res = self.same_file_cache.lock().unwrap().get(&s);
        if res.is_none() {
            return None
        }
        let sym_tab = res.unwrap();
        if sym_tab.is_dead() {
            self.same_file_cache.lock().unwrap().remove(&s);
            return None;
        }
        Some(sym_tab)
    }

    pub fn cache_by_stat(&self, s: Stat, v: Arc<SymbolNameTable>) {
        self.same_file_cache.lock().unwrap().cache(s, v);
    }

    pub fn update(&self, build_id_cache_options: GCacheOptions, same_file_cache_options: GCacheOptions) {
        self.build_id_cache.lock().unwrap().update(build_id_cache_options);
        self.same_file_cache.lock().unwrap().update(same_file_cache_options);
    }

    pub fn next_round(&self) {
        self.build_id_cache.lock().unwrap().next_round();
        self.same_file_cache.lock().unwrap().next_round();
    }

    pub fn cleanup(&self) {
        self.build_id_cache.lock().unwrap().cleanup();
        self.same_file_cache.lock().unwrap().cleanup();
    }

    pub fn debug_info(&self) -> ElfCacheDebugInfo {
        let build_id_cache = debug_info::<BuildID, SymbolNameTable, SymTabDebugInfo>(
            self.build_id_cache.lock().unwrap().deref(),
            |b: &BuildID, v: &SymbolNameTable, round: i32| {
                let mut res = v.debug_info();
                res.last_used_round = round;
                res
            });
        let same_file_cache = debug_info::<Stat, SymbolNameTable, SymTabDebugInfo>(
            self.same_file_cache.lock().unwrap().deref(),
            |s: &Stat, v: &SymbolNameTable, round: i32| {
                let mut res = v.debug_info();
                res.last_used_round = round;
                res
            });
        ElfCacheDebugInfo { build_id_cache, same_file_cache }
    }
}

pub struct ElfCacheDebugInfo {
    build_id_cache: GCacheDebugInfo<SymTabDebugInfo>,
    same_file_cache: GCacheDebugInfo<SymTabDebugInfo>,
}

impl ElfCacheDebugInfo {
    pub fn new(build_id_cache: GCacheDebugInfo<SymTabDebugInfo>, same_file_cache: GCacheDebugInfo<SymTabDebugInfo>) -> Self {
        Self { build_id_cache, same_file_cache }
    }
}

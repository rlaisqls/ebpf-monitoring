use std::sync::Mutex;
use gimli::DebugInfo;
use crate::ebpf::symtab::elf::buildid::BuildID;
use crate::ebpf::symtab::elf::symbol_table::SymTabDebugInfo;
use crate::ebpf::symtab::gcache::{GCache, GCacheDebugInfo, GCacheOptions, SymbolNameResolver};
use crate::ebpf::symtab::stat::Stat;

#[derive(Eq, PartialEq)]
pub struct ElfCache {
    build_id_cache: Mutex<GCache<BuildID, SymbolNameResolver>>,
    same_file_cache: Mutex<GCache<Stat, SymbolNameResolver>>,
}

impl ElfCache {
    pub fn new(build_id_cache_options: GCacheOptions, same_file_cache_options: GCacheOptions) -> Result<Self, Box<dyn std::error::Error>> {
        let build_id_cache = Mutex::new(GCache::<BuildID, SymbolNameResolver>::new(build_id_cache_options)?);
        let same_file_cache = Mutex::new(GCache::<Stat, SymbolNameResolver>::new(same_file_cache_options)?);

        Ok(Self { build_id_cache, same_file_cache })
    }

    pub fn get_symbols_by_build_id(&self, build_id: BuildID) -> Option<SymbolNameResolver> {
        let res = self.build_id_cache.lock().unwrap().get(build_id)?;
        if res.is_dead() {
            self.build_id_cache.lock().unwrap().remove(build_id.borrow());
            return None;
        }
        Some(res)
    }

    pub fn cache_by_build_id(&self, build_id: BuildID, v: SymbolNameResolver) {
        if let Some(v) = v {
            self.build_id_cache.lock().unwrap().cache(build_id, v);
        }
    }

    pub fn get_symbols_by_stat(&self, s: Stat) -> Option<SymbolNameResolver> {
        let res = self.same_file_cache.lock().unwrap().get(s)?;
        if res.is_dead() {
            self.same_file_cache.lock().unwrap().remove(s);
            return None;
        }
        Some(res)
    }

    pub fn cache_by_stat(&self, s: Stat, v: SymbolNameResolver) {
        if let Some(v) = v {
            self.same_file_cache.lock().unwrap().cache(s, v);
        }
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
        let build_id_cache = DebugInfo::new(self.build_id_cache.lock().unwrap().debug_info(), |b, v, round| {
            let mut res = v.debug_info();
            res.last_used_round = round;
            res
        });

        let same_file_cache = DebugInfo::new(self.same_file_cache.lock().unwrap().debug_info(), |s, v, round| {
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

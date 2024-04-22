use std::sync::{Arc, Mutex};
use log::{debug, error};

use crate::ebpf::metrics::symtab::SymtabMetrics;


use crate::ebpf::symtab::elf_cache::{ElfCache, ElfCacheDebugInfo};
use crate::ebpf::symtab::elf_module::{ElfTableOptions, SymbolOptions};
use crate::ebpf::symtab::gcache::{debug_info, GCache, GCacheDebugInfo, GCacheOptions};
use crate::ebpf::symtab::kallsyms::new_kallsyms;
use crate::ebpf::symtab::proc::{ProcTable, ProcTableDebugInfo};
use crate::ebpf::symtab::symtab::SymbolNameResolver;
use crate::ebpf::symtab::table::SymbolTab;
use crate::error::Result;

pub type PidKey = u32;

// SymbolCache is responsible for resolving PC address to Symbol
// maintaining a pid -> ProcTable cache
// resolving kernel symbols
pub struct SymbolCache {
    pid_cache: GCache<PidKey, ProcTable>,
    elf_cache: Arc<ElfCache>,
    kallsyms: Option<Arc<Mutex<SymbolTab>>>,
    options: CacheOptions,
    metrics: Arc<SymtabMetrics>,
}

#[derive(Copy, Clone)]
pub struct CacheOptions {
    pub pid_cache_options: GCacheOptions,
    pub build_id_cache_options: GCacheOptions,
    pub same_file_cache_options: GCacheOptions,
    pub symbol_options: SymbolOptions,
}

impl SymbolCache {
    pub fn new(options: CacheOptions, metrics: &SymtabMetrics) -> Result<Self> {
        // if metrics.is_none() {
        //     panic!("metrics is nil");
        // }
        let elf_cache = ElfCache::new(options.build_id_cache_options, options.same_file_cache_options).unwrap();
        let pid_cache = GCache::<PidKey, ProcTable>::new(options.pid_cache_options);

        Ok(Self {
            pid_cache,
            kallsyms: None,
            elf_cache: Arc::new(elf_cache),
            options,
            metrics: Arc::new(metrics.clone()),
        })
    }

    pub fn next_round(&mut self) {
        self.pid_cache.next_round();
        self.elf_cache.next_round();
    }

    pub fn cleanup(&mut self) {
        self.elf_cache.cleanup();
        self.pid_cache.cleanup();
    }

    pub fn get_proc_table(&mut self, pid: PidKey) -> Option<Arc<Mutex<ProcTable>>> {
        if let Some(cached) = self.pid_cache.get(&pid) {
            return Some(cached.clone());
        }
        debug!("NewProcTable {}", pid);
        let fresh = Arc::new(Mutex::new(ProcTable::new(
            pid as i32,
            ElfTableOptions {
                elf_cache: self.elf_cache.clone(),
                metrics: self.metrics.clone()
            },
        )));
        self.pid_cache.cache(pid, fresh.clone());
        Some(fresh.clone())
    }

    pub fn get_kallsyms(&mut self) -> Arc<Mutex<SymbolTab>> {
        if let Some(kallsyms) = &self.kallsyms {
            return kallsyms.clone();
        }
        self.init_kallsyms()
    }

    fn init_kallsyms(&mut self) -> Arc<Mutex<SymbolTab>> {
        let kallsyms = new_kallsyms().unwrap_or_else(|err| {
            error!("kallsyms init fail err: {}", err);
            SymbolTab::new(Vec::new())
        });

        if kallsyms.symbols.is_empty() {
            let _ = error!("kallsyms is empty. check your permissions kptr_restrict==0 && sysctl_perf_event_paranoid <= 1 or kptr_restrict==1 &&  CAP_SYSLOG");
        }

        let ks = Arc::new(Mutex::new(kallsyms));
        self.kallsyms = Some(ks.clone());
        ks.clone()
    }

    pub fn update_options(&mut self, options: CacheOptions) {
        self.pid_cache.update(options.pid_cache_options);
        self.elf_cache.update(options.build_id_cache_options, options.same_file_cache_options);
    }

    pub fn pid_cache_debug_info(&self) -> GCacheDebugInfo<ProcTableDebugInfo> {
        debug_info::<PidKey, ProcTable, ProcTableDebugInfo>(
            &self.pid_cache,
            |_b: &PidKey, v: &Arc<Mutex<ProcTable>>, round: i32| {
                let value = v.lock().unwrap();
                let mut res = value.debug_info();
                res.last_used_round = round;
                res
            })
    }

    pub fn elf_cache_debug_info(&self) -> ElfCacheDebugInfo {
        self.elf_cache.debug_info()
    }

    pub fn remove_dead_pid(&mut self, pid: &PidKey) {
        self.pid_cache.remove(pid);
    }
}

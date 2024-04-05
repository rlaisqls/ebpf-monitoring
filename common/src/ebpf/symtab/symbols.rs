use log::{debug, error};
use crate::ebpf::symtab::elf_cache::{ElfCache, ElfCacheDebugInfo};
use crate::ebpf::symtab::gcache::{GCache, GCacheDebugInfo, GCacheOptions};
use crate::ebpf::metrics::symtab::SymtabMetrics;
use crate::ebpf::symtab::elf_module::{ElfTableOptions, SymbolOptions};
use crate::ebpf::symtab::proc::{ProcTable, ProcTableDebugInfo, ProcTableOptions};
use crate::ebpf::symtab::table::SymbolTab;
use crate::ebpf::symtab::kallsyms::new_kallsyms;

pub type PidKey = u32;

// SymbolCache is responsible for resolving PC address to Symbol
// maintaining a pid -> ProcTable cache
// resolving kernel symbols
pub struct SymbolCache {
    pid_cache: GCache<PidKey, ProcTable>,
    elf_cache: ElfCache,
    kallsyms: Option<SymbolTab>,
    options: CacheOptions,
    metrics: SymtabMetrics,
}

#[derive(Copy, Clone)]
pub struct CacheOptions {
    pub pid_cache_options: GCacheOptions,
    pub build_id_cache_options: GCacheOptions,
    pub same_file_cache_options: GCacheOptions,
    pub symbol_options: SymbolOptions,
}

impl SymbolCache {
    pub fn new(options: CacheOptions, metrics: SymtabMetrics) -> Result<Self, Box<dyn std::error::Error>> {
        if metrics.is_none() {
            panic!("metrics is nil");
        }

        let elf_cache = ElfCache::new(options.build_id_cache_options, options.same_file_cache_options)?;
        let pid_cache = GCache::<PidKey, ProcTable>::new(options.pid_cache_options)?;

        Ok(Self {
            pid_cache,
            kallsyms: None,
            elf_cache,
            options,
            metrics: metrics.clone(),
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

    pub fn get_proc_table(&mut self, pid: PidKey) -> ProcTable {
        if let Some(cached) = self.pid_cache.get(pid) {
            return cached.clone();
        }

        debug!("NewProcTable {}", pid);
        let fresh = ProcTable::new(
            ProcTableOptions {
                pid: pid as i32,
                elf_table_options: ElfTableOptions {
                    elf_cache: &self.elf_cache,
                    metrics: &self.metrics,
                    symbol_options: &self.options.symbol_options,
                },
            },
        );
        self.pid_cache.cache(pid, fresh.clone());

        fresh
    }

    pub fn get_kallsyms(&mut self) -> &SymbolTab {
        if let Some(kallsyms) = &self.kallsyms {
            return kallsyms.clone();
        }
        &self.init_kallsyms()
    }

    fn init_kallsyms(&mut self) -> SymbolTab {
        let mut kallsyms = new_kallsyms().unwrap_or_else(|err| {
            error!(self.logger, "kallsyms init fail"; "err" => err);
            SymbolTab::new(Vec::new())
        });

        if kallsyms.symbols.is_empty() {
            let _ = error!("kallsyms is empty. check your permissions kptr_restrict==0 && sysctl_perf_event_paranoid <= 1 or kptr_restrict==1 &&  CAP_SYSLOG");
        }

        self.kallsyms = Some(kallsyms.clone());
        kallsyms
    }

    pub fn update_options(&mut self, options: CacheOptions) {
        self.pid_cache.update(options.pid_cache_options);
        self.elf_cache.update(options.build_id_cache_options, options.same_file_cache_options);
    }

    pub fn pid_cache_debug_info(&self) -> GCacheDebugInfo<ProcTableDebugInfo> {
        self.pid_cache.debug_info(|k, v, round| {
            let mut res = v.debug_info();
            res.last_used_round = round;
            res
        })
    }

    pub fn elf_cache_debug_info(&self) -> ElfCacheDebugInfo {
        self.elf_cache.debug_info()
    }

    pub fn remove_dead_pid(&mut self, pid: PidKey) {
        self.pid_cache.remove(pid);
    }
}

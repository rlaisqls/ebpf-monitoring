use std::{collections::HashMap, sync::{Arc, Mutex}, thread};
use std::collections::HashSet;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::ebpf::cpuonline;

use crate::error::Result;
use crate::ebpf::metrics::metrics::Metrics;
use crate::ebpf::sd::target::{Target, TargetFinder};
use crate::ebpf::symtab::elf_cache::ElfCacheDebugInfo;
use crate::ebpf::symtab::gcache::GCacheDebugInfo;
use crate::ebpf::symtab::proc::ProcTableDebugInfo;
use crate::ebpf::symtab::symbols::{CacheOptions, PidKey, SymbolCache};

type CollectProfilesCallback =
Box<dyn Fn(Target, Vec<String>, u64, u32, bool) + Send + 'static>;

#[derive(Clone)]
pub struct SessionOptions {
    collect_user: bool,
    collect_kernel: bool,
    unknown_symbol_module_offset: bool,
    unknown_symbol_address: bool,
    python_enabled: bool,
    cache_options: CacheOptions,
    metrics: Arc<Metrics>,
    sample_rate: u32,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            collect_user: false,
            collect_kernel: false,
            unknown_symbol_module_offset: false,
            unknown_symbol_address: false,
            python_enabled: false,
            cache_options: Default::default(),
            metrics: Arc::new(Default::default()),
            sample_rate: 0,
        }
    }
}

enum SampleAggregation {
    SampleAggregated,
    SampleNotAggregated,
}

type DiscoveryTarget = HashMap<String, String>;

#[derive(Default)]
struct Pids {
    unknown: HashMap<u32, ()>,
    dead: HashMap<u32, ()>,
    all: HashMap<u32, ProcInfoLite>,
}

type ProfilingType = u8;

#[derive(Debug)]
struct ProcInfoLite {
    pid: u32,
    comm: String,
    exe: String,
    typ: ProfilingType,
}

struct Session {
    target_finder: Arc<TargetFinder>,
    sym_cache: Arc<Mutex<SymbolCache>>,
    bpf: ProfileObjects,
    events_reader: PerfReader,
    pid_info_requests: Vec<u32>,
    dead_pid_events: Vec<u32>,
    options: SessionOptions,
    round_number: u32,
    mutex: Mutex<()>, // Add your own mutex type here
    started: bool,
    kprobes: Vec<()>, // Add your own kprobe type here
    pyperf: Option<()>, // Add your own PyPerf type here
    pyperf_events: Vec<()>, // Add your own PyPerfEvent type here
    pyperf_bpf: Option<()>, // Add your own PyPerfBpf type here
    pyperf_error: Option<()>, // Add your own PyPerfError type here
    pids: Pids,
    pid_exec_requests: Vec<u32>,
    perf_events: ()
}

struct TargetsOptions {
    targets: Vec<DiscoveryTarget>,
    targets_only: bool,
    default_target: DiscoveryTarget,
    container_cache_size: i32,
}

impl Session {
    pub fn new(target_finder: Arc<TargetFinder>, session_options: SessionOptions) -> Result<Self> {
        let sym_cache = SymbolCache::new(
            session_options.cache_options,
            session_options.metrics.symtab.clone()
        )?;
        Ok(Self {
            target_finder,
            sym_cache: Arc::new(Mutex::new(sym_cache)),
            bpf: ProfileObjects::default(),
            events_reader: PerfReader::default(),
            pid_info_requests: Vec::new(),
            dead_pid_events: Vec::new(),
            options: session_options,
            round_number: 0,
            mutex: Mutex::new(()),
            started: false,
            kprobes: Vec::new(),
            pyperf: None,
            pyperf_events: Vec::new(),
            pyperf_bpf: None,
            pyperf_error: None,
            pids: Pids::default(),
            pid_exec_requests: Vec::new(),
        })
    }

    fn start(&mut self) -> Result<()> {
        let _guard = self.mutex.lock()?;

        if let Err(err) = rlimit::remove_memlock() {
            return Err(err);
        }

        let mut opts = ebpf::CollectionOptions::new();
        opts.programs.log_disabled = true;

        if let Err(err) = pyrobpf::load_profile_objects(&mut self.bpf, &opts) {
            self.stop_locked();
            return Err(err.into());
        }

        btf::flush_kernel_spec(); // save some memory

        let events_reader = perf::Reader::new(&self.bpf.profile_maps.events, 4 * os::getpagesize())?;
        self.perf_events = attach_perf_events(self.options.sample_rate, self.bpf.do_perf_event)?;

        if let Err(err) = self.link_kprobes() {
            self.stop_locked();
            return Err(err.into());
        }

        self.events_reader = Some(events_reader);
        let pid_info_requests = Arc::new(Mutex::new(Vec::with_capacity(1024)));
        let pid_exec_requests = Arc::new(Mutex::new(Vec::with_capacity(1024)));
        let dead_pid_events = Arc::new(Mutex::new(Vec::with_capacity(1024)));
        self.pid_info_requests = Some(pid_info_requests.clone());
        self.pid_exec_requests = Some(pid_exec_requests.clone());
        self.dead_pid_events = Some(dead_pid_events.clone());

        self.started = true;
        let wg = Arc::new(AtomicBool::new(true));
        let wg_clone = wg.clone();

        let events_reader_clone = self.events_reader.clone().unwrap();
        let pid_info_requests_clone = pid_info_requests.deref().clone();
        let pid_exec_requests_clone = pid_exec_requests.deref().clone();
        let dead_pid_events_clone = dead_pid_events.deref().clone();
        let mut threads = Vec::with_capacity(4);

        for f in vec![
            move || Session::read_events(events_reader_clone, pid_info_requests_clone, pid_exec_requests_clone, dead_pid_events_clone),
            move || Session::process_pid_info_requests(pid_info_requests_clone, wg_clone.clone()),
            move || Session::process_dead_pids_events(dead_pid_events_clone, wg_clone.clone()),
            move || Session::process_pid_exec_requests(pid_exec_requests_clone, wg_clone.clone()),
        ] {
            let wg_clone = wg.clone();
            let thread = thread::spawn(move || {
                f();
                wg_clone.store(false, Ordering::SeqCst);
            });
            threads.push(thread);
        }

        for thread in threads {
            thread.join().unwrap();
        }

        Ok(())
    }

    fn stop(&self) {
        self.stop_and_wait();
    }

    fn update(&mut self, options: SessionOptions) -> Result<(), String> {
        let _guard = self.mutex.lock().unwrap();

        self.sym_cache.update_options(options.clone().cache_options);
        self.options = options;
        Ok(())
    }

    fn update_targets(&mut self, args: TargetsOptions) {
        self.target_finder.update(args);

        let _guard = self.mutex.lock().unwrap();

        for pid in self.pids.unknown.iter() {
            let target = self.target_finder.find_target(*pid);
            if let Some(target) = target {
                self.start_profiling_locked(*pid, target);
                self.pids.unknown.remove(pid);
            }
        }
    }

    fn collect_profiles(&mut self, cb: CollectProfilesCallback) -> Result<(), String> {
        let _guard = self.mutex.lock().unwrap();

        self.sym_cache.next_round();
        self.round_number += 1;

        let cb = cb.deref().clone();
        self.collect_python_profile(cb)?;
        self.collect_regular_profile(cb)?;

        self.cleanup();

        Ok(())
    }

    fn debug_info(&self) -> SessionDebugInfo {
        let _guard = self.mutex.lock().unwrap();

        SessionDebugInfo {
            elf_cache: self.sym_cache.elf_cache_debug_info(),
            pid_cache: self.sym_cache.pid_cache_debug_info(),
        }
    }

    fn collect_regular_profile(&mut self, cb: CollectProfilesCallback) -> Result<(), String> {
        let mut sb = StackBuilder::new();
        let mut known_stacks = HashSet::new();

        let (keys, values, batch) = self.get_counts_map_values()?;

        for (i, ck) in keys.iter().enumerate() {
            let value = values[i];

            if ck.user_stack >= 0 {
                known_stacks.insert(ck.user_stack as u32);
            }
            if ck.kern_stack >= 0 {
                known_stacks.insert(ck.kern_stack as u32);
            }
            if let Some(labels) = self.target_finder.find_target(ck.pid) {
                if !self.pids.dead.contains(&ck.pid) {
                    if let Some(proc) = self.sym_cache.get_proc_table(ck.pid) {
                        if let Some(target) = labels {
                            let (u_stack, k_stack) = self.get_stacks(ck.user_stack, ck.kern_stack);
                            let mut stats = StackResolveStats::default();
                            sb.reset();
                            sb.append(self.comm(ck.pid));
                            if self.options.collect_user {
                                self.walk_stack(&mut sb, &u_stack, &proc, &mut stats);
                            }
                            if self.options.collect_kernel {
                                self.walk_stack(&mut sb, &k_stack, &self.sym_cache.get_kallsyms(), &mut stats);
                            }
                            if sb.stack.len() > 1 {
                                cb(target, sb.stack.clone(), value, ck.pid, true);
                                self.collect_metrics(&target, &stats, &sb);
                            }
                        }
                    } else {
                        self.pids.dead.insert(ck.pid, ck);
                    }
                }
            }
        }

        self.clear_counts_map(keys, batch)?;
        self.clear_stacks_map(known_stacks)?;

        Ok(())
    }


    // Define getCountsMapValues function
    fn get_counts_map_values(&mut self) -> Result<(Vec<ProfileSampleKey>, Vec<u32>, bool), String> {
        // Try batch first
        let m = &self.bpf.profile_maps.counts;
        let map_size = m.max_entries();
        let mut keys: Vec<ProfileSampleKey> = Vec::with_capacity(map_size);
        let mut values: Vec<u32> = Vec::with_capacity(map_size);

        let opts = &ebpf::BatchOptions::default();
        let (n, err) = m.batch_lookup_and_delete(None, keys.as_mut_slice(), values.as_mut_slice(), opts)?;
        if n > 0 {
            // Log debug message
            println!("getCountsMapValues BatchLookupAndDelete count: {}", n);
            return Ok((keys[..n].to_vec(), values[..n].to_vec(), true));
        }
        if let Some(e) = err {
            if e == ebpf::Error::KeyNotExist {
                return Ok((vec![], vec![], true));
            } else {
                return Err(format!("Error: {}", e));
            }
        }

        // Try iterating if batch failed
        let mut result_keys: Vec<ProfileSampleKey> = Vec::new();
        let mut result_values: Vec<u32> = Vec::new();
        let mut it = m.iterate();
        while let Some((k, v)) = it.next() {
            result_keys.push(k);
            result_values.push(v);
        }

        // Log debug message
        println!("getCountsMapValues iter count: {}", keys.len());
        Ok((result_keys, result_values, false))
    }

    // Define clearCountsMap function
    fn clear_counts_map(&mut self, keys: &[ProfileSampleKey], batch: bool) -> Result<(), String> {
        if keys.is_empty() {
            return Ok(());
        }
        if batch {
            // do nothing, already deleted with GetValueAndDeleteBatch in getCountsMapValues
            return Ok(());
        }
        let m = &self.bpf.profile_maps.counts;
        for k in keys {
            m.delete(k)?;
        }

        // Log debug message
        println!("clearCountsMap count: {}", keys.len());
        Ok(())
    }

    // Define clearStacksMap function
    fn clear_stacks_map(&mut self, known_keys: &HashMap<u32, bool>) -> Result<(), String> {
        let m = &self.bpf.stacks;
        let mut cnt = 0;
        let mut errs = 0;

        if self.round_number % 10 == 0 {
            // do a full reset once in a while
            let mut it = m.iterate();
            let mut keys: Vec<u32> = Vec::new();
            while let Some((k, _)) = it.next() {
                keys.push(k);
            }
            for k in keys {
                if let Err(e) = m.delete(&k) {
                    errs += 1;
                } else {
                    cnt += 1;
                }
            }

            // Log debug message
            println!("clearStacksMap deleted all stacks count: {} unsuccessful: {}", cnt, errs);
            return Ok(());
        }

        for stack_id in known_keys.keys() {
            if let Err(e) = m.delete(stack_id) {
                errs += 1;
            } else {
                cnt += 1;
            }
        }
        println!("clearStacksMap deleted known stacks count: {} unsuccessful: {}", cnt, errs);
        Ok(())
    }
}

fn attach_perf_events(sample_rate: i32, prog: &ebpf::Program) -> Result<Vec<PerfEvent>> {
    let cpus = cpuonline::get()?;
    let mut perf_events = Vec::new();

    for cpu in cpus {
        let pe = PerfEvent::new(cpu as usize, sample_rate)?;
        perf_events.push(pe);

        if let Err(err) = pe.attach_perf_event(prog) {
            return Err(err);
        }
    }

    Ok(perf_events)
}

#[derive(Default)]
struct SessionDebugInfo {
    elf_cache: Option<ElfCacheDebugInfo>,
    pid_cache: Option<Vec<GCacheDebugInfo<ProcTableDebugInfo>>>,
}

struct StackBuilder {
    stack: Vec<String>,
}

impl StackBuilder {
    fn new() -> Self {
        StackBuilder {
            stack: Vec::new(),
        }
    }

    fn reset(&mut self) {
        self.stack.clear();
    }

    fn append(&mut self, sym: String) {
        self.stack.push(sym);
    }
}

#[derive(Default)]
struct StackResolveStats {
    known: u32,
    unknown_symbols: u32,
    unknown_modules: u32,
}

impl StackResolveStats {
    fn add(&mut self, other: StackResolveStats) {
        self.known += other.known;
        self.unknown_symbols += other.unknown_symbols;
        self.unknown_modules += other.unknown_modules;
    }
}

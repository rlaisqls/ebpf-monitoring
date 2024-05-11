use std::{
    collections::HashMap,
    fs, mem,
    sync::{Arc, Mutex},
};

use std::collections::HashSet;
use std::default::Default;
use std::ffi::c_void;
use std::io::Read;


use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::path::Path;
use std::sync::mpsc::{channel, Receiver};

use libbpf_rs::libbpf_sys::bpf_map_batch_opts;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{libbpf_sys, Link, MapFlags, Program};
use libbpf_sys::{
    __u32, bpf_map_delete_elem, bpf_map_lookup_batch,
    bpf_map_lookup_elem, size_t,
};
use log::{debug, error, info};


use tokio::io::AsyncReadExt;

use profile::*;

use crate::common::collector::{ProfileSample, SampleType};

use crate::ebpf::metrics::metrics::ProfileMetrics;
use crate::ebpf::ring::perf_event::PerfEvent;
use crate::ebpf::ring::reader::Reader;


use crate::ebpf::sd::target::{EbpfTarget, TargetFinder, TargetsOptions};
use crate::ebpf::session::profile::profile_bss_types::{pid_config, sample_key};
use crate::ebpf::symtab::elf_cache::ElfCacheDebugInfo;
use crate::ebpf::symtab::elf_module::ElfTableOptions;
use crate::ebpf::symtab::gcache::{GCacheDebugInfo, Resource};
use crate::ebpf::symtab::perf_symbol_table::PerfSymbolTable;
use crate::ebpf::symtab::proc::{ProcTable, ProcTableDebugInfo};
use crate::ebpf::symtab::symbols::{CacheOptions, SymbolCache};
use crate::ebpf::symtab::symtab::SymbolTable;
use crate::ebpf::sync::{ProfilingType};
use crate::ebpf::wait_group::WaitGroup;
use crate::error::Error::{InvalidData, OSError};
use crate::error::Result;

mod profile {
    include!("bpf/profile.skel.rs");
}

#[derive(Clone)]
pub struct SessionOptions {
    pub collect_user: bool,
    pub collect_kernel: bool,
    pub unknown_symbol_module_offset: bool,
    pub unknown_symbol_address: bool,
    pub python_enabled: bool,
    pub metrics: Arc<ProfileMetrics>,
    pub sample_rate: u32,
    pub cache_options: CacheOptions,
}

enum SampleAggregation {
    SampleAggregated,
    SampleNotAggregated,
}

pub type DiscoveryTarget = HashMap<String, String>;

#[derive(Debug, Default)]
struct Pids {
    unknown: HashMap<u32, ()>,
    dead: HashMap<u32, ()>,
    pub all: HashMap<u32, ProcInfoLite>,
}

#[derive(Debug)]
struct ProcInfoLite {
    pid: u32,
    comm: String,
    typ: ProfilingType,
}

pub struct SessionDebugInfo {
    elf_cache: ElfCacheDebugInfo,
    pid_cache: GCacheDebugInfo<ProcTableDebugInfo>,
}

impl Default for SessionDebugInfo {
    fn default() -> Self {
        Self {
            elf_cache: ElfCacheDebugInfo::default(),
            pid_cache: GCacheDebugInfo::default(),
        }
    }
}

pub struct Session<'a> {
    pub target_finder: Arc<Mutex<TargetFinder>>,
    pub(crate) sym_cache: Arc<Mutex<SymbolCache>>,
    tmp: Option<Arc<Mutex<PerfSymbolTable>>>,
    pub bpf: ProfileSkel<'a>,

    events_reader: Option<Arc<Mutex<Reader>>>,

    options: SessionOptions,
    pub(crate) round_number: u32,
    started: bool,
    kprobes: Vec<Link>,

    // We have 3 threads
    // 1 - reading perf events from ebpf. this one does not touch Session fields including mutex
    // 2 - processing pid info requests. this one Session fields to update pid info and python info, this should be done under mutex
    // 3 - processing pid dead events
    // Accessing wg should be done with no Session.mutex held to avoid deadlock, therefore wg access (Start, Stop) should be
    // synchronized outside
    wg: WaitGroup,

    fds: Vec<RawFd>,
    pids: Arc<Mutex<Pids>>,
    perf_events: Vec<PerfEvent>,
}

impl Session<'_> {
    pub fn new(target_finder: Arc<Mutex<TargetFinder>>, opts: SessionOptions) -> Result<Self> {
        let sym_cache = Arc::new(Mutex::new(
            SymbolCache::new(opts.cache_options, &opts.metrics.symtab).unwrap(),
        ));
        bump_memlock_rlimit().unwrap();
        let mut builder = ProfileSkelBuilder::default();
        builder.obj_builder.debug(true);
        let open_skel = builder.open().unwrap();
        let bpf = open_skel.load().unwrap();

        Ok(Self {
            started: false,
            bpf,
            tmp: None,
            target_finder,
            sym_cache,
            options: opts,
            events_reader: None,
            wg: Default::default(),
            fds: vec![],
            pids: Default::default(),
            kprobes: vec![],
            perf_events: vec![],
            round_number: 0,
        })
    }

    pub fn start(&mut self) -> Result<()> {
        bump_memlock_rlimit().expect("Failed to increase rlimit");
        self.bpf.attach().unwrap();

        self.perf_events = attach_perf_events(
            self.options.sample_rate,
            self.bpf.progs_mut().do_perf_event(),
        )
        .unwrap();
        self.wg.add(4);

        self.started = true;
        //self.read_events();
        Ok(())
    }

    fn stop_locked(&mut self) {
        self.wg.done();
    }

    fn stop(&mut self) {
        self.stop_locked();
        self.wg.done()
    }

    fn update(&mut self, options: SessionOptions) -> Result<(), String> {
        self.options = options;
        Ok(())
    }

    pub fn update_targets(&mut self, args: &TargetsOptions) {
        let mut targets = Vec::new();
        {
            let mut target_finder = self.target_finder.lock().unwrap();
            target_finder.update(args);

            let pids = self.pids.lock().unwrap();
            for p in pids.unknown.iter() {
                let pp = p.0;
                let pid = pp.clone();
                let target = target_finder.find_target(&pid);
                if let Some(target) = target {
                    targets.push((target.clone(), pid));
                }
            }
        }
        targets.iter_mut().for_each(|(t, p)| {
            self.start_profiling_locked(&p, t);
            let mut pids = self.pids.lock().unwrap();
            pids.unknown.remove(p);
        });
    }

    fn start_profiling_locked(&mut self, pid: &u32, target: &EbpfTarget) {
        if !self.started {
            return;
        }
        let typ = self.select_profiling_type(pid.clone(), target);
        // if typ.typ == ProfilingType::Python {
        //     self.try_start_python_profiling(pid, target, typ)
        // }
        self.set_pid_config(
            pid.clone(),
            typ,
            self.options.collect_user,
            self.options.collect_kernel,
        );
    }

    fn set_pid_config(
        &mut self,
        pid: u32,
        pi: ProcInfoLite,
        collect_user: bool,
        collect_kernel: bool,
    ) {
        info!("hello");
        let config = pid_config {
            profile_type: pi.typ.to_u8().clone(),
            collect_user: collect_user as u8,
            collect_kernel: collect_kernel as u8,
            padding_: 0,
        };
        let mut pids = self.pids.lock().unwrap();
        pids.all.insert(pid, pi);

        if let Err(err) = self.bpf.maps().pids().update(
            &pid.to_ne_bytes(),
            any_as_u8_slice(&config),
            MapFlags::ANY,
        ) {
            error!("updating pids map err: {:?}", err);
        }
    }

    fn select_profiling_type(&self, pid: u32, _target: &EbpfTarget) -> ProcInfoLite {
        if let Ok(exe_path) = fs::read_link(format!("/proc/{}/exe", pid)) {
            if let Ok(comm) = fs::read_to_string(format!("/proc/{}/comm", pid)) {
                let comm = comm.trim_end_matches('\n').to_string();
                let exe = Path::new(&exe_path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();

                info!("exe: {:?}, pid: {}", exe_path, pid);

                return if self.options.python_enabled
                    && (exe.starts_with("python") || exe == "uwsgi")
                {
                    ProcInfoLite {
                        pid,
                        comm,
                        typ: ProfilingType::Python,
                    }
                } else {
                    ProcInfoLite {
                        pid,
                        comm,
                        typ: ProfilingType::FramePointers,
                    }
                };
            }
        }

        error!("Failed to read proc information for pid: {}", pid);
        ProcInfoLite {
            pid,
            comm: String::new(),
            typ: ProfilingType::TypeError,
        }
    }

    pub fn process_pid_info_requests(&mut self, pid: u32) -> Result<()> {
        let already_dead = {
            let pids = self.pids.lock().unwrap();
            pids.dead.contains_key(&pid)
        };
        if already_dead {
            debug!("pid info request for dead pid: {}", pid);
            return Ok(());
        }

        let target = {
            let target_finder = self.target_finder.lock().unwrap();
            target_finder.find_target(&pid)
        };

        if target.is_none() {
            self.save_unknown_pid_locked(&pid);
        } else {
            debug!("pid info request: pid={}, target={:?}", pid, target);
            self.start_profiling_locked(&pid, &target.unwrap());
        }
        Ok(())
    }

    fn save_unknown_pid_locked(&mut self, pid: &u32) {
        let mut pids = self.pids.lock().unwrap();
        pids.unknown.insert(pid.clone(), ());
    }

    pub fn process_dead_pids_events(&mut self, pid: u32) -> Result<()> {
        debug!("pid dead: {}", pid);
        let mut pids = self.pids.lock().unwrap();
        pids.dead.insert(pid, Default::default());
        return Ok(());
    }

    pub fn process_pid_exec_requests(&mut self, pid: u32) -> Result<()> {
        let already_dead = {
            let pids = self.pids.lock().unwrap();
            pids.dead.contains_key(&pid)
        };
        if already_dead {
            debug!("pid info request for dead pid: {}", pid);
            return Ok(());
        }

        let target = {
            let target_finder = self.target_finder.lock().unwrap();
            target_finder.find_target(&pid)
        };

        if target.is_none() {
            self.save_unknown_pid_locked(&pid);
        } else {
            debug!("pid exec request: pid={}, target={:?}", pid, target);
            self.start_profiling_locked(&pid, &target.unwrap());
        }
        Ok(())
    }

    fn get_counts_map_values(&mut self) -> Result<(Vec<sample_key>, Vec<u32>, bool)> {
        let maps = &self.bpf.maps();
        let m = maps.counts();

        let map_size = m.info().unwrap().info.max_entries as usize;

        unsafe {
            let mut result_keys: Vec<sample_key> = Vec::with_capacity(map_size);
            let mut result_values: Vec<u32> = Vec::with_capacity(map_size);

            while let Some(bytes) = m.keys().next() {
                let key = byte_to_value::<sample_key>(&bytes).unwrap();
                let mut value: u32 = 0;
                bpf_map_lookup_elem(
                    m.as_fd().as_raw_fd(),
                    key as *const _ as *const c_void,
                    &mut value as *mut _ as *mut c_void,
                );
                bpf_map_delete_elem(
                    m.as_fd().as_raw_fd(),
                    key as *const _ as *const c_void
                );
                result_keys.push(key.clone());
                result_values.push(value.clone());
            }
            println!("getCountsMapValues iter count: {}", result_keys.len());
            Ok((result_keys, result_values, true))
        }
    }

    fn clear_counts_map(&mut self, keys: &[sample_key], batch: bool) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        if batch {
            // do nothing, already deleted with GetValueAndDeleteBatch in getCountsMapValues
            return Ok(());
        }
        let maps = &self.bpf.maps();
        let m = maps.counts();

        // m.delete(keys)?;
        let ret = unsafe {
            libbpf_sys::bpf_map_delete_elem(m.as_fd().as_raw_fd(), keys.as_ptr() as *const c_void)
        };
        if ret < 0 {
            // Error code is returned negative, flip to positive to match errno
            Err(OSError((-ret).to_string()))
        } else {
            println!("clearCountsMap count: {}", keys.len());
            Ok(())
        }
    }

    fn clear_stacks_map(&mut self, known_keys: &HashMap<u32, bool>) -> Result<()> {
        let maps = &self.bpf.maps();
        let m = maps.stacks();
        let mut cnt = 0;
        let mut errs = 0;

        if self.round_number % 10 == 0 {
            // do a full reset once in a while
            while let Some(k) = m.keys().next() {
                if let Err(_e) = m.delete(k.as_slice()) {
                    errs += 1;
                } else {
                    cnt += 1;
                }
            }
            println!(
                "clearStacksMap deleted all stacks count: {} unsuccessful: {}",
                cnt, errs
            );
            return Ok(());
        }

        for stack_id in known_keys.keys() {
            if let Err(_e) = m.delete(&stack_id.to_le_bytes()) {
                errs += 1;
            } else {
                cnt += 1;
            }
        }
        println!(
            "clearStacksMap deleted known stacks count: {} unsuccessful: {}",
            cnt, errs
        );
        Ok(())
    }

    pub fn debug_info(&mut self) -> Option<SessionDebugInfo> {
        if let Ok(sym_cache) = self.sym_cache.lock() {
            return Some(SessionDebugInfo {
                elf_cache: sym_cache.elf_cache_debug_info(),
                pid_cache: sym_cache.pid_cache_debug_info(),
            });
        }
        None
    }

    pub(crate) fn collect_regular_profile<F>(&mut self, cb: F) -> Result<()>
    where
        F: Fn(ProfileSample),
    {
        dbg!("collect_regular_profile");

        let mut sb = StackBuilder::new();
        let mut known_stacks: HashMap<u32, bool> = HashMap::new();
        let (keys, values, batch) = self.get_counts_map_values().unwrap();
        for (i, ck) in keys.iter().enumerate() {
            let value = values[i];
            if ck.user_stack >= 0 {
                known_stacks.insert(ck.user_stack as u32, true);
            }
            if ck.kern_stack >= 0 {
                known_stacks.insert(ck.kern_stack as u32, true);
            }
            let target_finder = self.target_finder.lock().unwrap();
            if let Some(labels) = target_finder.find_target(&ck.pid) {
                let (mut stats, proc) = {
                    let mut pids = self.pids.lock().unwrap();
                    if pids.dead.contains_key(&ck.pid) {
                        debug!("pid {} is dead", &ck.pid);
                        continue;
                    }
                    let stats = StackResolveStats::default();
                    let proc = {
                        // if self.tmp.is_none() {
                        //     self.tmp = Some(Arc::new(Mutex::new(PerfSymbolTable::new(ck.pid as i32))));
                        // }
                        // self.tmp.clone().unwrap()
                        let mut sym_cache = self.sym_cache.lock().unwrap();
                        if sym_cache.get_proc_table(ck.pid).is_none() {
                            pids.dead.insert(ck.pid, ());
                        }
                        sym_cache.get_proc_table(ck.pid).unwrap().clone()
                    };
                    (stats, proc)
                };
                {
                    let mut a = proc.lock().unwrap();
                    a.refresh_resource();
                }
                let u_stack = self.get_stack(ck.user_stack);
                let k_stack = self.get_stack(ck.kern_stack);
                sb.reset();
                sb.append(self.comm(ck.pid));

                if self.options.collect_user && u_stack.is_some() {
                    self.walk_stack(&mut sb, &u_stack.unwrap(), proc, &mut stats);
                }
                if self.options.collect_kernel && k_stack.is_some() {
                    let a = {
                        let mut sym_cache = self.sym_cache.lock().unwrap();
                        sym_cache.get_kallsyms().clone()
                    };
                    self.walk_stack(&mut sb, &k_stack.unwrap(), a, &mut stats);
                }
                if sb.stack.len() > 1 {
                    sb.stack.reverse();
                    cb(ProfileSample {
                        target: &labels,
                        pid: ck.pid,
                        sample_type: SampleType::Cpu,
                        aggregation: false,
                        stack: sb.stack.clone(),
                        value: value as u64,
                        value2: 0,
                    });
                    self.collect_metrics(&labels, &stats, &sb);
                }
            }
        }
        self.clear_counts_map(&keys, batch).unwrap();
        self.clear_stacks_map(&known_stacks).unwrap();
        Ok(())
    }

    fn comm(&self, pid: u32) -> String {
        let pids = self.pids.lock().unwrap();
        if let Some(proc_info) = pids.all.get(&pid) {
            if !proc_info.comm.is_empty() {
                return proc_info.comm.clone();
            }
        }
        "pid_unknown".to_string()
    }

    fn walk_stack(
        &self,
        sb: &mut StackBuilder,
        stack: &[u8],
        resolver: Arc<Mutex<dyn SymbolTable>>,
        stats: &mut StackResolveStats,
    ) {
        if stack.is_empty() {
            info!("stack is empty");
            return;
        }
        let mut stack_frames = Vec::new();
        for i in 0..127 {
            let start = i * 8;
            let end = start + 8;
            if end > stack.len() {
                break;
            }
            let instruction_pointer_bytes = &stack[i * 8..(i + 1) * 8];
            let instruction_pointer = u64::from_le_bytes(instruction_pointer_bytes.try_into().unwrap());
            if instruction_pointer == 0 {
                break;
            }

            let mut r = resolver.lock().unwrap();
            let name = if let Some(sym) = r.resolve(instruction_pointer) {
                if !sym.name.is_empty() {
                    stats.known += 1;
                    sym.name.clone()
                } else {
                    if !sym.module.is_empty() {
                        if self.options.unknown_symbol_module_offset {
                            format!("{}+{:x}", sym.module, sym.start)
                        } else {
                            sym.module.clone()
                        }
                    } else {
                        if self.options.unknown_symbol_address {
                            format!("{:x}", instruction_pointer)
                        } else {
                            "[unknown]".to_string()
                        }
                    }
                }
            } else {
                "[unknown]".to_string()
            };
            stack_frames.push(name);
        }
        stack_frames.reverse();
        for s in stack_frames {
            sb.append(s);
        }
    }

    fn get_stack(&self, stack_id: i64) -> Option<Vec<u8>> {
        if stack_id < 0 {
            return None;
        }
        let stack_id_u32 = stack_id as u32;
        self.bpf
            .maps()
            .stacks()
            .lookup(stack_id_u32.to_le_bytes().as_slice(), MapFlags::ANY)
            .unwrap_or_else(|_| None)
    }

    fn collect_metrics(&self, labels: &EbpfTarget, stats: &StackResolveStats, sb: &StackBuilder) {
        let m = &self.options.metrics.symtab;
        let service_name = labels.service_name();
        m.known_symbols
            .with_label_values(&[&service_name])
            .inc_by(stats.known as f64);
        m.unknown_symbols
            .with_label_values(&[&service_name])
            .inc_by(stats.unknown_symbols as f64);
        m.unknown_modules
            .with_label_values(&[&service_name])
            .inc_by(stats.unknown_modules as f64);

        if sb.stack.len() > 2 && stats.unknown_symbols + stats.unknown_modules > stats.known {
            m.unknown_stacks.with_label_values(&[&service_name]).inc();
        }
    }

    pub(crate) fn cleanup(&mut self) {
        let mut sym_cache = self.sym_cache.lock().unwrap();
        sym_cache.cleanup();

        let mut pids = self.pids.lock().unwrap();
        let mut dead_pids_to_remove = HashSet::new();
        for pid in pids.dead.keys() {
            dead_pids_to_remove.insert(*pid);
        }

        for pid in &dead_pids_to_remove {
            pids.dead.remove(pid);
            pids.unknown.remove(pid);
            pids.all.remove(pid);
            sym_cache.remove_dead_pid(pid);
            let _ = self.bpf.maps().pids().delete(&pid.to_le_bytes());

            if let Ok(mut target_finder) = self.target_finder.lock() {
                target_finder.remove_dead_pid(pid);
            }
        }

        let mut unknown_pids_to_remove = HashSet::new();
        let u = pids.unknown.clone();
        let keys = u.keys();
        for pid in keys {
            let proc_path = format!("/proc/{}", pid);
            if let Err(err) = fs::metadata(&proc_path) {
                if !matches!(err.kind(), std::io::ErrorKind::NotFound) {
                    error!("cleanup stat pid: {} err: {}", pid, err);
                }
                unknown_pids_to_remove.insert(pid.clone());
                pids.all.remove(pid);
                self.bpf.maps().pids().delete(&pid.to_le_bytes()).unwrap_or(());
            }
        }

        for pid in &unknown_pids_to_remove {
            pids.unknown.remove(pid);
        }

        if self.round_number % 10 == 0 {
            self.check_stale_pids();
        }
    }

    fn check_stale_pids(&self) {
        let m = &self.bpf.maps();
        let pids = m.pids();
        let map_size = pids.info().unwrap().info.max_entries as usize;
        let nkey = 0u32;
        let mut keys: Vec<u32> = Vec::with_capacity(map_size);
        let mut values: Vec<pid_config> = Vec::with_capacity(map_size);
        let mut count: u32 = 10;
        unsafe {
            let n = bpf_map_lookup_batch(
                pids.as_fd().as_raw_fd(),
                std::ptr::null_mut(),
                nkey as *mut _,
                keys.as_mut_ptr() as *mut c_void,
                values.as_mut_ptr() as *mut c_void,
                (&mut count) as *mut u32,
                &bpf_map_batch_opts {
                    sz: mem::size_of::<bpf_map_batch_opts>() as size_t,
                    elem_flags: MapFlags::ANY.bits(),
                    flags: MapFlags::ANY.bits(),
                } as *const bpf_map_batch_opts,
            );

            dbg!("check stale pids count: {}", n);
            for i in 0..n {
                if let Err(err) =
                    fs::metadata(format!("/proc/{}/status", keys[i as usize] as __u32))
                {
                    if err.kind() == std::io::ErrorKind::NotFound {
                        if let Err(_del_err) = pids.delete(&keys[i as usize].to_le_bytes()) {
                            error!("delete stale pid pid");
                        } else {
                            dbg!("stale pid deleted pid");
                        }
                    } else {
                        error!("check stale pids err: {}", err);
                    }
                } else {
                    dbg!("stale pid check : alive");
                }
            }
        }
    }
}

fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe { return core::slice::from_raw_parts((p as *const T) as *const u8, mem::size_of::<T>()) }
}

// https://github.com/libbpf/libbpf-rs/blob/ed31040a86388b699524bdfa25893fb2e85a9eb2/examples/runqslower/src/main.rs#L41
fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        return Err(InvalidData("Failed to increase rlimit".to_string()));
    }
    Ok(())
}

// https://github.com/torvalds/linux/blob/928a87efa42302a23bb9554be081a28058495f22/samples/bpf/trace_event_user.c#L152
fn attach_perf_events(sample_rate: u32, prog: &mut Program) -> Result<Vec<PerfEvent>> {
    let nprocs = libbpf_rs::num_possible_cpus().unwrap();
    Ok((0..nprocs)
        .map(|cpu| PerfEvent::new(cpu as i32, sample_rate as u64, prog).unwrap())
        .collect())
}

struct StackBuilder {
    stack: Vec<String>,
}

impl StackBuilder {
    fn new() -> Self {
        StackBuilder { stack: Vec::new() }
    }

    fn reset(&mut self) {
        self.stack.clear();
    }

    fn append(&mut self, sym: String) {
        self.stack.push(sym);
    }
}

#[derive(Default, Debug)]
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

fn byte_to_value<V>(bytes: &Vec<u8>) -> Option<&V> {
    if bytes.len() != mem::size_of::<V>() {
        return None;
    }
    let ptr = bytes.as_ptr() as *const V;
    let value_ref: &V;
    unsafe {
        value_ref = &*ptr;
    }
    return Some(value_ref);
}


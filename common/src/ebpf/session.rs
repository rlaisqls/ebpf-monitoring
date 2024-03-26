use std::{collections::HashMap, default, os, sync::{Arc, Mutex}, thread};
use std::collections::HashSet;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender, Receiver, channel};
use anyhow::bail;
use byteorder::ReadBytesExt;
use gimli::LittleEndian;
use gimli::Vendor::Default;
use libbpf_rs::libbpf_sys::BPF_MAP_LOOKUP_AND_DELETE_BATCH;
use libbpf_rs::Link;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use log::{debug, error};
use nix::unistd;
use crate::ebpf::cpuonline;

use crate::error::Result;
use crate::ebpf::metrics::metrics::Metrics;
use crate::ebpf::sd::target::{Target, TargetFinder};
use crate::ebpf::symtab::elf_cache::ElfCacheDebugInfo;
use crate::ebpf::symtab::gcache::GCacheDebugInfo;
use crate::ebpf::symtab::proc::ProcTableDebugInfo;
use crate::ebpf::symtab::symbols::{CacheOptions, PidKey, SymbolCache};
use crate::error::Error::InvalidData;

mod profile {
    include!("../profile.skel.rs");
}
use profile::*;
use crate::ebpf::perf_event::PerfEvent;
use crate::ebpf::sync::PidOp;
use crate::ebpf::sync::PidOp::Dead;

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

struct Session<'a> {
    target_finder: Arc<TargetFinder>,
    sym_cache: Arc<Mutex<SymbolCache>>,
    bpf: ProfileSkel<'a>,
    events_reader: Receiver<u32>,
    pid_info_requests: Receiver<u32>,
    dead_pid_events: Receiver<u32>,
    options: SessionOptions,
    round_number: u32,
    mutex: Mutex<()>, // Add your own mutex type here
    started: bool,
    kprobes: Vec<Link>,

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

        let mut skel_builder = ProfileSkelBuilder::default();
        bump_memlock_rlimit()?;
        let mut open_skel = skel_builder.open()?;

        Ok(Self {
            target_finder,
            sym_cache: Arc::new(Mutex::new(sym_cache)),
            bpf: open_skel,
            events_reader: PerfReader::default(),
            ..Default::default()
        })
    }

    fn start(&mut self) -> Result<()> {

        let _guard = self.mutex.lock()?;
        bump_memlock_rlimit().expect(&*"Failed to increase rlimit");

        let mut skel = self.bpf.load()?;
        skel.attach()?;
        let events_reader = perf::Reader::new(&self.bpf.maps_mut().events(), 4 * std::os::page_size)?;
        self.perf_events = attach_perf_events(self.options.sample_rate, self.bpf.links.do_perf_event)?;

        if let Err(err) = self.link_kprobes() {
            self.stop_locked();
            return Err(err.into());
        }

        self.events_reader = Some(events_reader);

        let (pid_info_request_tx, pid_info_request_rx) = channel::<u32>();
        let (pid_exec_request_tx, pid_exec_request_rx) = channel::<u32>();
        let (dead_pid_events_tx, dead_pid_events_rx) = channel::<u32>();
        self.pid_info_requests = pid_info_request_rx;
        self.pid_exec_requests = pid_exec_request_rx;
        self.dead_pid_events = dead_pid_events_rx;

        self.started = true;
        let mut threads = Vec::with_capacity(4);

        for f in vec![
            move || Session::read_events(events_reader, pid_info_request_tx, pid_exec_request_tx, dead_pid_events_tx),
            move || Session::process_pid_info_requests(),
            move || Session::process_dead_pids_events(),
            move || Session::process_pid_exec_requests(),
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

    fn stop_locked(&mut self) {
        drop(self.pid_info_requests.take());
        drop(self.dead_pid_events.take());
        drop(self.pid_exec_requests.take());
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

    fn read_events(
        &self,
        events: perf::Reader,
        pid_config_request: Sender<u32>,
        pid_exec_request: Sender<u32>,
        dead_pids_events: Sender<u32>,
    ) {
        for record in events {
            match record {
                Ok(record) => {
                    if record.lost_samples != 0 {
                        error!(
                            "perf event ring buffer full, dropped samples: {}",
                            record.lost_samples
                        );
                    }

                    if let Some(raw_sample) = record.raw_sample {
                        if raw_sample.len() < 8 {
                            error!("perf event record too small: {}", raw_sample.len());
                            continue;
                        }
                        let mut cursor = Cursor::new(raw_sample);
                        let op = cursor.read_u32::<LittleEndian>().unwrap();
                        let pid = cursor.read_u32::<LittleEndian>().unwrap();

                        if op == PidOp::RequestExecProcessInfo as u32 {
                            match pid_config_request.send(pid) {
                                Ok(_) => {}
                                Err(_) => {
                                    error!("pid info request queue full, dropping request: {}", pid);
                                    // Implement fallback at reset time if needed
                                }
                            }
                        } else if op == PidOp::Dead as u32 {
                            match dead_pids_events.send(pid) {
                                Ok(_) => {}
                                Err(_) => {
                                    error!("dead pid info queue full, dropping event: {}", pid);
                                }
                            }
                        } else if op == PidOp::RequestExecProcessInfo as u32 {
                            match pid_exec_request.send(pid) {
                                Ok(_) => {}
                                Err(_) => {
                                    error!("pid exec request queue full, dropping event: {}", pid);
                                }
                            }
                        } else {
                            error!("unknown perf event record: op={}, pid={}", op, pid);
                        }
                    }
                }
                Err(err) => {
                    error!("reading from perf event reader: {}", err);
                }
            }
        }
    }

    fn process_pid_info_requests(&self) {
        for pid in self.pid_info_requests {
            let target = self.target_finder.find_target(pid);
            debug!("pid info request: pid={}, target={:?}", pid, target);

            let mut lock = self.mutex.lock().unwrap();
            let already_dead = lock.pids.dead.contains(&pid);
            if already_dead {
                debug!("pid info request for dead pid: {}", pid);
                continue;
            }

            if target.is_none() {
                self.save_unknown_pid_locked(pid);
            } else {
                self.start_profiling_locked(pid, target.unwrap());
            }
        }
    }
    
    fn process_dead_pids_events(&mut self) {
        for pid in self.dead_pid_events {
            debug!(self.logger, "pid dead"; "pid" => pid);
            {
                let mut data = self.mutex.lock().unwrap();
                self.pids.dead.insert(pid, Default::default());
            }
        }
    }

    fn process_pid_exec_requests(&self, requests: Receiver<u32>) {
        for pid in requests {
            let target = self.target_finder.find_target(pid);
            debug!(self.logger, "pid exec request"; "pid" => pid);
            {
                let mut data = self.mutex.lock().unwrap();
                if data.pids_dead.contains(&pid) {
                    debug!(self.logger, "pid exec request for dead pid"; "pid" => pid);
                    continue;
                }
                if target.is_none() {
                    self.save_unknown_pid_locked(pid, &mut data);
                } else {
                    self.start_profiling_locked(pid, target.unwrap(), &mut data);
                }
            }
        }
    }

    fn link_kprobes(&mut self) -> Result<(), String> {
        let arch_sys = if cfg!(target_arch = "x86_64") {
            "__x64_"
        } else {
            "__arm64_"
        };
        let hooks = [
            ("disassociate_ctty", &self.bpf.progs().disassociate_ctty(), true),
            (arch_sys, &self.bpf.progs().exec(), false),
            (arch_sys, &self.bpf.progs().execveat(), false),
        ];
        for (kprobe, mut prog, required) in &hooks {
            match prog.attach_kprobe(false, prog.name()) {
                Ok(kp) => self.kprobes.push(kp),
                Err(err) => {
                    if *required {
                        return Err(format!("link kprobe {}: {}", kprobe, err));
                    }
                    error!(self.logger, "link kprobe"; "kprobe" => kprobe, "err" => err);
                }
            }
        }
        Ok(())
    }

    fn get_counts_map_values(&mut self) -> Result<(Vec<ProfileSampleKey>, Vec<u32>, bool), String> {
        // Try batch first
        let m = &self.bpf.maps().counts();
        m.update_batch()

        BPF_MAP_LOOKUP_AND_DELETE_BATCH
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

    fn clear_counts_map(&mut self, keys: &[ProfileSampleKey], batch: bool) -> Result<(), String> {
        if keys.is_empty() {
            return Ok(());
        }
        if batch {
            // do nothing, already deleted with GetValueAndDeleteBatch in getCountsMapValues
            return Ok(());
        }
        let m = &self.bpf.maps().counts();
        for k in keys {
            m.delete(k)?;
        }

        // Log debug message
        println!("clearCountsMap count: {}", keys.len());
        Ok(())
    }

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

fn attach_perf_events(sample_rate: i32, prog: &ebpf::Program) -> Result<Vec<PerfEvent>> {
    let cpus = cpuonline::get()?;
    let mut perf_events = Vec::new();

    for cpu in cpus {
        let pe = PerfEvent::new(cpu as usize as i32, sample_rate)?;
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

#[test]
fn ring_buf_epoll_wakeup() {
    let RingBufTest {
        mut ring_buf,
        _bpf,
        regs: _,
    } = RingBufTest::new();

    let epoll_fd = epoll::create(false).unwrap();
    epoll::ctl(
        epoll_fd,
        epoll::ControlOptions::EPOLL_CTL_ADD,
        ring_buf.as_raw_fd(),
        // The use of EPOLLET is intentional. Without it, level-triggering would result in
        // more notifications, and would mask the underlying bug this test reproduced when
        // the synchronization logic in the RingBuf mirrored that of libbpf. Also, tokio's
        // AsyncFd always uses this flag (as demonstrated in the subsequent test).
        epoll::Event::new(epoll::Events::EPOLLIN | epoll::Events::EPOLLET, 0),
    )
        .unwrap();
    let mut epoll_event_buf = [epoll::Event::new(epoll::Events::EPOLLIN, 0); 1];
    let mut total_events: u64 = 0;
    let writer = WriterThread::spawn();
    while total_events < WriterThread::NUM_MESSAGES {
        epoll::wait(epoll_fd, -1, &mut epoll_event_buf).unwrap();
        while let Some(read) = ring_buf.next() {
            assert_eq!(read.len(), 8);
            total_events += 1;
        }
    }
    writer.join();
}
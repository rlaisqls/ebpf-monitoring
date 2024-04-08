use std::{collections::HashMap, fs, sync::{Arc, Mutex}, thread};
use std::any::Any;
use std::borrow::Borrow;
use std::collections::HashSet;
use std::default::Default;
use std::ffi::c_void;
use std::io::{Cursor, Read};
use std::ops::Deref;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

use byteorder::ReadBytesExt;
use gimli::LittleEndian;
use libbpf_rs::{Error, libbpf_sys, Link, Map, MapFlags, MapHandle};
use libbpf_rs::libbpf_sys::{bpf_map_batch_opts, bpf_map_lookup_and_delete_batch};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_sys::{__u32, bpf_map_lookup_batch};
use log::{debug, error, info};
use prometheus::opts;

use profile::*;
use crate::common::collector::{CollectProfilesCallback, ProfileSample, SamplesCollector, SampleType};

use crate::ebpf::cpuonline;
use crate::ebpf::metrics::metrics::Metrics;
use crate::ebpf::metrics::symtab::SymtabMetrics;
use crate::ebpf::perf_event::PerfEvent;
use crate::ebpf::reader::Reader;
use crate::ebpf::sd::target::{Target, TargetFinder, TargetsOptions};
use crate::ebpf::session::profile::profile_bss_types::{pid_config, pid_event, sample_key};
use crate::ebpf::symtab::elf_cache::ElfCacheDebugInfo;
use crate::ebpf::symtab::gcache::GCacheDebugInfo;
use crate::ebpf::symtab::proc::ProcTableDebugInfo;
use crate::ebpf::symtab::symbols::{CacheOptions, SymbolCache};
use crate::ebpf::symtab::symtab::SymbolTable;
use crate::ebpf::sync::{PidOp, ProfilingType};
use crate::ebpf::sync::PidOp::Dead;
use crate::ebpf::wait_group::WaitGroup;
use crate::error::Error::{InvalidData, NotFound, OSError, SessionError};
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
    pub metrics: Arc<Metrics>,
    pub sample_rate: u32,
    pub cache_options: CacheOptions,
}

enum SampleAggregation {
    SampleAggregated,
    SampleNotAggregated,
}

pub type DiscoveryTarget = HashMap<String, String>;

#[derive(Default)]
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
    pid_cache: GCacheDebugInfo<ProcTableDebugInfo>
}

pub struct Session<'a> {
    pub target_finder: Arc<TargetFinder>,
    sym_cache: Arc<SymbolCache<'a>>,
    bpf: ProfileSkel<'a>,

    events_reader: Option<Reader>,
    pid_info_requests: Option<Receiver<u32>>,
    dead_pid_events: Option<Receiver<u32>>,
    pid_exec_requests: Option<Receiver<u32>>,

    options: SessionOptions,
    round_number: u32,
    mutex: Mutex<()>,
    started: bool,
    kprobes: Vec<Link>,

    // We have 3 threads
    // 1 - reading perf events from ebpf. this one does not touch Session fields including mutex
    // 2 - processing pid info requests. this one Session fields to update pid info and python info, this should be done under mutex
    // 3 - processing pid dead events
    // Accessing wg should be done with no Session.mutex held to avoid deadlock, therefore wg access (Start, Stop) should be
    // synchronized outside
    wg: WaitGroup,

    pids: Pids,
    perf_events: Vec<PerfEvent>
}

impl SamplesCollector for Session<'_> {

    fn collect_profiles(&mut self, callback: CollectProfilesCallback) -> Result<()> {
        let _guard = self.mutex.lock().unwrap();
        self.sym_cache.next_round();
        self.round_number += 1;

        self.collect_regular_profile(callback).unwrap();
        self.cleanup();

        Ok(())
    }
}

impl Session<'_> {
    pub fn new(target_finder: Arc<TargetFinder>, opts: SessionOptions) -> Result<Self> {
        let sym_cache = SymbolCache::new(opts.cache_options, &opts.metrics.symtab).unwrap();
        bump_memlock_rlimit().unwrap();
        let mut open_skel = ProfileSkelBuilder::default().open().unwrap();
        let bpf = open_skel.load().unwrap();
        
        Ok(Self {
            started: false,
            bpf,
            target_finder,
            sym_cache: Arc::new(sym_cache),
            options: opts,
            events_reader: None,
            pid_info_requests: None,
            dead_pid_events: None,
            pid_exec_requests: None,
            mutex: Mutex::new(()),
            wg: Default::default(),
            pids: Default::default(),
            kprobes: vec![],
            perf_events: vec![],
            round_number: 0,
        })
    }

    fn start(&mut self) -> Result<()> {

        let _guard = self.mutex.lock().unwrap();
        bump_memlock_rlimit().expect(&*"Failed to increase rlimit");

        self.bpf.attach().unwrap();
        self.bpf.maps().events();
        let events_reader = Reader::new(
            MapHandle::try_clone(self.bpf.maps().events()).unwrap(), 4 * page_size::get()
        ).unwrap();
        self.perf_events = attach_perf_events(
            self.options.sample_rate,
            &self.bpf.links.do_perf_event.take().unwrap()
        ).unwrap();

        if let Err(err) = self.link_kprobes() {
            self.stop_locked();
            return Err(SessionError(err));
        }
        self.events_reader = Some(events_reader);

        let (pid_info_request_tx, pid_info_request_rx) = channel::<u32>();
        let (pid_exec_request_tx, pid_exec_request_rx) = channel::<u32>();
        let (dead_pid_events_tx, dead_pid_events_rx) = channel::<u32>();

        self.pid_info_requests = Some(pid_info_request_rx);
        self.pid_exec_requests = Some(pid_exec_request_rx);
        self.dead_pid_events = Some(dead_pid_events_rx);
        self.wg.add(4);

        self.started = true;
        thread::spawn(move || {
            self.read_events(pid_info_request_tx, pid_exec_request_tx, dead_pid_events_tx)
        });
        thread::spawn(move || {
            self.process_pid_info_requests()
        });
        thread::spawn(move || {
            self.process_dead_pids_events()
        });
        thread::spawn(move || {
            self.process_pid_exec_requests()
        });
        Ok(())
    }

    fn stop_locked(&mut self) {
        drop(self.pid_info_requests.take());
        drop(self.dead_pid_events.take());
        drop(self.pid_exec_requests.take());

        self.wg.done();
    }

    fn stop(&mut self) {
        self.stop_locked();
        self.wg.done()
    }

    fn update(&mut self, options: SessionOptions) -> Result<(), String> {
        let _guard = self.mutex.lock().unwrap();
        self.options = options;
        Ok(())
    }

    pub fn update_targets(&mut self, args: TargetsOptions) {
        self.target_finder.update(args);
        let _guard = self.mutex.lock().unwrap();
        for pid in self.pids.unknown.iter() {
            let target = self.target_finder.find_target(pid.0);
            if let Some(target) = target {
                self.start_profiling_locked(pid.0, target);
                self.pids.unknown.remove(pid.0);
            }
        }
    }

    fn start_profiling_locked(&mut self, pid: &u32, target: Target) {
        if !self.started {
            return;
        }
        let typ = self.select_profiling_type(pid.clone(), &target);
        // if typ.typ == ProfilingType::Python {
        //     self.try_start_python_profiling(pid, target, typ)
        // }
        self.set_pid_config(pid.clone(), typ, self.options.collect_user, self.options.collect_kernel);
    }

    fn set_pid_config(&mut self, pid: u32, pi: ProcInfoLite, collect_user: bool, collect_kernel: bool) {
        self.pids.all.insert(pid, pi);
        let config = pid_config {
            profile_type: pi.typ.to_u8(),
            collect_user: collect_user as u8,
            collect_kernel: collect_kernel as u8,
            padding_: 0,
        };

        if let Err(err) = self.bpf.maps().pids()
            .update(&pid.to_ne_bytes(), any_as_u8_slice(&config), MapFlags::ANY)
        {
            let _ = error!("updating pids map err: {:?}", err);
        }
    }

    fn select_profiling_type(&self, pid: u32, target: &Target) -> ProcInfoLite {
        if let Ok(exe_path) = fs::read_link(format!("/proc/{}/exe", pid)) {
            if let Ok(comm) = fs::read_to_string(format!("/proc/{}/comm", pid)) {
                let comm = comm.trim_end_matches('\n').to_string();
                let exe = Path::new(&exe_path).file_name().unwrap_or_default().to_string_lossy();

                info!("exe: {:?}, pid: {}", exe_path, pid);

                return if self.options.python_enabled && (exe.starts_with("python") || exe == "uwsgi") {
                    ProcInfoLite { pid, comm, typ: ProfilingType::Python }
                } else {
                    ProcInfoLite { pid, comm, typ: ProfilingType::FramePointers }
                }
            }
        }

        // Logging error
        eprintln!("Failed to read proc information for pid: {}", pid);

        ProcInfoLite { pid, comm: String::new(), typ: ProfilingType::TypeError }
    }

    fn read_events(
        &mut self,
        pid_config_request: Sender<u32>,
        pid_exec_request: Sender<u32>,
        dead_pids_events: Sender<u32>,
    ) {
        loop {
            match self.events_reader.take().unwrap().read() {
                Ok(record) => {
                    if record.lost_samples != 0 {
                        error!(
                            "perf event ring buffer full, dropped samples: {}",
                            record.lost_samples
                        );
                    }

                    if !record.raw_sample.is_empty() {
                        if record.raw_sample.len() < 8 {
                            error!("perf event record too small: {}", record.raw_sample.len());
                            continue;
                        }

                        let mut e = pid_event {
                            op: u32::from_le_bytes([record.raw_sample[0], record.raw_sample[1], record.raw_sample[2], record.raw_sample[3]]),
                            pid: u32::from_le_bytes([record.raw_sample[4], record.raw_sample[5], record.raw_sample[6], record.raw_sample[7]])
                        };
                        if e.op == PidOp::RequestExecProcessInfo as u32 {
                            match pid_config_request.send(e.pid) {
                                Ok(_) => {}
                                Err(_) => {
                                    error!("pid info request queue full, dropping request: {}", e.pid);
                                }
                            }
                        } else if e.op == Dead as u32 {
                            match dead_pids_events.send(e.pid) {
                                Ok(_) => {}
                                Err(_) => {
                                    error!("dead pid info queue full, dropping event: {}", e.pid);
                                }
                            }
                        } else if e.op == PidOp::RequestExecProcessInfo as u32 {
                            match pid_exec_request.send(e.pid) {
                                Ok(_) => {}
                                Err(_) => {
                                    error!("pid exec request queue full, dropping event: {}", e.pid);
                                }
                            }
                        } else {
                            error!("unknown perf event record: op={}, pid={}", e.op, e.pid);
                        }
                    }
                }
                Err(err) => {
                    error!("reading from perf event reader: {}", err);
                }
            }
        }
    }

    fn process_pid_info_requests(&mut self) {
        for pid in self.pid_info_requests.take().unwrap() {
            let target = self.target_finder.find_target(&pid);
            debug!("pid info request: pid={}, target={:?}", pid, target);

            let already_dead = self.pids.dead.contains_key(&pid);
            if already_dead {
                debug!("pid info request for dead pid: {}", pid);
                continue;
            }

            if target.is_none() {
                self.save_unknown_pid_locked(&pid);
            } else {
                self.start_profiling_locked(&pid, target.unwrap());
            }
        }
    }

    fn save_unknown_pid_locked(&mut self, pid: &u32) {
        self.pids.unknown.insert(pid.clone(), ());
    }
    
    fn process_dead_pids_events(&mut self) {
        for pid in self.dead_pid_events.take().unwrap() {
            debug!("pid dead: {}", pid);
            {
                self.pids.dead.insert(pid, Default::default());
            }
        }
    }

    fn process_pid_exec_requests(&mut self) {
        for pid in self.dead_pid_events.take().unwrap() {
            let target = self.target_finder.find_target(&pid);
            info!("pid exec request: {}", pid);
            {
                let _ = self.mutex.lock().unwrap();
                if self.pids.dead.contains_key(&pid) {
                    info!("pid exec request for dead pid: {}", pid);
                    continue;
                }
                if target.is_none() {
                    self.save_unknown_pid_locked(&pid);
                } else {
                    self.start_profiling_locked(&pid, target.unwrap());
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
            (format!("{}{}", arch_sys, "sys_execve").as_str(), &self.bpf.progs().exec(), false),
            (format!("{}{}", arch_sys, "sys_execveat").as_str(), &self.bpf.progs().exec(), false),
        ];
        for (kprobe, mut prog, required) in &hooks {
            match prog.attach_kprobe(false, prog.name()) {
                Ok(kp) => self.kprobes.push(kp),
                Err(err) => {
                    if *required {
                        return Err(format!("link kprobe {}: {}", kprobe, err));
                    }
                    error!("link kprobe kprobe: {}, err: {}", kprobe, err);
                }
            }
        }
        Ok(())
    }

    fn get_counts_map_values(&mut self) -> Result<(Vec<sample_key>, Vec<u32>, bool)> {
        let m = &self.bpf.maps().counts();
        let map_size  = m.info().unwrap().info.max_entries as usize;
        let mut keys: Vec<sample_key> = Vec::with_capacity(map_size);
        let mut values: Vec<u32> = Vec::with_capacity(map_size);
        let mut count: u32 = 10;
        let mut nkey = 0u32;
        unsafe {
            let n = bpf_map_lookup_and_delete_batch(
                m.as_fd().as_raw_fd(),
                std::ptr::null_mut(),
                nkey as *mut _,
                keys.as_mut_ptr() as *mut c_void,
                values.as_mut_ptr() as *mut c_void,
                (&mut count) as *mut u32,
                &bpf_map_batch_opts {
                    sz: 0,
                    elem_flags: 0,
                    flags: 0,
                } as *const bpf_map_batch_opts,
            );

            if n > 0 {
                let size = n as usize;
                println!("getCountsMapValues BatchLookupAndDelete count: {}", n);
                return Ok((keys[..size].to_vec(), values[..size].to_vec(), true));
            }
            Err(NotFound("".to_string()))
            //
            // let mut result_keys: Vec<sample_key> = Vec::with_capacity(map_size);
            // let mut result_values: Vec<u32> = Vec::with_capacity(map_size);
            // let mut it = m.iterate();
            // while let Some((&k, &v)) = it.next() {
            //     result_keys.push(k);
            //     result_values.push(v);
            // }
            // println!("getCountsMapValues iter count: {}", keys.len());
            // Ok((result_keys, result_values, false))
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
        let m = &self.bpf.maps().counts();

        // m.delete(keys)?;
        let ret = unsafe {
            libbpf_sys::bpf_map_delete_elem(
                m.as_fd().as_raw_fd(),
                keys.as_ptr() as *const c_void
            )
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
        let m = &self.bpf.maps().stacks();
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
                if let Err(_e) = m.delete(&k.to_le_bytes()) {
                    errs += 1;
                } else {
                    cnt += 1;
                }
            }
            println!("clearStacksMap deleted all stacks count: {} unsuccessful: {}", cnt, errs);
            return Ok(());
        }

        for stack_id in known_keys.keys() {
            if let Err(_e) = m.delete(&stack_id.to_le_bytes()) {
                errs += 1;
            } else {
                cnt += 1;
            }
        }
        println!("clearStacksMap deleted known stacks count: {} unsuccessful: {}", cnt, errs);
        Ok(())
    }

    pub fn debug_info(&self) -> SessionDebugInfo {
        SessionDebugInfo {
            elf_cache: self.sym_cache.elf_cache_debug_info(),
            pid_cache: self.sym_cache.pid_cache_debug_info()
        }
    }

    fn collect_regular_profile(&mut self, cb: CollectProfilesCallback) -> Result<()> {
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
            if let Some(labels) = self.target_finder.find_target(&ck.pid) {
                if self.pids.dead.contains_key(&ck.pid) {
                    continue;
                }
                if let Some(mut proc) = self.sym_cache.get_proc_table(ck.pid) {
                    let u_stack = self.get_stack(ck.user_stack).unwrap();
                    let k_stack = self.get_stack(ck.kern_stack).unwrap();
                    let mut stats = StackResolveStats::default();
                    sb.reset();
                    sb.append(self.comm(ck.pid));
                    if self.options.collect_user {
                        self.walk_stack(&mut sb, &u_stack, proc, &mut stats);
                    }
                    if self.options.collect_kernel {
                        let mut a = self.sym_cache.get_kallsyms();
                        self.walk_stack(&mut sb, &k_stack, a, &mut stats);
                    }
                    if sb.stack.len() > 1 {
                        cb(ProfileSample{
                            target: &labels,
                            pid: ck.pid,
                            sample_type: SampleType::Cpu,
                            aggregation: true,
                            stack: sb.stack.clone(),
                            value: value as u64,
                            value2: 0,
                        });
                        self.collect_metrics(&labels, &stats, &sb);
                    }
                } else {
                    self.pids.dead.insert(ck.pid, ());
                }
            }
        }
        self.clear_counts_map(&keys, batch).unwrap();
        Ok(self.clear_stacks_map(&known_stacks).unwrap())
    }

    fn comm(&self, pid: u32) -> String {
        if let Some(proc_info) = self.pids.all.get(&pid) {
            if !proc_info.comm.is_empty() {
                return proc_info.comm.clone();
            }
        }
        "pid_unknown".to_string()
    }

    fn walk_stack(&self, sb: &mut StackBuilder, stack: &[u8], mut resolver: Arc<dyn SymbolTable>, stats: &mut StackResolveStats) {
        if stack.is_empty() {
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
            let sym = resolver.resolve(instruction_pointer).unwrap();
            let name = if !sym.name.is_empty() {
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
        self.bpf.maps().stacks()
            .lookup(stack_id_u32.to_le_bytes().as_slice(), MapFlags::ANY)
            .unwrap_or_else(|_| None)
    }

    fn collect_metrics(&self, labels: &Target, stats: &StackResolveStats, sb: &StackBuilder) {
        let m = &self.options.metrics.symtab;
        let service_name = labels.service_name();

        m.known_symbols.with_label_values(&[&service_name]).inc_by(stats.known as f64);
        m.unknown_symbols.with_label_values(&[&service_name]).inc_by(stats.unknown_symbols as f64);
        m.unknown_modules.with_label_values(&[&service_name]).inc_by(stats.unknown_modules as f64);

        if sb.stack.len() > 2 && stats.unknown_symbols + stats.unknown_modules > stats.known {
            m.unknown_stacks.with_label_values(&[&service_name]).inc();
        }
    }

    fn cleanup(&mut self) {
        self.sym_cache.cleanup();

        let mut dead_pids_to_remove = HashSet::new();
        for pid in self.pids.dead.keys() {
            dbg!("cleanup dead pid: {}", pid.to_string());
            dead_pids_to_remove.insert(*pid);
        }

        for pid in &dead_pids_to_remove {
            self.pids.dead.remove(pid);
            self.pids.unknown.remove(pid);
            self.pids.all.remove(pid);
            self.sym_cache.remove_dead_pid(pid);
            self.bpf.maps().pids().delete(&pid.to_le_bytes()).unwrap();
            self.target_finder.remove_dead_pid(pid);
        }

        let mut unknown_pids_to_remove = HashSet::new();
        for pid in self.pids.unknown.keys() {
            let proc_path = format!("/proc/{}", pid);
            if let Err(err) = fs::metadata(&proc_path) {
                if !matches!(err.kind(), std::io::ErrorKind::NotFound) {
                    error!("cleanup stat pid: {} err: {}", pid, err);
                }
                unknown_pids_to_remove.insert(pid.clone());
                self.pids.all.remove(pid).unwrap();
                self.bpf.maps().pids().delete(&pid.to_le_bytes()).unwrap()
            }
        }

        for pid in &unknown_pids_to_remove {
            self.pids.unknown.remove(pid);
        }

        if self.round_number % 10 == 0 {
            self.check_stale_pids();
        }
    }

    fn check_stale_pids(&self) {
        let m = &self.bpf.maps().pids();
        let map_size = m.info().unwrap().info.max_entries as usize;
        let mut nkey = 0u32;
        let mut keys: Vec<u32> = Vec::with_capacity(map_size);
        let mut values: Vec<pid_config> = Vec::with_capacity(map_size);
        let mut count: u32 = 10;
        unsafe {
            let n = bpf_map_lookup_batch(
                m.as_fd().as_raw_fd(),
                std::ptr::null_mut(),
                nkey as *mut _,
                keys.as_mut_ptr() as *mut c_void,
                values.as_mut_ptr() as *mut c_void,
                (&mut count) as *mut u32,
                &bpf_map_batch_opts {
                    sz: 0,
                    elem_flags: 0,
                    flags: 0,
                } as *const bpf_map_batch_opts,
            );

            dbg!("check stale pids count: {}", n);
            for i in 0..n {
                if let Err(err) = fs::metadata(format!("/proc/{}/status", keys[i as usize] as __u32)) {
                    if err.kind() == std::io::ErrorKind::NotFound {
                        if let Err(_del_err) = m.delete(&keys[i as usize].to_le_bytes()) {
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
    unsafe {
        return core::slice::from_raw_parts(
            (p as *const T) as *const u8,
            core::mem::size_of::<T>(),
        )
    }
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
fn attach_perf_events(sample_rate: u32, link: &Link) -> Result<Vec<PerfEvent>> {
    let cpus = cpuonline::get()?;
    let mut perf_events = Vec::new();
    for cpu in cpus {
        let mut pe = PerfEvent::new(cpu as i32, sample_rate as u64)?;
        perf_events.push(pe);

        if let Err(err) = pe.attach_perf_event(link) {
            return Err(InvalidData(format!("{:?}", err)));
        }
    }
    Ok(perf_events)
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
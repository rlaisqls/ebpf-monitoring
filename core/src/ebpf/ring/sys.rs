use std::{
	ffi::{c_int, c_long, CString, OsStr}
	, mem,
	os::fd::{BorrowedFd, FromRawFd as _, OwnedFd},
};
use std::os::fd::{AsRawFd, RawFd};

use libbpf_sys::{bpf_attr, bpf_cmd, BPF_MAP_UPDATE_ELEM, PERF_COUNT_SW_BPF_OUTPUT, PERF_COUNT_SW_CPU_CLOCK, perf_event_attr, PERF_FLAG_FD_CLOEXEC, PERF_SAMPLE_RAW, PERF_TYPE_SOFTWARE, PERF_TYPE_TRACEPOINT};
use libc::{pid_t};
use crate::ebpf::ring::{Syscall, syscall};

use crate::error::Error::InvalidData;
use crate::error::Result;

pub fn bpf_map_update_elem<K, V>(
	fd: BorrowedFd<'_>,
	key: Option<&K>,
	value: &V,
	flags: u64,
) -> Result<c_long> {
	let mut a = unsafe { mem::zeroed::<bpf_attr>() };

	let u = unsafe { &mut a.__bindgen_anon_2 };
	u.map_fd = fd.as_raw_fd() as u32;
	if let Some(key) = key {
		u.key = key as *const _ as u64;
	}
	u.__bindgen_anon_1.value = value as *const _ as u64;
	u.flags = flags;

	let mut attr = &mut a;
	let call = Syscall::Ebpf { cmd: BPF_MAP_UPDATE_ELEM, attr };
	syscall(call)
}

pub fn perf_event_open(
	perf_type: u32,
	config: u64,
	pid: pid_t,
	cpu: c_int,
	sample_period: u64,
	sample_frequency: Option<u64>,
	wakeup: bool,
	inherit: bool,
	flags: u32,
) -> Result<RawFd> {
	let mut attr = unsafe { mem::zeroed::<perf_event_attr>() };

	attr.config = config;
	attr.size = mem::size_of::<perf_event_attr>() as u32;
	attr.type_ = perf_type;
	attr.sample_type = PERF_SAMPLE_RAW as u64;
	attr.set_inherit(if inherit { 1 } else { 0 });
	attr.__bindgen_anon_2.wakeup_events = u32::from(wakeup);

	if let Some(frequency) = sample_frequency {
		attr.set_freq(1);
		attr.__bindgen_anon_1.sample_freq = frequency;
	} else {
		attr.__bindgen_anon_1.sample_period = sample_period;
	}

	perf_event_sys(attr, pid, cpu, flags)
}

pub fn perf_event_open_bpf(cpu: c_int) -> Result<RawFd> {
	perf_event_open(
		PERF_TYPE_SOFTWARE as u32,
		PERF_COUNT_SW_BPF_OUTPUT as u64,
		-1,
		cpu,
		1,
		None,
		true,
		false,
		PERF_FLAG_FD_CLOEXEC,
	)
}


pub fn perf_event_ioctl(
	fd: RawFd,
	request: c_int,
	arg: c_int,
) -> Result<c_long> {
	let call = Syscall::PerfEventIoctl { fd, request, arg };
	syscall(call)
}

fn perf_event_sys(attr: perf_event_attr, pid: pid_t, cpu: i32, flags: u32) -> Result<RawFd> {
	let fd = syscall(Syscall::PerfEventOpen {
		attr,
		pid,
		cpu,
		group: -1,
		flags,
	}).unwrap();
	if fd < 0 {
		return Err(InvalidData(format!("perf_event_open: invalid fd returned: {fd}")))
	}
	// SAFETY: perf_event_open returns a new file descriptor on success.
	Ok(fd.try_into().unwrap())
}

/*
impl TryFrom<u32> for perf_event_type {
    PERF_RECORD_MMAP = 1,
    PERF_RECORD_LOST = 2,
    PERF_RECORD_COMM = 3,
    PERF_RECORD_EXIT = 4,
    PERF_RECORD_THROTTLE = 5,
    PERF_RECORD_UNTHROTTLE = 6,
    PERF_RECORD_FORK = 7,
    PERF_RECORD_READ = 8,
    PERF_RECORD_SAMPLE = 9,
    PERF_RECORD_MMAP2 = 10,
    PERF_RECORD_AUX = 11,
    PERF_RECORD_ITRACE_START = 12,
    PERF_RECORD_LOST_SAMPLES = 13,
    PERF_RECORD_SWITCH = 14,
    PERF_RECORD_SWITCH_CPU_WIDE = 15,
    PERF_RECORD_NAMESPACES = 16,
    PERF_RECORD_KSYMBOL = 17,
    PERF_RECORD_BPF_EVENT = 18,
    PERF_RECORD_CGROUP = 19,
    PERF_RECORD_MAX

    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        todo!()
    }
}
*/
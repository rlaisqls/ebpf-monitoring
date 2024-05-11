pub mod reader;
pub mod sys;
pub mod perf_buffer;
pub mod perf_event;

use crate::error::Result;
use std::{
	ffi::{c_int, c_long, c_void},
	io, mem,
	os::fd::{AsRawFd as _, BorrowedFd},
};
use std::os::fd::RawFd;
use libbpf_sys::{bpf_attr, bpf_cmd, perf_event_attr};
use libc::{pid_t, SYS_bpf, SYS_perf_event_open};


use crate::error::Error::PerfBufferError;

pub(crate) enum Syscall<'a> {
	Ebpf {
		cmd: bpf_cmd,
		attr: &'a mut bpf_attr,
	},
	PerfEventOpen {
		attr: perf_event_attr,
		pid: pid_t,
		cpu: i32,
		group: i32,
		flags: u32,
	},
	PerfEventIoctl {
		fd: RawFd,
		request: c_int,
		arg: c_int,
	},
}

impl std::fmt::Debug for Syscall<'_> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Ebpf { cmd, attr: _ } => f
				.debug_struct("Syscall::Ebpf")
				.field("cmd", cmd)
				.field("attr", &format_args!("_"))
				.finish(),
			Self::PerfEventOpen {
				attr: _,
				pid,
				cpu,
				group,
				flags,
			} => f
				.debug_struct("Syscall::PerfEventOpen")
				.field("attr", &format_args!("_"))
				.field("pid", pid)
				.field("cpu", cpu)
				.field("group", group)
				.field("flags", flags)
				.finish(),
			Self::PerfEventIoctl { fd, request, arg } => f
				.debug_struct("Syscall::PerfEventIoctl")
				.field("fd", fd)
				.field("request", request)
				.field("arg", arg)
				.finish(),
		}
	}
}

fn syscall(call: Syscall<'_>) -> Result<c_long> {
	match unsafe {
		match call {
			Syscall::Ebpf { cmd, attr } => {
				libc::syscall(SYS_bpf, cmd, attr, mem::size_of::<bpf_attr>())
			}
			Syscall::PerfEventOpen {
				attr,
				pid,
				cpu,
				group,
				flags,
			} => libc::syscall(SYS_perf_event_open, &attr, pid, cpu, group, flags),
			Syscall::PerfEventIoctl { fd, request, arg } => {
				let int = libc::ioctl(fd.as_raw_fd(), request.try_into().unwrap(), arg);
				#[allow(trivial_numeric_casts)]
					let int = int as c_long;
				int
			}
		}
	} {
		ret @ 0.. => Ok(ret),
		_ret => Err(PerfBufferError(io::Error::last_os_error().to_string())),
	}
}

#[cfg_attr(test, allow(unused_variables))]
pub(crate) unsafe fn mmap(
	addr: *mut c_void,
	len: usize,
	prot: c_int,
	flags: c_int,
	fd: BorrowedFd<'_>,
	offset: libc::off_t,
) -> *mut c_void {
	return libc::mmap(addr, len, prot, flags, fd.as_raw_fd(), offset);
}
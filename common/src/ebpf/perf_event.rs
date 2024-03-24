use std::io;
use std::os::raw::c_ulong;
use std::os::unix::io::RawFd;

use perf_event::hooks::sys::bindings::{__u64, PERF_COUNT_SW_CPU_CLOCK, perf_event_attr, PERF_FLAG_FD_CLOEXEC, PERF_TYPE_SOFTWARE};
use perf_event::hooks::sys::perf_event_open;
use crate::ebpf::link::{Program, RawLink, RawLinkOptions};

use crate::error::Result;

pub struct PerfEvent {
    fd: RawFd,
    link: Option<RawLink>,
}

impl PerfEvent {
    pub fn new(cpu: i32) -> Result<Self> {
        let attr = perf_event_attr {
            type_: PERF_TYPE_SOFTWARE,
            config: PERF_COUNT_SW_CPU_CLOCK as __u64,
            ..Default::default()
        };
        let perf_event = PerfEvent::try_new(&attr, cpu)?;
        Ok(perf_event)
    }

    fn try_new(attr: &perf_event_attr, cpu: i32) -> Result<Self> {
        let perf_event = PerfEvent::open(attr, cpu)?;
        Ok(PerfEvent {
            fd: perf_event,
            link: None,
        })
    }

    fn open(attr: &perf_event_attr, cpu: i32) -> Result<RawFd> {
        PerfEvent::open_with_flags(attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC)
    }

    fn open_with_flags(attr: &perf_event_attr, pid: i32, cpu: i32, group_fd: i32, flags: u32) -> Result<RawFd> {
        PerfEvent::try_open(attr, pid, cpu, group_fd, flags)
    }

    fn try_open(attr: &perf_event_attr, pid: i32, cpu: i32, group_fd: i32, flags: u32) -> Result<RawFd> {
        let perf_event = PerfEvent::_open(attr, pid, cpu, group_fd, flags)?;
        Ok(perf_event)
    }

    fn _open(attr: &perf_event_attr, pid: i32, cpu: i32, group_fd: i32, flags: u32) -> Result<RawFd> {
        unsafe {
            let fd = perf_event_open(&mut attr.clone(), pid, cpu, group_fd, flags as c_ulong);
            if fd < 0 {
                return Err(io::Error::last_os_error().into());
            }
            Ok(fd)
        }
    }

    pub fn attach_bpf(&mut self, prog: &Program) -> Result<()> {
        self.attach_bpf_link(prog)
    }

    fn attach_bpf_link(&mut self, prog: &Program) -> Result<()> {
        sys.BPF_PROG_TYPE_PERF_EVENT
        let opts = RawLinkOptions {
            target_fd: self.fd,
            program: prog,
            attach_type: AttachType::PerfEvent,

        };
        self.link = Some(attach_raw_link(opts)?);
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        unsafe {
            libc::close(self.fd);
        }
        if let Some(link) = self.link.take() {
            link.close()?;
        }
        Ok(())
    }
}

impl Drop for PerfEvent {
    fn drop(&mut self) {
        if let Err(e) = self.close() {
            eprintln!("Error closing perf event: {:?}", e);
        }
    }
}
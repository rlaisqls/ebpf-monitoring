use std::io;
use std::os::raw::c_ulong;
use std::os::unix::io::RawFd;

use libbpf_rs::{Link, Program};
use perf_event::hooks::sys::bindings::{__u64, PERF_COUNT_SW_CPU_CLOCK, perf_event_attr, PERF_FLAG_FD_CLOEXEC, PERF_TYPE_SOFTWARE};
use perf_event::hooks::sys::perf_event_open;

use crate::ebpf::{PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_SET_BPF};
use crate::error::Error::InvalidData;
use crate::error::Result;

#[derive(Clone)]
pub struct PerfEvent {
    fd: RawFd,
    link: Option<Link>,
    ioctl: bool
}

impl PerfEvent {
    pub fn new(cpu: i32, sample_rate: i32) -> Result<Self> {
        let attr = perf_event_attr {
            type_: PERF_TYPE_SOFTWARE,
            config: PERF_COUNT_SW_CPU_CLOCK as __u64,
            ..Default::default()
        };
        unsafe {
            let fd = perf_event_open(&mut attr.clone(), -1, cpu, -1, PERF_FLAG_FD_CLOEXEC as c_ulong);
            if fd < 0 {
                return Err(InvalidData("".to_string()));
            }
            Ok(PerfEvent {
                fd,
                link: None,
                ioctl: false,
            })
        }
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

    pub(crate) fn attach_perf_event(&mut self, prog: &mut Program) -> Result<(), io::Error> {
        match prog.attach_perf_event(self.fd) {
            Ok(_) => Ok(()),
            Err(_) => self.attach_perf_event_ioctl(prog),
        }
    }

    fn attach_perf_event_ioctl(&mut self, prog: &Program) -> Result<(), io::Error> {
        let err = unsafe { libc::ioctl(self.fd, PERF_EVENT_IOC_SET_BPF as c_ulong, prog.fd()) };
        if err == -1 {
            return Err(io::Error::last_os_error());
        }
        let err = unsafe { libc::ioctl(self.fd, PERF_EVENT_IOC_ENABLE as c_ulong, 0) };
        if err == -1 {
            return Err(io::Error::last_os_error());
        }
        self.ioctl = true;
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
use std::{io, mem};

use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::io::RawFd;

use aya::programs::perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK;
use libbpf_rs::{Link};
use libbpf_rs::libbpf_sys::{PERF_FLAG_FD_CLOEXEC, PERF_SAMPLE_CPU, PERF_TYPE_SOFTWARE};
use libbpf_rs::ProgramType::Syscall;
use libbpf_sys::{perf_event_attr, PERF_SAMPLE_RAW};
use libc::{c_int, c_ulong, group, pid_t, SYS_perf_event_open, syscall};
use log::info;

use crate::ebpf::{PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_SET_BPF};
use crate::error::Error::OSError;
use crate::error::Result;

pub struct PerfEvent {
    fd: RawFd,
    link: Option<Link>,
    ioctl: bool
}

impl PerfEvent {
    pub fn new(cpu: i32, sample_rate: u64) -> Result<Self> {
        // let attr = perf_event_attr {
        //     kind: PERF_TYPE_SOFTWARE,
        //     sample_type: PERF_SAMPLE_CPU as u64,
        //     config: PERF_COUNT_SW_CPU_CLOCK as u64,
        //     sample_period_or_freq: sample_rate,
        //     ..Default::default()
        // };

        unsafe {
            let fd = perf_event_open(
                PERF_TYPE_SOFTWARE,
                PERF_COUNT_SW_CPU_CLOCK as u64,
                -1,
                cpu,
                sample_rate,
                None,
                false,
                false,
                0
            ).unwrap().as_raw_fd();
            // let fd = sys_perf_event_open(&attr, -1 as pid_t, cpu as _, -1, PERF_FLAG_FD_CLOEXEC as c_ulong)?;
            Ok(PerfEvent { fd, link: None, ioctl: false })
        }
    }

    fn close(&mut self) -> Result<()> {
        unsafe {
            libc::close(self.fd);
        }
        if let Some(link) = self.link.take() {
            // link.close()
            link.detach().unwrap();
        }
        Ok(())
    }

    pub(crate) fn attach_perf_event(&mut self, link: &Link) -> Result<()> {
        self.attach_perf_event_ioctl(link)
    }

    fn attach_perf_event_ioctl(&mut self, link: &Link) -> Result<()> {
        let err = unsafe { libc::ioctl(self.fd, PERF_EVENT_IOC_SET_BPF as c_ulong, link.as_fd()) };
        if err == -1 {
            return Err(OSError("fail to call PERF_EVENT_IOC_SET_BPF".to_string()));
        }
        let err = unsafe { libc::ioctl(self.fd, PERF_EVENT_IOC_ENABLE as c_ulong, 0) };
        if err == -1 {
            return Err(OSError("fail to call PERF_EVENT_IOC_ENABLE".to_string()));
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

pub(crate) fn perf_event_open(
    perf_type: u32,
    config: u64,
    pid: pid_t,
    cpu: c_int,
    sample_period: u64,
    sample_frequency: Option<u64>,
    wakeup: bool,
    inherit: bool,
    flags: u32,
) -> Result<OwnedFd> {
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

fn perf_event_sys(attr: perf_event_attr, pid: pid_t, cpu: i32, flags: u32) -> Result<OwnedFd> {
    unsafe {
        let fd = syscall(SYS_perf_event_open, &attr, pid, cpu, -1, flags) as c_int;

        if fd < 0 {
            let err = io::Error::from_raw_os_error(-fd).raw_os_error();
            if err.unwrap_or_default() == libc::EINVAL {
                info!("Your profiling frequency might be too high; try lowering it");
            }
            return Err(OSError(err.expect("").to_string()));
        }
        Ok(OwnedFd::from_raw_fd(fd as i32))
    }
}
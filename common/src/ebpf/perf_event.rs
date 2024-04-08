use std::{io};
use std::collections::HashMap;
use std::os::fd::AsFd;
use std::os::unix::io::RawFd;
use std::time::Duration;

use anyhow::bail;
use aya::programs::perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK;
use libbpf_rs::{Link};
use libbpf_rs::libbpf_sys::{PERF_FLAG_FD_CLOEXEC, PERF_SAMPLE_CPU, PERF_TYPE_SOFTWARE};
use libc::{c_int, c_ulong, pid_t, SYS_perf_event_open, syscall};
use log::info;
use url::Url;

use crate::ebpf::{PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_SET_BPF};
use crate::error::Error::OSError;
use crate::error::Result;

pub struct PerfEvent {
    fd: RawFd,
    link: Option<Link>,
    ioctl: bool
}

#[repr(C)]
pub struct PerfEventAttr {
    pub kind: u32,
    pub size: u32,
    pub config: u64,
    pub sample_period_or_freq: u64,
    pub sample_type: u64,
    pub read_format: u64,
    pub bits: u64,
    pub wakeup: u32,
    pub flags: u64,
    pub wakeup_events_or_watermark: u32,
    pub bp_type: u32,
    pub bp_addr_or_config: u64,
    pub bp_len_or_config: u64,
    pub branch_sample_type: u64,
    pub sample_regs_user: u64,
    pub sample_stack_user: u32,
    pub clock_id: i32,
}

impl Default for PerfEventAttr {
    fn default() -> Self {
        Self {
            kind: 0,
            size: 0,
            config: 0,
            sample_period_or_freq: 0,
            sample_type: 0,
            read_format: 0,
            bits: 0,
            wakeup: 0,
            flags: 0,
            wakeup_events_or_watermark: 0,
            bp_type: 0,
            bp_addr_or_config: 0,
            bp_len_or_config: 0,
            branch_sample_type: 0,
            sample_regs_user: 0,
            sample_stack_user: 0,
            clock_id: 0,
        }
    }
}

impl PerfEvent {
    pub fn new(cpu: i32, sample_rate: u64) -> Result<Self> {
        let attr = PerfEventAttr {
            kind: PERF_TYPE_SOFTWARE,
            sample_type: PERF_SAMPLE_CPU as u64,
            config: PERF_COUNT_SW_CPU_CLOCK as u64,
            sample_period_or_freq: sample_rate,
            ..Default::default()
        };

        unsafe {
            let fd = sys_perf_event_open(&attr, -1 as pid_t, cpu as _, -1, PERF_FLAG_FD_CLOEXEC as c_ulong)?;
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
            return Err(OSError("".to_string()));
        }
        let err = unsafe { libc::ioctl(self.fd, PERF_EVENT_IOC_ENABLE as c_ulong, 0) };
        if err == -1 {
            return Err(OSError("".to_string()));
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

pub unsafe fn sys_perf_event_open(
    attr: &PerfEventAttr,
    pid: pid_t,
    cpu: c_int,
    group_fd: c_int,
    flags: c_ulong,
) -> Result<c_int> {
    unsafe {
        let fd = syscall(
            SYS_perf_event_open,
            attr as *const _,
            pid,
            cpu,
            group_fd,
            flags,
        ) as c_int;
        if fd < 0 {
            let err = io::Error::from_raw_os_error(-fd).raw_os_error();
            if err.unwrap_or_default() == libc::EINVAL {
                info!("Your profiling frequency might be too high; try lowering it");
            }
            return Err(OSError(err.expect("").to_string()));
        }
        Ok(fd)
    }
}
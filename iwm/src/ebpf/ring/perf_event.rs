


use std::os::unix::io::RawFd;


use libbpf_rs::{Link, Program};
use libbpf_rs::libbpf_sys::{PERF_TYPE_SOFTWARE};

use libbpf_sys::{PERF_COUNT_SW_CPU_CLOCK};




use crate::ebpf::ring::sys::perf_event_open;

use crate::error::Result;

#[derive(Debug)]
pub struct PerfEvent {
	pub fd: RawFd,
	link: Option<Link>,
	ioctl: bool
}

impl PerfEvent {
	pub fn new(cpu: i32, sample_rate: u64, prog: &mut Program) -> Result<Self> {
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
		).unwrap();
		let link = prog.attach_perf_event(fd).unwrap();
		// https://ebpf-docs.dylanreimerink.nl/linux/program-type/BPF_PROG_TYPE_PERF_EVENT/#ioctl-method
		// let err = unsafe { libc::ioctl(fd, PERF_EVENT_IOC_SET_BPF as c_ulong, prog.as_fd().as_raw_fd()) };
		// if err == -1 {
		// 	return Err(OSError("fail to call PERF_EVENT_IOC_SET_BPF".to_string()));
		// }
		// let err = unsafe { libc::ioctl(fd, PERF_EVENT_IOC_ENABLE as c_ulong, 0) };
		// if err == -1 {
		// 	return Err(OSError("fail to call PERF_EVENT_IOC_ENABLE".to_string()));
		// }
		Ok(PerfEvent { fd, link: Some(link), ioctl: false })
	}

	fn close(&mut self) -> Result<()> {
		unsafe {
			libc::close(self.fd);
		}
		if let Some(link) = self.link.take() {
			link.detach().unwrap();
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
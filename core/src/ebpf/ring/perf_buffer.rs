use std::{
	ffi::c_void,
	io, mem,
	os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd},
	ptr, slice,
	sync::atomic::{self, AtomicPtr, Ordering},
};
use std::borrow::BorrowMut;
use std::fs::File;
use std::os::fd::FromRawFd;
use aya::maps::MapData;
use aya::maps::perf::PerfEventArrayBuffer;

use bytes::BytesMut;
use libbpf_sys::{__u64, perf_event_header, perf_event_mmap_page, PERF_RECORD_LOST, PERF_RECORD_SAMPLE};
use libc::{c_int, MAP_FAILED, MAP_SHARED, mmap, munmap, PROT_READ, PROT_WRITE};
use log::info;
use nix::fcntl::{fcntl, FcntlArg::*, OFlag};

use crate::ebpf::{PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE};
use crate::ebpf::ring::sys::{perf_event_ioctl, perf_event_open_bpf};
use crate::error::Error::{OSError, PerfBufferError};
use crate::error::Result;

/// Return type of `read_events()`.
#[derive(Debug, PartialEq, Eq)]
pub struct Events {
	/// The number of events read.
	pub read: usize,
	/// The number of events lost.
	pub lost: usize,
}

#[derive(Debug)]
pub struct PerfBuffer {
	pub buf: AtomicPtr<perf_event_mmap_page>,
	pub size: usize,
	pub page_size: usize,
	pub fd: RawFd,
	pub cpu: i32,
}

impl PerfBuffer {
	pub fn new(
		cpu_id: i32,
		page_size: usize,
		page_count: usize,
	) -> Result<Self> {
		if !page_count.is_power_of_two() {
			return Err(PerfBufferError(format!("InvalidPageCount {}", page_count)));
		}
		let fd = perf_event_open_bpf(cpu_id).unwrap();
		// set_non_blocking(fd).unwrap();
		let size = page_size * page_count;
		let buf = unsafe {
			mmap(
				ptr::null_mut(),
				size + page_size,
				PROT_READ | PROT_WRITE,
				MAP_SHARED,
				fd,
				0,
			)
		};
		if buf == MAP_FAILED {
			return Err(PerfBufferError(io::Error::last_os_error().to_string()))
		}

		let perf_buf = Self {
			buf: AtomicPtr::new(buf as *mut perf_event_mmap_page),
			fd,
			size,
			page_size,
			cpu: cpu_id
		};
		perf_event_ioctl(perf_buf.fd, PERF_EVENT_IOC_ENABLE, 0).unwrap();
		Ok(perf_buf)
	}

	pub(crate) fn read_events(
		&mut self,
		buffers: &mut [BytesMut],
	) -> Result<Events> {
		if buffers.is_empty() {
			return Err(PerfBufferError("NoBuffers".to_string()));
		}
		let header = self.buf.load(Ordering::SeqCst);
		let base = header as usize + self.page_size;

		let mut events = Events { read: 0, lost: 0 };
		let mut buf_n = 0;

		let fill_buf = |start_off, base, mmap_size, out_buf: &mut [u8]| {
			let len = out_buf.len();

			let end = (start_off + len) % mmap_size;
			let start = start_off % mmap_size;

			if start < end {
				out_buf.copy_from_slice(unsafe {
					slice::from_raw_parts((base + start) as *const u8, len)
				});
			} else {
				let size = mmap_size - start;
				unsafe {
					out_buf[..size]
						.copy_from_slice(slice::from_raw_parts((base + start) as *const u8, size));
					out_buf[size..]
						.copy_from_slice(slice::from_raw_parts(base as *const u8, len - size));
				}
			}
		};

		let read_event = |event_start, event_type, base, buf: &mut BytesMut| {
			let sample_size = match event_type {
				x if x == PERF_RECORD_SAMPLE as u32 || x == PERF_RECORD_LOST as u32 => {
					let mut size = [0u8; mem::size_of::<u32>()];
					fill_buf(
						event_start + mem::size_of::<perf_event_header>(),
						base,
						self.size,
						&mut size,
					);
					u32::from_ne_bytes(size)
				}
				_ => return Ok(None),
			} as usize;

			let sample_start =
				(event_start + mem::size_of::<perf_event_header>() + mem::size_of::<u32>())
					% self.size;

			match event_type {
				x if x == PERF_RECORD_SAMPLE as u32 => {
					buf.clear();
					buf.reserve(sample_size);
					unsafe { buf.set_len(sample_size) };

					fill_buf(sample_start, base, self.size, buf);

					Ok(Some((1, 0)))
				}
				x if x == PERF_RECORD_LOST as u32 => {
					let mut count = [0u8; mem::size_of::<u64>()];
					fill_buf(
						event_start + mem::size_of::<perf_event_header>() + mem::size_of::<u64>(),
						base,
						self.size,
						&mut count,
					);
					Ok(Some((0, u64::from_ne_bytes(count) as usize)))
				}
				_ => Ok(None),
			}
		};

		let head = unsafe { (*header).data_head } as usize;
		let mut tail = unsafe { (*header).data_tail } as usize;
		while head != tail {
			if buf_n == buffers.len() {
				break;
			}

			let buf = &mut buffers[buf_n];

			let event_start = tail % self.size;
			let event =
				unsafe { ptr::read_unaligned((base + event_start) as *const perf_event_header) };
			let event_size = event.size as usize;

			match read_event(event_start, event.type_, base, buf) {
				Ok(Some((read, lost))) => {
					if read > 0 {
						buf_n += 1;
						events.read += read;
					}
					events.lost += lost;
				}
				Ok(None) => { /* skip unknown event type */ }
				Err(e) => {
					// we got an error and we didn't process any events, propagate the error
					// and give the caller a chance to increase buffers
					atomic::fence(Ordering::SeqCst);
					unsafe { (*header).data_tail = tail as u64 };
					return Err(e);
				}
			}
			tail += event_size;
		}

		atomic::fence(Ordering::SeqCst);
		unsafe { (*header).data_tail = tail as u64 };

		Ok(events)
	}
}

pub fn set_non_blocking(fd: RawFd) -> Result<()> {
	let flags = fcntl(fd, F_GETFL);
	if flags.is_err() {
		return Err(OSError(format!("F_GETFL error errorno: {}", flags.err().unwrap())))
	}
	let mut oflags = OFlag::from_bits_truncate(flags.unwrap());
	oflags |= OFlag::O_NONBLOCK;
	if fcntl(fd, F_SETFL(oflags)).is_err() {
		return Err(OSError(format!("F_SETFL error errorno: {}", flags.err().unwrap())))
	}
	Ok(())
}

fn get_head_and_tail(buf: &AtomicPtr<perf_event_mmap_page>) -> (*mut perf_event_mmap_page, usize, usize) {
	let header = buf.load(Ordering::SeqCst);
	let head = unsafe { (*header).data_head } as usize;
	let tail = unsafe { (*header).data_tail } as usize;
	(header, head, tail)
}

impl AsRawFd for PerfBuffer {
	fn as_raw_fd(&self) -> RawFd {
		self.fd
	}
}

impl AsFd for PerfBuffer {
	fn as_fd(&self) -> BorrowedFd<'_> {
		unsafe { BorrowedFd::borrow_raw(self.fd) }
	}
}

impl Drop for PerfBuffer {
	fn drop(&mut self) {
		unsafe {
			perf_event_ioctl(self.fd, PERF_EVENT_IOC_DISABLE, 0).unwrap();
			munmap(
				self.buf.load(Ordering::SeqCst) as *mut c_void,
				self.size + self.page_size,
			);
		}
	}
}

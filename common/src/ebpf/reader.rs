use std::io::{self, Read};
use std::ops::Deref;
use std::os::unix::io::RawFd;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::slice::from_raw_parts_mut;

use crate::error::Error::{OSError};
use libbpf_rs::libbpf_sys::{PERF_COUNT_SW_BPF_OUTPUT, PERF_FLAG_FD_CLOEXEC, PERF_SAMPLE_RAW, PERF_TYPE_SOFTWARE};
use libbpf_rs::{Map, MapHandle};
use libbpf_sys::perf_event_mmap_page;
use libc::{c_int, c_void, close, MAP_FAILED, MAP_SHARED, mmap, munmap, pid_t, PROT_READ};
use polling::Poller;

use crate::ebpf::perf_event::{PerfEventAttr, sys_perf_event_open};
use crate::error::Error::{Closed, EndOfRing, InvalidData, MustBePaused, UnknownEvent};
use crate::error::Result;

const PERF_RECORD_LOST: u32 = 2;
const PERF_RECORD_SAMPLE: u32 = 1;
const PERF_EVENT_HEADER_SIZE: usize = std::mem::size_of::<PerfEventHeader>();

#[repr(C)]
#[derive(Debug)]
struct PerfEventHeader {
    type_: u32,
    misc: u16,
    size: u16,
}

#[derive(Debug)]
pub struct Record {
    cpu: i32,
    raw_sample: Vec<u8>,
    lost_samples: u64,
    remaining: i32,
}

#[derive(Debug)]
enum PerfError {
    Closed,
    UnknownEvent(u32),
    Io(io::Error),
}

impl From<io::Error> for PerfError {
    fn from(err: io::Error) -> Self {
        PerfError::Io(err)
    }
}

// Reader allows reading bpf_perf_event_output from user space.
pub struct Reader {
    poller: Arc<Poller>,
    deadline: Option<Duration>,

    // mu protects read/write access to the Reader structure with the
    // exception of 'pauseFds', which is protected by 'pauseMu'.
    // If locking both 'mu' and 'pauseMu', 'mu' must be locked first.
    mu: Arc<Mutex<()>>,

    // Closing a PERF_EVENT_ARRAY removes all event fds
    // stored in it, so we keep a reference alive.
    array: MapHandle,
    rings: Vec<PerfEventRing>,
    epoll_events: polling::Events,
    epoll_rings: Vec<PerfEventRing>,
    event_header: Vec<u8>,

    pause_mu: Arc<Mutex<()>>,
    pause_fds: Vec<RawFd>,

    paused: bool,
    overwritable: bool,

    buffer_size: usize,
}

impl Reader {
    pub fn new(array: MapHandle, per_cpu_buffer: usize) -> Result<Self> {
        let n_cpu = 4 * page_size::get();
        let mut rings = Vec::with_capacity(n_cpu);
        let mut pause_fds = Vec::with_capacity(n_cpu);
        let poller = Arc::new(Poller::new().unwrap());

        // bpf_perf_event_output checks which CPU an event is enabled on,
        // but doesn't allow using a wildcard like -1 to specify "all CPUs".
        // Hence, we have to create a ring for each CPU.
        let mut buffer_size = 0;
        for i in 0..n_cpu {
            let ring = PerfEventRing::new(i as i32, per_cpu_buffer as i32, 0).unwrap();
            buffer_size = ring.size();

            let fd = ring.fd;
            rings.push(ring);
            pause_fds.push(fd);
            unsafe {
                poller.add(fd, polling::Event::all(i)).unwrap();
            }
        }

        Ok(Reader {
            poller,
            deadline: Some(Duration::from_secs(10)),
            mu: Arc::new(Mutex::new(())),
            array: array,
            rings,
            epoll_events: polling::Events::new(),
            epoll_rings: Vec::new(),
            event_header: vec![0; PERF_EVENT_HEADER_SIZE],
            pause_mu: Arc::new(Mutex::new(())),
            pause_fds,
            paused: false,
            overwritable: false,
            buffer_size
        })
    }

    pub(crate) fn read(&mut self) -> Result<Record> {
        let mut record = Record {
            cpu: 0,
            raw_sample: Vec::new(),
            lost_samples: 0,
            remaining: 0,
        };
        self.read_into(&mut record).unwrap();
        Ok(record)
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        self.poller.close();
        for ring in self.rings.iter_mut() {
            ring.close();
        }
        self.rings.clear();
        Ok(())
    }

    pub(crate) fn read_into(&mut self, rec: &mut Record) -> Result<()> {
        let _ = self.mu.lock().unwrap();

        if self.overwritable && !self.paused {
            return Err(MustBePaused);
        }

        if self.rings.is_empty() {
            return Err(Closed);
        }

        loop {
            if self.epoll_rings.is_empty() {

                let n_events = self.poller.wait(&mut self.epoll_events, self.deadline);
                let _ = self.pause_mu.lock().unwrap();

                // Re-validate pr.paused since we dropped pauseMu.
                if self.overwritable && !self.paused {
                    return Err(MustBePaused);
                }

                for event in self.epoll_events[..n_events].iter() {
                    let ring = &self.rings[event.cpu_for_event()];
                    self.epoll_rings.push(ring.clone());

                    // Read the current head pointer now, not every time
                    // we read a record. This prevents a single fast producer
                    // from keeping the reader busy.
                    ring.load_head().unwrap();
                }
            }

            // Start at the last available event. The order in which we
            // process them doesn't matter, and starting at the back allows
            // resizing epollRings to keep track of processed rings.
            match self.read_record_from_ring(rec, &mut self.epoll_rings[self.epoll_rings.len() - 1]) {
                Err(EndOfRing) => {
                    // We've emptied the current ring buffer, process
                    // the next one.
                    self.epoll_rings.pop();
                    continue;
                }
                Err(e) => return Err(e.into()),
                Ok(_) => return Ok(()),
            }
        }
    }

    pub(crate) fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    pub(crate) fn read_record_from_ring(&mut self, rec: &mut Record, ring: &mut PerfEventRing) -> Result<()> {
        ring.write_tail();
        rec.cpu = ring.cpu;
        read_record(ring, rec, &mut self.event_header, self.overwritable).unwrap();
        if self.overwritable {
            return Err(EndOfRing);
        }
        rec.remaining = ring.remaining() as i32;
        Ok(())
    }
}

fn read_record(rd: &mut dyn Read, rec: &mut Record, buf: &mut [u8], overwritable: bool) -> Result<()> {
    // Assert that the buffer is large enough.
    let perf_event_header_size = std::mem::size_of::<PerfEventHeader>();
    let buf = &mut buf[..perf_event_header_size];
    if let Err(err) = rd.read_exact(buf) {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            return Err(EndOfRing);
        }
        return Err(InvalidData("ReadRecordError".to_string()));
    }

    let header = PerfEventHeader {
        type_: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        misc: u16::from_le_bytes([buf[4], buf[5]]),
        size: u16::from_le_bytes([buf[6], buf[7]]),
    };

    match header.type_ {
        PERF_RECORD_LOST => {
            rec.raw_sample.clear();
            rec.lost_samples = read_lost_records(rd).unwrap();
        }
        PERF_RECORD_SAMPLE => {
            rec.lost_samples = 0;
            rec.raw_sample = read_raw_sample(rd, overwritable).unwrap();
        }
        _ => return Err(UnknownEvent(header.type_)),
    }
    Ok(())
}

// Read lost records from the reader
fn read_lost_records(rd: &mut dyn Read) -> Result<u64, io::Error> {
    let mut buf = [0; 8]; // Assuming the size of struct perf_event_lost
    rd.read_exact(&mut buf).unwrap();
    Ok(u64::from_le_bytes(buf))
}

// Read raw sample from the reader
fn read_raw_sample(rd: &mut dyn Read, overwritable: bool) -> Result<Vec<u8>, io::Error> {
    let mut buf = vec![0; 4]; // Assuming the size of struct perf_event_sample
    rd.read_exact(&mut buf)?;
    let size = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    let mut data = vec![0; size];
    rd.read_exact(&mut data)?;

    Ok(data)
}

trait RingReader {
    fn load_head(&mut self);
    fn size(&self) -> usize;
    fn remaining(&self) -> usize;
    fn write_tail(&mut self);
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
}

struct PerfEventRing {
    fd: RawFd,
    cpu: i32,
    mmap: *mut u8,
    ring_reader: ForwardReader
}

impl PerfEventRing {
    fn new(cpu: i32, per_cpu_buffer: i32, watermark: i32) -> Result<Self> {
        if watermark >= per_cpu_buffer {
            return Err(InvalidData("watermark must be smaller than per_cpu_buffer".to_string()));
        }

        let fd = create_perf_event(cpu, watermark)?;

        let mmap_size = perf_buffer_size(per_cpu_buffer as usize);
        let protections = PROT_READ;

        let mmap = unsafe {
            mmap(ptr::null_mut(), mmap_size, protections, MAP_SHARED, fd, 0)
        };

        if mmap == MAP_FAILED {
            unsafe { close(fd) };
            return Err(OSError("".to_string()));
        }

        let mut meta = mmap as *mut perf_event_mmap_page;
        let ring = unsafe { from_raw_parts_mut(mmap as *mut u8, perf_buffer_size(per_cpu_buffer as usize)) };
        let ring_reader= ForwardReader::new(unsafe { *meta }, ring.deref());

        Ok(PerfEventRing {
            fd,
            cpu,
            mmap: mmap as *mut u8,
            ring_reader,
        })
    }

    fn close(&mut self) {
        let _ = unsafe { close(self.fd) };
        let _ = unsafe { munmap(self.mmap as *mut c_void, 0) };
        self.fd = -1;
        self.mmap = ptr::null_mut();
    }
}

fn perf_buffer_size(per_cpu_buffer: usize) -> usize {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let n_pages = (per_cpu_buffer + page_size - 1) / page_size;
    let n_pages = 2usize.pow((n_pages as f64).log2().ceil() as u32);
    let n_pages = n_pages + 1;
    n_pages * page_size
}

impl RingReader for PerfEventRing {
    fn load_head(&mut self) { self.ring_reader.load_head() }
    fn size(&self) -> usize { self.ring_reader.size() }
    fn remaining(&self) -> usize { self.ring_reader.remaining() }
    fn write_tail(&mut self) { self.ring_reader.load_head() }
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.ring_reader.read(buf)
    }
}

impl Read for PerfEventRing {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        Ok(self.ring_reader.read(buf).unwrap())
    }
}

// PERF_BIT_WATERMARK value referenced by https://go.googlesource.com/sys/+/054c452bb702e465e95ce8e7a3d9a6cf0cd1188d/unix/ztypes_linux_ppc64le.go?pli=1#999
const PERF_BIT_WATERMARK: i32 = 0x4000;

fn create_perf_event(cpu: c_int, watermark: c_int) -> Result<c_int> {
    let mut watermark = watermark;
    if watermark == 0 {
        watermark = 1;
    }

    let attr = PerfEventAttr {
        kind: PERF_TYPE_SOFTWARE as u32,
        sample_type: PERF_SAMPLE_RAW as u64,
        config: PERF_COUNT_SW_BPF_OUTPUT as u64,
        bits: PERF_BIT_WATERMARK as u64,
        wakeup: watermark as u32,
        ..Default::default()
    };

    unsafe {
        let fd = sys_perf_event_open(&attr, -1 as pid_t, cpu as c_int, -1 as c_int, PERF_FLAG_FD_CLOEXEC as libc::c_ulong);
        Ok(fd.unwrap())
    }
}


struct ForwardReader {
    meta: perf_event_mmap_page,
    head: AtomicU64,
    tail: AtomicU64,
    mask: u64,
    ring: Vec<u8>,
}

impl ForwardReader {
    fn new(meta: perf_event_mmap_page, ring: &[u8]) -> Self {
        let head = AtomicU64::new(meta.data_head);
        let tail = AtomicU64::new(meta.data_tail);
        let mask = (ring.len() - 1) as u64; // Assuming ring.len() is a power of two
        Self { meta, head, tail, mask, ring: Vec::from(ring) }
    }
}

impl RingReader for ForwardReader {
    fn load_head(&mut self) {
        self.head = AtomicU64::from(self.meta.data_head)
    }

    fn size(&self) -> usize {
        self.ring.len()
    }

    fn remaining(&self) -> usize {
        ((self.head.load(Ordering::Relaxed) - self.tail.load(Ordering::Relaxed)) & self.mask) as usize
    }

    fn write_tail(&mut self) {
        let tail = self.tail.load(Ordering::Relaxed);
        self.meta.data_tail = tail;
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let start = (self.tail.load(Ordering::Relaxed) & self.mask) as usize;
        let mut n = buf.len();
        let remainder = self.ring.capacity() - start;
        if n > remainder {
            n = remainder;
        }
        let head = self.head.load(Ordering::Relaxed) as usize;
        let remainder = head - start;
        if n > remainder {
            n = remainder;
        }

        buf[..n].copy_from_slice(&self.ring[start..start + n]);
        self.tail.fetch_add(n as u64, Ordering::Relaxed);

        if self.tail.load(Ordering::Relaxed) == head as u64 {
            return Ok(n);
        }

        Ok(n)
    }
}

use std::os::fd::{AsFd};
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use libbpf_rs::MapHandle;

use object::ReadRef;
use polling::{Event, Poller, PollMode};


use crate::ebpf::ring::perf_buffer::{Events, PerfBuffer};
use crate::ebpf::ring::sys::bpf_map_update_elem;
use crate::error::Error::MustBePaused;
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
    pub cpu: i32,
    pub raw_samples: Vec<BytesMut>,
    pub lost_samples: u32,
    pub remaining: i32,
}

// Reader allows reading bpf_perf_event_output from user space.
pub struct Reader {
    poller: Arc<Poller>,
    deadline: Option<Duration>,

    rings: Vec<Arc<Mutex<PerfBuffer>>>,
    epoll_events: Arc<Mutex<polling::Events>>,
    epoll_rings: Vec<Arc<Mutex<PerfBuffer>>>,
    event_header: Vec<u8>,

    pause_fds: Vec<RawFd>,

    paused: bool,
    overwritable: bool,

    buffer_size: usize,
}

impl Reader {
    pub fn new(array: &MapHandle) -> Result<Self> {
        let n_cpu = array.info().unwrap().info.max_entries;

        let poller = Arc::new(Poller::new().unwrap());
        let mut pause_fds = Vec::with_capacity(n_cpu as usize);
        let mut rings = Vec::with_capacity(n_cpu as usize);

        let mut buffer_size = 0;
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        dbg!(n_cpu);
        for i in 0..n_cpu {
            let ring = PerfBuffer::new(i as i32, page_size, 4).unwrap();
            dbg!(&ring);
            buffer_size = ring.size.clone();
            unsafe {
                poller.add_with_mode(ring.fd, Event::all(i as usize), PollMode::Level).unwrap();
            }
            pause_fds.push(ring.fd);
            let bpf = bpf_map_update_elem(array.as_fd(), Some(&i), &ring.fd, 0).unwrap();
            dbg!(bpf);
            rings.push(Arc::new(Mutex::new(ring)));
        }

        dbg!(&poller);
        Ok(Reader {
            poller,
            deadline: None,
            rings,
            epoll_events: Arc::new(Mutex::new(polling::Events::new())),
            epoll_rings: Vec::new(),
            event_header: vec![0; PERF_EVENT_HEADER_SIZE],
            pause_fds,
            paused: false,
            overwritable: false,
            buffer_size
        })
    }

    pub fn read_events(&mut self) -> Result<Record> {
        let mut events = polling::Events::new();
        loop {
            if self.epoll_rings.len() == 0usize {
                events.clear();
                self.poller.wait(&mut events, self.deadline).unwrap();
                if self.overwritable && !self.paused {
                    return Err(MustBePaused);
                }
                for event in events.iter() {
                    let ring = self.rings[event.key].clone();
                    self.epoll_rings.push(ring);
                }
                continue;
            }
            let len = self.epoll_rings.len().clone();
            if len == 0 { continue; }

            let mut buffers = vec![BytesMut::with_capacity(PERF_EVENT_HEADER_SIZE)];
            let (Events { read: _read, lost }, cpu) = {
                let mut ring = self.epoll_rings[len - 1].lock().unwrap();
                (ring.read_events(&mut buffers).unwrap(), ring.cpu)
            };
            self.epoll_rings.pop();
            return Ok(Record {
                cpu,
                raw_samples: buffers,
                lost_samples: lost as u32,
                remaining: 0,
            });
        }
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        self.rings.clear();
        Ok(())
    }

    pub(crate) fn buffer_size(&self) -> usize {
        self.buffer_size
    }
}
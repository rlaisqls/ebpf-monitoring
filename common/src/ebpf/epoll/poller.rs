use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::os::unix::io::{FromRawFd, OwnedFd, AsRawFd, AsFd, RawFd, BorrowedFd};

use libc::c_int;
use nix::sys::epoll::{
    epoll_create1, epoll_ctl, epoll_wait, EpollEvent, EpollFlags, EpollCreateFlags, EpollOp,
};
use nix::sys::eventfd::EfdFlags;
use nix::unistd::close;

use crate::error::{Error, Result};

pub struct Poller {
    epoll_fd: RawFd,
    event: Arc<EventFd>,
}

impl Poller {
    fn new() -> Result<Self> {
        let epoll_fd = epoll_create1(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();
        let event = EventFd::new().unwrap();
        let event_arc = Arc::new(event);

        let mut poller = Poller {
            epoll_fd,
            event: event_arc.clone(),
        };
        poller.add(event_arc.unwrap().raw_fd(), 0).unwrap();
        Ok(poller)
    }

    fn add(&mut self, fd: RawFd, id: i32) -> Result<()> {
        if id as i64 > i32::MAX as i64 {
            return Err(Error::OSError("".to_string())).unwrap();
        }

        let mut event = EpollEvent::new(EpollFlags::EPOLLIN, id as u64);
        epoll_ctl(self.epoll_fd, EpollOp::EpollCtlAdd, fd, &mut event).unwrap();
        Ok(())
    }

    fn wait(&self, deadline: Option<Instant>) -> Result<Vec<EpollEvent>> {
        let mut events = vec![EpollEvent::empty(); 10]; // Adjust size as needed

        let timeout = deadline.map_or(-1, |d| {
            d.saturating_duration_since(Instant::now()).as_millis() as c_int
        });

        let n_events = epoll_wait(self.epoll_fd, &mut events, timeout as isize).unwrap();
        Ok(events.into_iter().take(n_events).collect())
    }

    fn close(&mut self) -> nix::Result<()> {
        close(self.epoll_fd).unwrap();
        self.epoll_fd = -1;
        Ok(())
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct EventFd(OwnedFd);
impl EventFd {
    /// [`EventFd::from_value_and_flags`] with `init_val = 0` and `flags = EfdFlags::empty()`.
    pub fn new() -> Result<Self> {
        Self::from_value_and_flags(0, EfdFlags::empty())
    }
    /// Constructs [`EventFd`] with the given `init_val` and `flags`.
    ///
    /// Wrapper around [`libc::eventfd`].
    pub fn from_value_and_flags(init_val: u32, flags: EfdFlags) -> Result<Self> {
        let res = unsafe { libc::eventfd(init_val, flags.bits()) };
        unsafe { Ok(EventFd(OwnedFd::from_raw_fd(res))) }
    }
    /// [`EventFd::from_value_and_flags`] with `init_val = 0` and given `flags`.
    pub fn from_flags(flags: EfdFlags) -> Result<Self> {
        Self::from_value_and_flags(0, flags)
    }
    /// [`EventFd::from_value_and_flags`] with given `init_val` and `flags = EfdFlags::empty()`.
    pub fn from_value(init_val: u32) -> Result<Self> {
        Self::from_value_and_flags(init_val, EfdFlags::empty())
    }
    /// Arms `self`, a following call to `poll`, `select` or `epoll` will return immediately.
    ///
    /// [`EventFd::write`] with `1`.
    pub fn arm(&self) -> Result<usize> {
        self.write(1)
    }
    /// Defuses `self`, a following call to `poll`, `select` or `epoll` will block.
    ///
    /// [`EventFd::write`] with `0`.
    pub fn defuse(&self) -> Result<usize> {
        self.write(0)
    }
    /// Enqueues `value` triggers.
    ///
    /// The next `value` calls to `poll`, `select` or `epoll` will return immediately.
    ///
    /// [`EventFd::write`] with `value`.
    pub fn write(&self, value: u64) -> Result<usize> {
        Ok(write(&self.0,&value.to_ne_bytes()))
    }
    // Reads the value from the file descriptor.
    pub fn read(&self) -> Result<u64> {
        let mut arr = [0; std::mem::size_of::<u64>()];
        read(self.0.as_raw_fd(),&mut arr);
        Ok(u64::from_ne_bytes(arr))
    }
}

/// Read from a raw file descriptor.
///
/// See also [read(2)](https://pubs.opengroup.org/onlinepubs/9699919799/functions/read.html)
pub fn read(fd: RawFd, buf: &mut [u8]) -> usize {
    let res =
        unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len() as libc::size_t) };
    res as usize
}

/// Write to a raw file descriptor.
///
/// See also [write(2)](https://pubs.opengroup.org/onlinepubs/9699919799/functions/write.html)
pub fn write<Fd: AsFd>(fd: Fd, buf: &[u8]) -> usize {
    let res = unsafe {
        libc::write(
            fd.as_fd().as_raw_fd(),
            buf.as_ptr().cast(),
            buf.len() as libc::size_t,
        )
    };
    res as usize
}

impl AsFd for EventFd {
    fn as_fd(&self) -> BorrowedFd {
        self.0.as_fd()
    }
}
impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
impl From<EventFd> for OwnedFd {
    fn from(x: EventFd) -> OwnedFd {
        x.0
    }
}

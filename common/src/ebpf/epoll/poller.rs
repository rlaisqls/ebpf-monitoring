use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use libc::c_int;
use nix::sys::epoll::{
    epoll_create1, epoll_ctl, epoll_wait, EpollEvent, EpollFlags, EpollOp,
};
use nix::sys::eventfd::EfdFlags;
use nix::unistd::close;

pub struct Poller {
    epoll_fd: RawFd,
    event: Arc<Mutex<EventFd>>,
}

impl Poller {
    fn new() -> nix::Result<Self> {
        let epoll_fd = epoll_create1(EpollFlags::EPOLL_CLOEXEC)?;
        let event = EventFd::new(EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK)?;
        let event_arc = Arc::new(Mutex::new(event));

        let mut poller = Poller {
            epoll_fd,
            event: event_arc.clone(),
        };
        poller.add(event_arc.lock().unwrap().raw_fd(), 0)?;
        Ok(poller)
    }

    fn add(&mut self, fd: RawFd, id: i32) -> nix::Result<()> {
        if id as i64 > i32::MAX as i64 {
            return Err(nix::Error::from_errno(nix::errno::Errno::EINVAL));
        }

        let mut event = EpollEvent::new(EpollFlags::EPOLLIN, id as u64);
        epoll_ctl(self.epoll_fd, EpollOp::EpollCtlAdd, fd, &mut event)?;
        Ok(())
    }

    fn wait(&self, deadline: Option<Instant>) -> nix::Result<Vec<EpollEvent>> {
        let mut events = vec![EpollEvent::empty(); 10]; // Adjust size as needed

        let timeout = deadline.map_or(-1, |d| {
            d.saturating_duration_since(Instant::now()).as_millis() as c_int
        });

        let n_events = epoll_wait(self.epoll_fd, &mut events, timeout as isize)?;
        Ok(events.into_iter().take(n_events).collect())
    }

    fn close(&mut self) -> nix::Result<()> {
        self.event.lock().unwrap().wake()?;
        close(self.epoll_fd)?;
        self.epoll_fd = -1;
        Ok(())
    }
}

pub struct EventFd {
    fd: RawFd,
}

impl EventFd {
    fn new(flags: EfdFlags) -> nix::Result<Self> {
        let fd = EventFd::from_value_and_flags(0, flags)?;
        Ok(Self { fd })
    }

    fn raw_fd(&self) -> RawFd {
        self.fd
    }

    fn wake(&self) -> nix::Result<()> {
        nix::unistd::write(self.fd, &1u64.to_ne_bytes())?;
        Ok(())
    }

    fn close(&self) -> nix::Result<()> {
        close(self.fd)
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl Drop for EventFd {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

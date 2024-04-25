use std::sync::{Condvar, Mutex};

pub struct WaitGroup {
    count: usize,
    condvar: Condvar,
    mutex: Mutex<()>,
}

impl WaitGroup {
    fn new() -> WaitGroup {
        WaitGroup {
            count: 0,
            condvar: Condvar::new(),
            mutex: Mutex::new(()),
        }
    }

    pub(crate) fn add(&mut self, delta: usize) {
        self.count += delta;
    }

    pub(crate) fn done(&self) {
        if self.count == 0 {
            panic!("negative WaitGroup counter")
        }
        self.condvar.notify_all();
    }

    fn wait(&self) {
        let mut guard = self.mutex.lock().unwrap();
        while self.count > 0 {
            guard = self.condvar.wait(guard).unwrap();
        }
    }
}

impl Default for WaitGroup {
    fn default() -> Self {
        WaitGroup::new()
    }
}
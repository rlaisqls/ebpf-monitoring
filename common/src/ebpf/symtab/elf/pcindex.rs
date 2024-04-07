use std::convert::From;

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PCIndex {
    i32: Option<Vec<u32>>,
    i64: Option<Vec<u64>>,
}

impl PCIndex {
    pub fn new(sz: usize) -> Self {
        PCIndex {
            i32: Some(vec![0; sz]),
            i64: None,
        }
    }

    fn set(&mut self, idx: usize, value: u64) {
        if let Some(i32_vec) = &mut self.i32 {
            if value < u64::from(u32::MAX) {
                i32_vec[idx] = value as u32;
                return;
            }
            self.set_impl(idx, value);
        }
    }

    fn set_impl(&mut self, idx: usize, value: u64) {
        if let Some(i32_vec) = &mut self.i32 {
            if value >= u64::from(u32::MAX) {
                let mut values64 = vec![0; i32_vec.len()];
                for (j, &val) in i32_vec.iter().enumerate() {
                    values64[j] = val as u64;
                }
                self.i32 = None;
                values64[idx] = value;
                self.i64 = Some(values64);
            } else {
                i32_vec[idx] = value as u32;
            }
        } else if let Some(i64_vec) = &mut self.i64 {
            i64_vec[idx] = value;
        }
    }

    pub(crate) fn length(&self) -> usize {
        if let Some(i32_vec) = &self.i32 {
            i32_vec.len()
        } else if let Some(i64_vec) = &self.i64 {
            i64_vec.len()
        } else {
            0
        }
    }

    fn get(&self, idx: usize) -> u64 {
        if let Some(i32_vec) = &self.i32 {
            u64::from(i32_vec[idx])
        } else if let Some(i64_vec) = &self.i64 {
            i64_vec[idx]
        } else {
            0
        }
    }

    fn is_32(&self) -> bool {
        self.i32.is_some()
    }

    fn first(&self) -> u64 {
        if let Some(i32_vec) = &self.i32 {
            u64::from(i32_vec[0])
        } else if let Some(i64_vec) = &self.i64 {
            i64_vec[0]
        } else {
            0
        }
    }

    fn pc_index_64(&mut self) -> &PCIndex {
        if let Some(_i64_vec) = &self.i64 {
            return self;
        }
        if let Some(i32_vec) = &self.i32 {
            let i64_vec: Vec<u64> = i32_vec.iter().map(|&x| u64::from(x)).collect();
            self.i64 = Some(i64_vec);
            self.i32 = None;
        }
        self
    }


    pub(crate) fn find_index(&self, addr: u64) -> Option<isize> {
        if let Some(i32_vec) = &self.i32 {
            if addr < u64::from(i32_vec[0]) {
                return None;
            }
            match i32_vec.binary_search(&(addr as u32)) {
                Ok(i) => return Some(i as isize),
                Err(mut i) => {
                    if i > 0 {
                        i -= 1;
                        let v = i32_vec[i];
                        while i > 0 && i32_vec[i - 1] == v {
                            i -= 1;
                        }
                        return Some(i as isize);
                    }
                }
            }
        } else if let Some(i64_vec) = &self.i64 {
            if addr < i64_vec[0] {
                return None;
            }
            match i64_vec.binary_search(&addr) {
                Ok(i) => return Some(i as isize),
                Err(mut i) => {
                    if i > 0 {
                        i -= 1;
                        let v = i64_vec[i];
                        while i > 0 && i64_vec[i - 1] == v {
                            i -= 1;
                        }
                        return Some(i as isize);
                    }
                }
            }
        }
        None
    }
}

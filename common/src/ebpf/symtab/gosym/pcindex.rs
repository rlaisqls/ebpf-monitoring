
pub struct PCIndex {
    i32: Option<Vec<u32>>,
    i64: Option<Vec<u64>>,
}

impl PCIndex {
    fn new(sz: usize) -> Self {
        Self {
            i32: Some(vec![0; sz]),
            i64: None,
        }
    }

    fn set(&mut self, idx: usize, value: u64) {
        if let Some(i32_values) = &mut self.i32 {
            if value < u32::MAX as u64 {
                i32_values[idx] = value as u32;
                return;
            }
            self.set_impl(idx, value);
        }
    }

    fn set_impl(&mut self, idx: usize, value: u64) {
        match self.i32 {
            Some(ref mut vec) if value <= u32::MAX as u64 => {
                // i32 벡터가 있고, value가 u32로 표현 가능한 경우
                vec[idx] = value as u32;
            }
            Some(ref vec) => {
                // i32 벡터가 있지만, value가 u32 최대값을 초과하는 경우
                let mut values_64 = vec.iter().map(|&x| x as u64).collect::<Vec<u64>>();
                values_64.resize(vec.len(), 0); // 확장하지 않은 새 요소들을 0으로 초기화
                values_64[idx] = value;
                self.i32 = None; // i32 벡터를 None으로 설정
                self.i64 = Some(values_64); // 새로운 i64 벡터를 설정
            }
            None => {
                // i32 벡터가 None인 경우, i64 벡터를 직접 수정
                if let Some(ref mut vec) = self.i64 {
                    vec[idx] = value;
                }
            }
        }
    }

    fn len(&self) -> usize {
        if let Some(i32_values) = &self.i32 {
            i32_values.len()
        } else if let Some(i64_values) = &self.i64 {
            i64_values.len()
        } else {
            0
        }
    }

    fn get(&self, idx: usize) -> u64 {
        if let Some(i32_values) = &self.i32 {
            i32_values[idx] as u64
        } else if let Some(i64_values) = &self.i64 {
            i64_values[idx]
        } else {
            0
        }
    }

    fn is_32(&self) -> bool {
        self.i32.is_some()
    }

    fn first(&self) -> u64 {
        if let Some(i32_values) = &self.i32 {
            i32_values[0] as u64
        } else if let Some(i64_values) = &self.i64 {
            i64_values[0]
        } else {
            0
        }
    }

    pub(crate) fn find_index(&self, addr: u64) -> isize {
        if let Some(i32_values) = &self.i32 {
            if addr < i32_values[0] as u64 {
                return -1;
            }
            match i32_values.binary_search(&(addr as u32)) {
                Ok(i) => i as isize,
                Err(_) => {
                    let mut i = i32_values.binary_search(&(addr as u32 - 1)).unwrap_or_else(|_| 0);
                    let v = i32_values[i];
                    while i > 0 && i32_values[i - 1] == v {
                        i -= 1;
                    }
                    i as isize
                }
            }
        } else if let Some(i64_values) = &self.i64 {
            if addr < i64_values[0] {
                return -1;
            }
            match i64_values.binary_search(&addr) {
                Ok(i) => i as isize,
                Err(_) => {
                    let mut i = i64_values.binary_search(&(addr - 1)).unwrap_or_else(|_| 0);
                    let v = i64_values[i];
                    while i > 0 && i64_values[i - 1] == v {
                        i -= 1;
                    }
                    i as isize
                }
            }
        } else {
            -1
        }
    }

    fn pc_index64(mut self) -> Self {
        if self.i64.is_none() {
            if let Some(i32_vec) = self.i32.take() {
                self.i64 = Some(
                    i32_vec.into_iter()
                        .map(|x| x as u64).collect());
            }
        }
        self.i32 = None;
        self
    }
}
